package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// UpstreamAddr sets upstream SOCKS5 address at build time:
// go build -ldflags "-X 'main.UpstreamAddr=1.2.3.4:1080'"
var UpstreamAddr string

const (
	listenAddr      = "127.0.0.1:4444"
	controlSockPath = "/tmp/proxy_socks5_control.sock"
)

type connRegistry struct {
	mu    sync.Mutex
	next  uint64
	pairs map[uint64]connPair
}

type connPair struct {
	client   net.Conn
	upstream net.Conn
}

type upstreamConfig struct {
	Addr string
	User string
	Pass string
}

func main() {
	cfg, err := resolveConfigFromArgs()
	if err != nil {
		log.Fatal(err)
	}
	if err := validateConfig(cfg); err != nil {
		log.Fatalf("invalid config: %v", err)
	}

	// If the process is already running, update its upstream and exit.
	if sendUpdateToRunningProcess(cfg) {
		log.Printf("updated running proxy upstream to %s", cfg.Addr)
		return
	}

	var upstreamValue atomic.Value
	upstreamValue.Store(cfg)
	registry := &connRegistry{pairs: make(map[uint64]connPair)}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	controlLn, err := net.Listen("unix", controlSockPath)
	if err != nil {
		// stale socket path from crashed process
		_ = os.Remove(controlSockPath)
		controlLn, err = net.Listen("unix", controlSockPath)
		if err != nil {
			log.Fatalf("control socket listen failed: %v", err)
		}
	}
	defer func() {
		controlLn.Close()
		_ = os.Remove(controlSockPath)
	}()

	go controlLoop(controlLn, &upstreamValue, registry)

	if cfg.User != "" {
		log.Printf("local SOCKS5 on %s -> upstream SOCKS5 %s (auth user: %s)", listenAddr, cfg.Addr, cfg.User)
	} else {
		log.Printf("local SOCKS5 on %s -> upstream SOCKS5 %s", listenAddr, cfg.Addr)
	}

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			log.Printf("accept failed: %v", err)
			continue
		}
		go handleClient(clientConn, &upstreamValue, registry)
	}
}

func resolveConfigFromArgs() (upstreamConfig, error) {
	var cfg upstreamConfig

	if len(os.Args) > 1 {
		cfg.Addr = strings.TrimSpace(os.Args[1])
	}
	if len(os.Args) > 2 {
		user, pass, err := parseUserPass(strings.TrimSpace(os.Args[2]))
		if err != nil {
			return cfg, err
		}
		cfg.User = user
		cfg.Pass = pass
	}

	if cfg.Addr == "" && UpstreamAddr != "" {
		cfg.Addr = strings.TrimSpace(UpstreamAddr)
	}
	if cfg.Addr == "" {
		cfg.Addr = strings.TrimSpace(os.Getenv("UPSTREAM_ADDR"))
	}
	if cfg.Addr == "" {
		return cfg, errors.New("usage: ./proxy IP:PORT [user:password]")
	}

	return cfg, nil
}

func parseUserPass(s string) (string, string, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", errors.New("invalid credentials format; use user:password")
	}
	if strings.Contains(parts[0], "\t") || strings.Contains(parts[1], "\t") || strings.Contains(parts[0], "\n") || strings.Contains(parts[1], "\n") {
		return "", "", errors.New("credentials must not contain tabs/newlines")
	}
	return parts[0], parts[1], nil
}

func validateConfig(cfg upstreamConfig) error {
	host, port, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return err
	}
	if host == "" {
		return errors.New("empty host")
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return errors.New("invalid port")
	}
	if (cfg.User == "" && cfg.Pass != "") || (cfg.User != "" && cfg.Pass == "") {
		return errors.New("both user and password must be set")
	}
	if len(cfg.User) > 255 || len(cfg.Pass) > 255 {
		return errors.New("user/password is too long")
	}
	return nil
}

func sendUpdateToRunningProcess(cfg upstreamConfig) bool {
	conn, err := net.Dial("unix", controlSockPath)
	if err != nil {
		return false
	}
	defer conn.Close()

	line := fmt.Sprintf("%s\t%s\t%s\n", cfg.Addr, cfg.User, cfg.Pass)
	if _, err := conn.Write([]byte(line)); err != nil {
		return false
	}

	resp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return false
	}
	return strings.TrimSpace(resp) == "OK"
}

func controlLoop(ln net.Listener, upstreamValue *atomic.Value, registry *connRegistry) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleControlConn(conn, upstreamValue, registry)
	}
}

func handleControlConn(conn net.Conn, upstreamValue *atomic.Value, registry *connRegistry) {
	defer conn.Close()

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		_, _ = conn.Write([]byte("ERR read\n"))
		return
	}

	next, err := parseControlLine(strings.TrimSpace(line))
	if err != nil || validateConfig(next) != nil {
		_, _ = conn.Write([]byte("ERR invalid\n"))
		return
	}

	old := upstreamValue.Load().(upstreamConfig)
	upstreamValue.Store(next)
	registry.closeAll()
	log.Printf("upstream updated: %s -> %s", old.Addr, next.Addr)
	_, _ = conn.Write([]byte("OK\n"))
}

func parseControlLine(line string) (upstreamConfig, error) {
	parts := strings.SplitN(line, "\t", 3)
	if len(parts) != 3 {
		return upstreamConfig{}, errors.New("invalid control message")
	}
	return upstreamConfig{
		Addr: strings.TrimSpace(parts[0]),
		User: parts[1],
		Pass: parts[2],
	}, nil
}

func handleClient(clientConn net.Conn, upstreamValue *atomic.Value, registry *connRegistry) {
	defer clientConn.Close()

	dstAddr, err := readClientRequest(clientConn)
	if err != nil {
		log.Printf("client handshake failed: %v", err)
		return
	}

	cfg := upstreamValue.Load().(upstreamConfig)
	upstreamConn, err := net.Dial("tcp", cfg.Addr)
	if err != nil {
		log.Printf("upstream dial failed: %v", err)
		writeSocksReply(clientConn, 0x01)
		return
	}
	defer upstreamConn.Close()

	connID := registry.add(clientConn, upstreamConn)
	defer registry.remove(connID)

	if err := sendUpstreamConnect(upstreamConn, dstAddr, cfg); err != nil {
		log.Printf("upstream connect failed: %v", err)
		writeSocksReply(clientConn, 0x05)
		return
	}

	if err := writeSocksReply(clientConn, 0x00); err != nil {
		log.Printf("reply to client failed: %v", err)
		return
	}

	tunnel(clientConn, upstreamConn)
}

func (r *connRegistry) add(client, upstream net.Conn) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.next++
	id := r.next
	r.pairs[id] = connPair{client: client, upstream: upstream}
	return id
}

func (r *connRegistry) remove(id uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.pairs, id)
}

func (r *connRegistry) closeAll() {
	r.mu.Lock()
	pairs := make([]connPair, 0, len(r.pairs))
	for _, p := range r.pairs {
		pairs = append(pairs, p)
	}
	r.mu.Unlock()

	for _, p := range pairs {
		_ = p.client.Close()
		_ = p.upstream.Close()
	}
}

func readClientRequest(conn net.Conn) (string, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", err
	}
	if head[0] != 0x05 {
		return "", errors.New("unsupported SOCKS version")
	}

	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}

	// no-auth method
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return "", err
	}

	reqHead := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHead); err != nil {
		return "", err
	}
	if reqHead[0] != 0x05 {
		return "", errors.New("invalid request version")
	}
	if reqHead[1] != 0x01 {
		return "", errors.New("only CONNECT is supported")
	}

	host, err := readHost(conn, reqHead[3])
	if err != nil {
		return "", err
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBytes)

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func sendUpstreamConnect(upstreamConn net.Conn, dstAddr string, cfg upstreamConfig) error {
	// Upstream greeting
	greeting := []byte{0x05, 0x01, 0x00}
	if cfg.User != "" {
		greeting = []byte{0x05, 0x02, 0x00, 0x02}
	}
	if _, err := upstreamConn.Write(greeting); err != nil {
		return err
	}

	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(upstreamConn, greetResp); err != nil {
		return err
	}
	if greetResp[0] != 0x05 {
		return errors.New("invalid upstream greeting response")
	}

	switch greetResp[1] {
	case 0x00:
		// no-auth selected
	case 0x02:
		if err := authUserPass(upstreamConn, cfg.User, cfg.Pass); err != nil {
			return err
		}
	default:
		return errors.New("upstream does not accept offered auth methods")
	}

	host, portStr, err := net.SplitHostPort(dstAddr)
	if err != nil {
		return err
	}
	portInt, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}

	req := make([]byte, 0, 300)
	req = append(req, 0x05, 0x01, 0x00)

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("domain is too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(portInt))
	req = append(req, portBytes...)

	if _, err := upstreamConn.Write(req); err != nil {
		return err
	}

	replyHead := make([]byte, 4)
	if _, err := io.ReadFull(upstreamConn, replyHead); err != nil {
		return err
	}
	if replyHead[0] != 0x05 {
		return errors.New("invalid upstream response version")
	}
	if replyHead[1] != 0x00 {
		return errors.New("upstream rejected CONNECT")
	}

	if _, err := readHost(upstreamConn, replyHead[3]); err != nil {
		return err
	}
	discardPort := make([]byte, 2)
	_, err = io.ReadFull(upstreamConn, discardPort)
	return err
}

func authUserPass(conn net.Conn, user, pass string) error {
	if user == "" {
		return errors.New("upstream requested user/password auth, but credentials are empty")
	}

	req := make([]byte, 0, 3+len(user)+len(pass))
	req = append(req, 0x01, byte(len(user)))
	req = append(req, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)

	if _, err := conn.Write(req); err != nil {
		return err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x01 || resp[1] != 0x00 {
		return errors.New("upstream user/password auth failed")
	}
	return nil
}

func readHost(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case 0x03: // Domain
		var ln [1]byte
		if _, err := io.ReadFull(r, ln[:]); err != nil {
			return "", err
		}
		name := make([]byte, int(ln[0]))
		if _, err := io.ReadFull(r, name); err != nil {
			return "", err
		}
		return string(name), nil
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	default:
		return "", errors.New("unsupported address type")
	}
}

func writeSocksReply(conn net.Conn, rep byte) error {
	// BND.ADDR = 0.0.0.0, BND.PORT = 0
	_, err := conn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

func tunnel(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(b, a)
		done <- struct{}{}
	}()
	<-done
}
