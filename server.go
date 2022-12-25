package accelerator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
)

const (
	defaultServerConnPoolSize   = 64
	defaultServerNumFrameSender = 32
	defaultServerTimeout        = 10 * time.Second
)

// for server map key and network
type mac = [6]byte
type ipv4 = [net.IPv4len]byte
type ipv6 = [net.IPv6len]byte
type port = [2]byte

var broadcast = mac{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

// Server is the accelerator server.
type Server struct {
	passHash     []byte
	connPoolSize int
	numFrSender  int
	timeout      time.Duration
	enableNAT    bool

	handle       *pcap.Handle
	logger       *logger
	tlsListener  net.Listener
	quicListener net.Listener
	nat          *nat

	tokens    map[sessionToken]time.Time
	tokensRWM sync.RWMutex

	macs     map[mac]sessionToken
	macsRWM  sync.RWMutex
	ipv4s    map[ipv4]sessionToken
	ipv4sRWM sync.RWMutex
	ipv6s    map[ipv6]sessionToken
	ipv6sRWM sync.RWMutex

	ipv4ToMACs    map[ipv4]mac
	ipv4ToMACsRWM sync.RWMutex
	ipv6ToMACs    map[ipv6]mac
	ipv6ToMACsRWM sync.RWMutex

	connPools    map[sessionToken]*connPool
	connPoolsRWM sync.RWMutex

	frameCh    chan *frame
	frameCache *sync.Pool

	numTr  int32
	income chan struct{}

	closed int32

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewServer is used to create a new server from configuration.
func NewServer(cfg *ServerConfig) (*Server, error) {
	var ok bool
	handle, err := openPcapDevice(cfg.Common.Interface)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open pcap device")
	}
	defer func() {
		if !ok {
			handle.Close()
		}
	}()
	passHash, err := decodePasswordHash(cfg.Common.PassHash)
	if err != nil {
		return nil, err
	}
	// initialize logger
	lg, err := newLogger(cfg.Common.LogPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open log file")
	}
	defer func() {
		if !ok {
			_ = lg.Close()
		}
	}()
	// initialize tls config
	tlsConfig, err := newServerTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	poolSize := cfg.Server.ConnPoolSize
	if poolSize < 1 {
		poolSize = defaultServerConnPoolSize
	}
	numFrSender := cfg.Server.NumFrameSender
	if numFrSender < 1 {
		numFrSender = defaultServerNumFrameSender
	}
	timeout := time.Duration(cfg.Server.Timeout)
	if timeout < 1 {
		timeout = defaultServerTimeout
	}
	listeners, err := bindListeners(cfg, tlsConfig, timeout)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !ok {
			unbindListeners(listeners)
		}
	}()
	var nat *nat
	if cfg.NAT.Enabled {
		nat, err = newNAT(lg, cfg)
		if err != nil {
			return nil, err
		}
	}
	server := Server{
		passHash:     passHash,
		numFrSender:  numFrSender,
		connPoolSize: poolSize,
		timeout:      timeout,
		enableNAT:    cfg.NAT.Enabled,
		handle:       handle,
		logger:       lg,
		tlsListener:  listeners[0],
		quicListener: listeners[1],
		nat:          nat,
		tokens:       make(map[sessionToken]time.Time, 16),
		macs:         make(map[mac]sessionToken, 16),
		ipv4s:        make(map[ipv4]sessionToken, 16),
		ipv6s:        make(map[ipv6]sessionToken, 16),
		ipv4ToMACs:   make(map[ipv4]mac, 16),
		ipv6ToMACs:   make(map[ipv6]mac, 16),
		connPools:    make(map[sessionToken]*connPool, 16),
		frameCh:      make(chan *frame, 64*1024),
		frameCache:   new(sync.Pool),
		income:       make(chan struct{}, 1),
	}
	server.frameCache.New = func() interface{} {
		return newFrame()
	}
	server.ctx, server.cancel = context.WithCancel(context.Background())
	ok = true
	return &server, nil
}

func openPcapDevice(device string) (*pcap.Handle, error) {
	iHandle, err := pcap.NewInactiveHandle(device)
	if err != nil {
		return nil, err
	}
	var ok bool
	defer func() {
		if !ok {
			iHandle.CleanUp()
		}
	}()
	err = iHandle.SetSnapLen(64 * 1024)
	if err != nil {
		return nil, err
	}
	err = iHandle.SetPromisc(true)
	if err != nil {
		return nil, err
	}
	err = iHandle.SetTimeout(pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	err = iHandle.SetImmediateMode(true)
	if err != nil {
		return nil, err
	}
	err = iHandle.SetBufferSize(64 * 1024 * 1024)
	if err != nil {
		return nil, err
	}
	handle, err := iHandle.Activate()
	if err != nil {
		return nil, err
	}
	ok = true
	return handle, nil
}

func newServerTLSConfig(cfg *ServerConfig) (*tls.Config, error) {
	caPEM, err := os.ReadFile(cfg.TLS.ClientCA)
	if err != nil {
		return nil, err
	}
	cert, err := parseCertificatePEM(caPEM)
	if err != nil {
		return nil, err
	}
	tlsCert, err := tls.LoadX509KeyPair(cfg.TLS.ServerCert, cfg.TLS.ServerKey)
	if err != nil {
		return nil, err
	}
	config := tls.Config{
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{tlsCert},
		ClientCAs:    x509.NewCertPool(),
	}
	config.ClientCAs.AddCert(cert)
	return &config, nil
}

func bindListeners(cfg *ServerConfig, tc *tls.Config, t time.Duration) ([]net.Listener, error) {
	var (
		tlsListener  net.Listener
		quicListener net.Listener
		listened     bool
		ok           bool
		err          error
	)
	// bind TCP listener
	if cfg.TCP.Enabled {
		tlsListener, err = tls.Listen(cfg.TCP.Network, cfg.TCP.Address, tc)
		if err != nil {
			return nil, err
		}
		defer func() {
			if !ok {
				_ = tlsListener.Close()
			}
		}()
		listened = true
	}
	// bind UDP listener
	if cfg.UDP.Enabled {
		quicListener, err = quicListen(cfg.UDP.Network, cfg.UDP.Address, tc, t)
		if err != nil {
			return nil, err
		}
		defer func() {
			if !ok {
				_ = quicListener.Close()
			}
		}()
		listened = true
	}
	if !listened {
		return nil, errors.New("no listener is enabled")
	}
	ok = true
	return []net.Listener{tlsListener, quicListener}, nil
}

func unbindListeners(listeners []net.Listener) {
	for i := 0; i < len(listeners); i++ {
		if listeners[i] != nil {
			_ = listeners[i].Close()
		}
	}
}

// Run is used to run the accelerator server.
func (srv *Server) Run() {
	if srv.tlsListener != nil {
		srv.wg.Add(1)
		go srv.serve(srv.tlsListener)
		addr := srv.tlsListener.Addr()
		srv.logger.Infof("start tls listener(%s %s)", addr.Network(), addr)
	}
	if srv.quicListener != nil {
		srv.wg.Add(1)
		go srv.serve(srv.quicListener)
		addr := srv.quicListener.Addr()
		srv.logger.Infof("start quic listener(%s %s)", addr.Network(), addr)
	}
	if srv.nat != nil {
		srv.logger.Info("accelerator nat module is enabled")
		srv.logger.Info("[localhost]")
		srv.logger.Info("MAC address: ", srv.nat.localMAC)
		if srv.nat.localIPv4 != nil {
			srv.logger.Info("IPv4 address:", srv.nat.localIPv4)
		}
		if srv.nat.localIPv6 != nil {
			srv.logger.Info("IPv6 address:", srv.nat.localIPv6)
		}
		srv.logger.Info("[gateway]")
		srv.logger.Info("MAC address: ", srv.nat.gatewayMAC)
		if srv.nat.gatewayIPv4 != nil {
			srv.logger.Info("IPv4 address:", srv.nat.gatewayIPv4)
		}
		if srv.nat.gatewayIPv6 != nil {
			srv.logger.Info("IPv6 address:", srv.nat.gatewayIPv6)
		}
		srv.nat.Run()
	}
	// start frame capturer
	srv.logger.Info("start accelerator frame capturer")
	srv.wg.Add(1)
	go srv.frameCapturer()
	// start frame senders
	srv.logger.Info("start accelerator frame senders")
	for i := 0; i < srv.numFrSender; i++ {
		sender := srv.newFrameSender()
		srv.wg.Add(1)
		go sender.sendLoop()
	}
	srv.logger.Info("accelerator server is running")
}

func (srv *Server) serve(listener net.Listener) {
	defer srv.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			srv.logger.Fatal("Server.serve", r)
		}
	}()
	defer func() {
		err := listener.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			srv.logger.Error(err)
		}
	}()
	const maxDelay = time.Second
	var delay time.Duration // how long to sleep on accept failure
	for {
		conn, err := listener.Accept()
		if err != nil {
			// check error type
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else {
					delay *= 2
				}
				if delay > maxDelay {
					delay = maxDelay
				}
				if delay != maxDelay {
					const format = "accept error: %s; retrying in %v"
					srv.logger.Errorf(format, err, delay)
				}
				time.Sleep(delay)
				continue
			}
			if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
				return
			}
			srv.logger.Error("failed to accept:", err)
			return
		}
		srv.wg.Add(1)
		go srv.handleConn(conn)
	}
}

func (srv *Server) handleConn(conn net.Conn) {
	defer srv.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			srv.logger.Fatal("Server.handleConn", r)
		}
	}()
	remoteAddr := conn.RemoteAddr()
	defer func() {
		err := conn.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			if strings.Contains(err.Error(), "tls: failed to send closeNotify alert") {
				return
			}
			const format = "(%s) failed to close transporter: %s"
			srv.logger.Errorf(format, remoteAddr, err)
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(2 * srv.timeout))
	err := srv.authenticate(conn)
	if err != nil {
		const format = "(%s) failed to authenticate: %s"
		srv.logger.Warningf(format, remoteAddr, err)
		return
	}
	// read command
	buf := make([]byte, cmdSize)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		const format = "(%s) failed to receive command: %s"
		srv.logger.Errorf(format, remoteAddr, err)
		return
	}
	cmd := buf[0]
	switch cmd {
	case cmdLogin:
		srv.handleLogin(conn)
	case cmdLogoff:
		srv.handleLogoff(conn)
	case cmdTransport:
		srv.handleTransport(conn)
	default:
		const format = "(%s) receive invalid command: %d"
		srv.logger.Warningf(format, remoteAddr, cmd)
	}
}

func (srv *Server) authenticate(conn net.Conn) error {
	passHash := make([]byte, sha256.Size)
	_, err := io.ReadFull(conn, passHash)
	if err != nil {
		return errors.Wrap(err, "failed to receive password hash")
	}
	if subtle.ConstantTimeCompare(srv.passHash, passHash) != 1 {
		srv.defend(conn)
		return errors.New("invalid password hash")
	}
	// read padding random data
	buf := make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return errors.Wrap(err, "failed to receive padding random data size")
	}
	size := binary.BigEndian.Uint16(buf)
	_, err = io.CopyN(io.Discard, conn, int64(size))
	if err != nil {
		return errors.Wrap(err, "failed to receive padding random data")
	}
	// send authentication response
	resp, err := buildAuthResponse()
	if err != nil {
		return errors.WithMessage(err, "failed to build authentication response")
	}
	_, err = conn.Write(resp)
	if err != nil {
		return errors.Wrap(err, "failed to send authentication response")
	}
	return nil
}

func (srv *Server) defend(conn net.Conn) {
	const format = "defend client (%s) "
	srv.logger.Warningf(format, conn.RemoteAddr())
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				srv.logger.Fatal("Server.defend", r)
			}
		}()
		_, _ = io.Copy(io.Discard, conn)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				srv.logger.Fatal("Server.defend", r)
			}
		}()
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-timer.C:
				data, err := generateRandomData()
				if err != nil {
					return
				}
				data = data[2:] // skip size header
				_, err = conn.Write(data)
				if err != nil {
					return
				}
			case <-srv.ctx.Done():
				return
			}
			timer.Reset(time.Duration(1+rand.Intn(3)) * time.Second) // #nosec
		}
	}()
	wg.Wait()
}

func (srv *Server) handleLogin(conn net.Conn) {
	remoteAddr := conn.RemoteAddr()
	obf := make([]byte, obfSize)
	_, err := io.ReadFull(conn, obf)
	if err != nil {
		const format = "(%s) failed to receive random data: %s"
		srv.logger.Errorf(format, remoteAddr, err)
		return
	}
	// generate session token
	h := sha512.New()
	data, err := generateRandomData()
	if err != nil {
		const format = "(%s) failed to generate random data: %s"
		srv.logger.Errorf(format, remoteAddr, err)
		return
	}
	h.Write(data)
	h.Write(obf)
	token := sessionToken{}
	copy(token[:], h.Sum(nil))
	// send session token
	buf := make([]byte, cmdSize+tokenSize)
	buf[0] = loginOK
	copy(buf[cmdSize:], token[:])
	_, err = conn.Write(buf)
	if err != nil {
		const format = "(%s) failed to send session token: %s"
		srv.logger.Errorf(format, remoteAddr, err)
		return
	}
	srv.addSessionToken(token)
	srv.prepareConnPool(token)
	srv.logger.Infof("(%s) login successfully", remoteAddr)
}

func (srv *Server) handleLogoff(conn net.Conn) {
	remoteAddr := conn.RemoteAddr()
	token := sessionToken{}
	_, err := io.ReadFull(conn, token[:])
	if err != nil {
		const format = "(%s) failed to receive session token: %s"
		srv.logger.Errorf(format, remoteAddr, err)
		return
	}
	buf := make([]byte, cmdSize)
	buf[0] = logoffOK
	_, err = conn.Write(buf)
	if err != nil {
		const format = "(%s) failed to send log off response: %s"
		srv.logger.Errorf(format, remoteAddr, err)
		return
	}
	if !srv.isSessionTokenExist(token) {
		return
	}
	srv.removeConnPool(token)
	srv.unbindMAC(token)
	srv.unbindIPv4(token)
	srv.unbindIPv6(token)
	srv.deleteSessionToken(token)
	srv.logger.Infof("(%s) logoff successfully", remoteAddr)
}

func (srv *Server) handleTransport(conn net.Conn) {
	remoteAddr := conn.RemoteAddr()
	token := sessionToken{}
	_, err := io.ReadFull(conn, token[:])
	if err != nil {
		const format = "(%s) failed to receive session token: %s"
		srv.logger.Errorf(format, remoteAddr, err)
		return
	}
	if !srv.isValidSessionToken(token) {
		const format = "(%s) receive invalid session token"
		srv.logger.Warningf(format, remoteAddr)
		_ = srv.writeTransportResponse(conn, invalidToken)
		return
	}
	// add connection to pool
	pool := srv.getConnPool(token)
	if pool == nil {
		return
	}
	if !pool.AddConn(&conn) {
		_ = srv.writeTransportResponse(conn, fullConnPool)
		return
	}
	defer pool.DeleteConn(&conn)
	// send transport response
	err = srv.writeTransportResponse(conn, transportOK)
	if err != nil {
		const format = "(%s) failed to send transport response: %s"
		srv.logger.Errorf(format, remoteAddr, err)
		return
	}
	// send income client signal
	select {
	case srv.income <- struct{}{}:
	default:
	}
	// update transport client counter
	atomic.AddInt32(&srv.numTr, 1)
	defer atomic.AddInt32(&srv.numTr, -1)
	// start transport frame
	tr := srv.newTransporter(conn, token)
	tr.transport()
}

func (srv *Server) writeTransportResponse(conn net.Conn, resp byte) error {
	buf := bytes.NewBuffer(make([]byte, 0, 4))
	buf.WriteByte(resp)
	if resp == fullConnPool {
		size := make([]byte, 2)
		binary.BigEndian.PutUint16(size, uint16(srv.connPoolSize))
		buf.Write(size)
	}
	_, err := conn.Write(buf.Bytes())
	return err
}

// frameCapturer is used to capture frame from destination network
// interface and send it to the frame channel for frameSender.
func (srv *Server) frameCapturer() {
	defer srv.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			srv.logger.Fatal("Server.frameCapturer", r)
			// restart frame capturer
			time.Sleep(time.Second)
			srv.wg.Add(1)
			go srv.frameCapturer()
		}
	}()
	var (
		data []byte
		fr   *frame
		err  error
	)
	for {
		if srv.isIdle() {
			select {
			case <-srv.income:
			case <-srv.ctx.Done():
				return
			}
		}
		data, _, err = srv.handle.ZeroCopyReadPacketData()
		if err != nil {
			return
		}
		size := len(data)
		if size > maxFrameSize {
			const format = "capture too large frame, size: 0x%X"
			srv.logger.Warningf(format, size)
			continue
		}
		fr = srv.frameCache.Get().(*frame)
		fr.WriteHeader(size)
		fr.WriteData(data)
		select {
		case srv.frameCh <- fr:
		case <-srv.ctx.Done():
			return
		}
	}
}

func (srv *Server) isIdle() bool {
	return atomic.LoadInt32(&srv.numTr) < 1
}

func (srv *Server) addSessionToken(token sessionToken) {
	now := time.Now()
	srv.tokensRWM.Lock()
	defer srv.tokensRWM.Unlock()
	// clean expired session token
	for t, e := range srv.tokens {
		if now.After(e) {
			delete(srv.tokens, t)
		}
	}
	// add session token
	srv.tokens[token] = now.Add(3 * 24 * time.Hour)
}

func (srv *Server) deleteSessionToken(token sessionToken) {
	srv.tokensRWM.Lock()
	defer srv.tokensRWM.Unlock()
	delete(srv.tokens, token)
}

func (srv *Server) isSessionTokenExist(token sessionToken) bool {
	srv.tokensRWM.RLock()
	defer srv.tokensRWM.RUnlock()
	_, ok := srv.tokens[token]
	return ok
}

func (srv *Server) isValidSessionToken(token sessionToken) bool {
	now := time.Now()
	srv.tokensRWM.RLock()
	defer srv.tokensRWM.RUnlock()
	e, ok := srv.tokens[token]
	if !ok {
		return false
	}
	return now.Before(e)
}

func (srv *Server) bindMAC(token sessionToken, mac mac) {
	srv.macsRWM.Lock()
	defer srv.macsRWM.Unlock()
	t := srv.macs[mac]
	if t != emptySessionToken {
		srv.connPoolsRWM.RLock()
		defer srv.connPoolsRWM.RUnlock()
		pool := srv.connPools[t]
		if pool != nil && !pool.IsEmpty() {
			return
		}
	}
	srv.macs[mac] = token
}

func (srv *Server) unbindMAC(token sessionToken) {
	srv.macsRWM.Lock()
	defer srv.macsRWM.Unlock()
	for m, t := range srv.macs {
		if t != token {
			continue
		}
		delete(srv.macs, m)
	}
}

func (srv *Server) bindIPv4(token sessionToken, ip ipv4) bool {
	srv.ipv4sRWM.Lock()
	defer srv.ipv4sRWM.Unlock()
	t := srv.ipv4s[ip]
	if t != emptySessionToken {
		srv.connPoolsRWM.RLock()
		defer srv.connPoolsRWM.RUnlock()
		pool := srv.connPools[t]
		if pool != nil && !pool.IsEmpty() {
			return false
		}
	}
	srv.ipv4s[ip] = token
	return true
}

func (srv *Server) unbindIPv4(token sessionToken) {
	srv.ipv4sRWM.Lock()
	defer srv.ipv4sRWM.Unlock()
	for ip, t := range srv.ipv4s {
		if t != token {
			continue
		}
		delete(srv.ipv4s, ip)
		srv.unbindIPv4ToMAC(ip)
	}
}

func (srv *Server) bindIPv6(token sessionToken, ip ipv6) bool {
	srv.ipv6sRWM.Lock()
	defer srv.ipv6sRWM.Unlock()
	t := srv.ipv6s[ip]
	if t != emptySessionToken {
		srv.connPoolsRWM.RLock()
		defer srv.connPoolsRWM.RUnlock()
		pool := srv.connPools[t]
		if pool != nil && !pool.IsEmpty() {
			return false
		}
	}
	srv.ipv6s[ip] = token
	return true
}

func (srv *Server) unbindIPv6(token sessionToken) {
	srv.ipv6sRWM.Lock()
	defer srv.ipv6sRWM.Unlock()
	for ip, t := range srv.ipv6s {
		if t != token {
			continue
		}
		delete(srv.ipv6s, ip)
		srv.unbindIPv6ToMAC(ip)
	}
}

func (srv *Server) bindIPv4ToMAC(ip ipv4, mac mac) {
	srv.ipv4ToMACsRWM.Lock()
	defer srv.ipv4ToMACsRWM.Unlock()
	srv.ipv4ToMACs[ip] = mac
}

func (srv *Server) unbindIPv4ToMAC(ip ipv4) {
	srv.ipv4ToMACsRWM.Lock()
	defer srv.ipv4ToMACsRWM.Unlock()
	delete(srv.ipv4ToMACs, ip)
}

func (srv *Server) bindIPv6ToMAC(ip ipv6, mac mac) {
	srv.ipv6ToMACsRWM.Lock()
	defer srv.ipv6ToMACsRWM.Unlock()
	srv.ipv6ToMACs[ip] = mac
}

func (srv *Server) unbindIPv6ToMAC(ip ipv6) {
	srv.ipv6ToMACsRWM.Lock()
	defer srv.ipv6ToMACsRWM.Unlock()
	delete(srv.ipv6ToMACs, ip)
}

func (srv *Server) ipv4ToMAC(ip ipv4) mac {
	srv.ipv4ToMACsRWM.RLock()
	defer srv.ipv4ToMACsRWM.RUnlock()
	return srv.ipv4ToMACs[ip]
}

func (srv *Server) ipv6ToMAC(ip ipv6) mac {
	srv.ipv6ToMACsRWM.RLock()
	defer srv.ipv6ToMACsRWM.RUnlock()
	return srv.ipv6ToMACs[ip]
}

func (srv *Server) prepareConnPool(token sessionToken) {
	srv.connPoolsRWM.Lock()
	defer srv.connPoolsRWM.Unlock()
	if srv.isClosed() {
		return
	}
	if srv.connPools[token] != nil {
		return
	}
	srv.connPools[token] = newConnPool(srv.connPoolSize)
}

func (srv *Server) removeConnPool(token sessionToken) {
	srv.connPoolsRWM.Lock()
	defer srv.connPoolsRWM.Unlock()
	pool, ok := srv.connPools[token]
	if !ok {
		return
	}
	delete(srv.connPools, token)
	err := pool.Close()
	if err == nil {
		return
	}
	srv.logger.Error("failed to remove connection pool:", err)
}

func (srv *Server) getConnPool(token sessionToken) *connPool {
	srv.connPoolsRWM.RLock()
	defer srv.connPoolsRWM.RUnlock()
	return srv.connPools[token]
}

func (srv *Server) getConnPoolByMAC(mac mac) *connPool {
	token := srv.getSessionTokenByMAC(mac)
	if token == emptySessionToken {
		return nil
	}
	return srv.getConnPool(token)
}

func (srv *Server) getSessionTokenByMAC(mac mac) sessionToken {
	srv.macsRWM.RLock()
	defer srv.macsRWM.RUnlock()
	return srv.macs[mac]
}

func (srv *Server) getConnPoolByIPv4(ip ipv4) *connPool {
	token := srv.getSessionTokenByIPv4(ip)
	if token == emptySessionToken {
		return nil
	}
	return srv.getConnPool(token)
}

func (srv *Server) getSessionTokenByIPv4(ip ipv4) sessionToken {
	srv.ipv4sRWM.RLock()
	defer srv.ipv4sRWM.RUnlock()
	return srv.ipv4s[ip]
}

func (srv *Server) getConnPoolByIPv6(ip ipv6) *connPool {
	token := srv.getSessionTokenByIPv6(ip)
	if token == emptySessionToken {
		return nil
	}
	return srv.getConnPool(token)
}

func (srv *Server) getSessionTokenByIPv6(ip ipv6) sessionToken {
	srv.ipv6sRWM.RLock()
	defer srv.ipv6sRWM.RUnlock()
	return srv.ipv6s[ip]
}

func (srv *Server) broadcast(data []byte) {
	srv.connPoolsRWM.RLock()
	defer srv.connPoolsRWM.RUnlock()
	for _, pool := range srv.connPools {
		if srv.isClosed() {
			return
		}
		_, _ = pool.Write(data)
	}
}

func (srv *Server) broadcastExcept(data []byte, token sessionToken) {
	srv.connPoolsRWM.RLock()
	defer srv.connPoolsRWM.RUnlock()
	for t, pool := range srv.connPools {
		if srv.isClosed() {
			return
		}
		if t == token {
			continue
		}
		_, _ = pool.Write(data)
	}
}

func (srv *Server) isClosed() bool {
	return atomic.LoadInt32(&srv.closed) != 0
}

// Close is used to close accelerator server.
func (srv *Server) Close() error {
	atomic.StoreInt32(&srv.closed, 1)
	srv.cancel()
	var err error
	if srv.tlsListener != nil {
		e := srv.tlsListener.Close()
		if e != nil && !errors.Is(e, net.ErrClosed) {
			srv.logger.Error("failed to close tls listener:", e)
			err = e
		}
		srv.logger.Info("tls listener is closed")
	}
	if srv.quicListener != nil {
		e := srv.quicListener.Close()
		if e != nil && !errors.Is(e, net.ErrClosed) {
			srv.logger.Error("failed to close quic listener:", e)
			if err == nil {
				err = e
			}
		}
		srv.logger.Info("quic listener is closed")
	}
	srv.logger.Info("all listeners are closed")
	srv.connPoolsRWM.Lock()
	defer srv.connPoolsRWM.Unlock()
	for token, pool := range srv.connPools {
		e := pool.Close()
		if e != nil {
			srv.logger.Error("failed to close connection pool:", e)
			if err == nil {
				err = e
			}
		}
		delete(srv.connPools, token)
	}
	srv.logger.Info("all connection pools are closed")
	srv.wg.Wait()
	srv.handle.Close()
	srv.logger.Info("pcap handle is closed")
	if srv.nat != nil {
		srv.nat.Close()
		srv.logger.Info("nat module is closed")
	}
	srv.logger.Info("accelerator server is stopped")
	e := srv.logger.Close()
	if e != nil && err == nil {
		err = e
	}
	return err
}
