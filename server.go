package accelerator

import (
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
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
)

const (
	defaultServerConnPoolSize    = 64
	defaultServerNumPacketSender = 32
	defaultServerTimeout         = 10 * time.Second
)

// Server is the accelerator server.
type Server struct {
	passHash     []byte
	connPoolSize int
	numPktSender int
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

	connPools    map[sessionToken]*connPool
	connPoolsRWM sync.RWMutex

	packetCh    chan *packet
	packetCache *sync.Pool

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
		return nil, err
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
	numSender := cfg.Server.NumPacketSender
	if numSender < 8 {
		numSender = defaultServerNumPacketSender
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
		numPktSender: numSender,
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
		connPools:    make(map[sessionToken]*connPool, 16),
		packetCh:     make(chan *packet, 64*1024),
		packetCache:  new(sync.Pool),
	}
	server.packetCache.New = func() interface{} {
		return newPacket()
	}
	server.ctx, server.cancel = context.WithCancel(context.Background())
	ok = true
	return &server, nil
}

func openPcapDevice(device string) (*pcap.Handle, error) {
	iHandle, err := pcap.NewInactiveHandle(device)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	var ok bool
	defer func() {
		if !ok {
			iHandle.CleanUp()
		}
	}()
	err = iHandle.SetSnapLen(64 * 1024)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	err = iHandle.SetPromisc(true)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	err = iHandle.SetTimeout(pcap.BlockForever)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	err = iHandle.SetImmediateMode(true)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	err = iHandle.SetBufferSize(64 * 1024 * 1024)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	handle, err := iHandle.Activate()
	if err != nil {
		return nil, errors.WithStack(err)
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
		srv.nat.Run()
	}
	for i := 0; i < srv.numPktSender; i++ {
		sender := srv.newPacketSender()
		srv.wg.Add(1)
		go sender.sendLoop()
	}
	srv.wg.Add(1)
	go srv.captureLoop()
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
	defer func() {
		err := conn.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			srv.logger.Error(err)
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(3 * srv.timeout))
	err := srv.authenticate(conn)
	if err != nil {
		const format = "(%s) failed to authenticate: %s"
		srv.logger.Warningf(format, conn.RemoteAddr(), err)
		return
	}
	// read command
	buf := make([]byte, cmdSize)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		const format = "(%s) failed to receive command: %s"
		srv.logger.Errorf(format, conn.RemoteAddr(), err)
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
		srv.logger.Warningf(format, conn.RemoteAddr(), cmd)
		return
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
		srv.logger.Errorf(format, remoteAddr)
		return
	}
	buf := make([]byte, cmdSize)
	buf[0] = transOK
	_, err = conn.Write(buf)
	if err != nil {
		const format = "(%s) failed to send transport response: %s"
		srv.logger.Errorf(format, remoteAddr, err)
		return
	}
	// add connection to pool
	pool := srv.getConnPool(token)
	if pool == nil {
		return
	}
	if pool.IsFull() {
		return
	}
	c := &conn
	if !pool.AddConn(c) {
		return
	}
	defer pool.DeleteConn(c)
	// start transport packet
	tc := srv.newTransportConn(conn, token)
	tc.transport()
}

// captureLoop is used to capture packet from destination network
// interface and send it to the packet channel for packetSender.
func (srv *Server) captureLoop() {
	defer srv.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			srv.logger.Fatal("Server.captureLoop", r)
		}
	}()
	defer srv.handle.Close()
	var (
		data []byte
		pkt  *packet
		size int
		err  error
	)
	for {
		data, _, err = srv.handle.ZeroCopyReadPacketData()
		if err != nil {
			return
		}
		pkt = srv.packetCache.Get().(*packet)
		size = copy(pkt.buf[frameHeaderSize:], data)
		pkt.size = uint16(size)
		select {
		case srv.packetCh <- pkt:
		case <-srv.ctx.Done():
			return
		}
	}
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

func (srv *Server) bindIPv4(token sessionToken, ip ipv4) {
	srv.ipv4sRWM.Lock()
	defer srv.ipv4sRWM.Unlock()
	srv.ipv4s[ip] = token
}

func (srv *Server) unbindIPv4(token sessionToken) {
	srv.ipv4sRWM.Lock()
	defer srv.ipv4sRWM.Unlock()
	for ip, t := range srv.ipv4s {
		if t != token {
			continue
		}
		delete(srv.ipv4s, ip)
	}
}

func (srv *Server) bindIPv6(token sessionToken, ip ipv6) {
	srv.ipv6sRWM.Lock()
	defer srv.ipv6sRWM.Unlock()
	srv.ipv6s[ip] = token
}

func (srv *Server) unbindIPv6(token sessionToken) {
	srv.ipv6sRWM.Lock()
	defer srv.ipv6sRWM.Unlock()
	for ip, t := range srv.ipv6s {
		if t != token {
			continue
		}
		delete(srv.ipv6s, ip)
	}
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
	srv.handle.Close()
	srv.logger.Info("pcap handle is closed")
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
	srv.logger.Info("all listeners stop serve")
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
	srv.logger.Info("all connection pools is closed")
	srv.wg.Wait()
	if srv.nat != nil {
		srv.nat.Close()
		srv.logger.Info("nat is closed")
	}
	srv.logger.Info("accelerator server is stopped")
	e := srv.logger.Close()
	if e != nil && err == nil {
		err = e
	}
	return err
}
