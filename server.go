package accelerator

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
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

// Server is the accelerator server.
type Server struct {
	config   *ServerConfig
	passHash []byte
	timeout  time.Duration

	handle       *pcap.Handle
	logger       *logger
	tlsListener  net.Listener
	quicListener net.Listener

	tokens    map[[tokenSize]byte]struct{}
	tokensRWM sync.RWMutex

	macs    map[[6]byte][tokenSize]byte
	macsMu  sync.Mutex
	ipv4s   map[[net.IPv4len]byte][tokenSize]byte
	ipv4sMu sync.Mutex
	ipv6s   map[[net.IPv6len]byte][tokenSize]byte
	ipv6sMu sync.Mutex

	connPools    map[[tokenSize]byte]*connPool
	connPoolsRWM sync.RWMutex

	packetCh    chan *packet
	packetCache sync.Pool

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
	// set timeout
	timeout := cfg.Common.Timeout
	if timeout < 1 {
		timeout = 10 * time.Second
	}
	var (
		tlsListener  net.Listener
		quicListener net.Listener
		listened     bool
	)
	// start TCP listener
	if cfg.TCP.Enabled {
		tlsListener, err = tls.Listen(cfg.TCP.Network, cfg.TCP.Address, tlsConfig)
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
	// start UDP listener
	if cfg.UDP.Enabled {
		quicListener, err = quicListen(cfg.UDP.Network, cfg.UDP.Address, tlsConfig, timeout)
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
	// TODO initialize NAT
	server := Server{
		config:       cfg,
		passHash:     passHash,
		timeout:      timeout,
		handle:       handle,
		logger:       lg,
		tlsListener:  tlsListener,
		quicListener: quicListener,
		tokens:       make(map[[tokenSize]byte]struct{}, 16),
		connPools:    make(map[[tokenSize]byte]*connPool, 16),
		packetCh:     make(chan *packet, 64*1024),
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
					srv.logger.Warningf(format, err, delay)
				}
				time.Sleep(delay)
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			srv.logger.Error("failed to accept:", err)
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
		const format = "[%s] failed to authenticate: %s"
		srv.logger.Warningf(format, conn.RemoteAddr(), err)
		return
	}
	// read command
	buf := make([]byte, cmdSize)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		const format = "[%s] failed to read command: %s"
		srv.logger.Warningf(format, conn.RemoteAddr(), err)
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
		const format = "[%s] read invalid command: %d"
		srv.logger.Warningf(format, conn.RemoteAddr(), cmd)
		return
	}
}

func (srv *Server) authenticate(conn net.Conn) error {
	passHash := make([]byte, sha256.Size)
	_, err := io.ReadFull(conn, passHash)
	if err != nil {
		return errors.Wrap(err, "failed to read password hash")
	}
	if subtle.ConstantTimeCompare(srv.passHash, passHash) != 1 {
		srv.defend(conn)
		return errors.New("invalid password hash")
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
	const format = "defend client [%s] "
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

}

func (srv *Server) handleLogoff(conn net.Conn) {

}

func (srv *Server) handleTransport(conn net.Conn) {
	_ = conn.SetDeadline(time.Time{})
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
		err  error
	)
	for {
		data, _, err = srv.handle.ZeroCopyReadPacketData()
		if err != nil {
			return
		}
		pkt = srv.packetCache.Get().(*packet)
		pkt.size = copy(pkt.buf, data)
		select {
		case srv.packetCh <- pkt:
		case <-srv.ctx.Done():
			return
		}
	}
}

// packetSender is used to parse packet from destination network
// interface, if the source MAC address or IP address is matched
// in clients map, it will be sent to the connection about client.
func (srv *Server) packetSender() {
	defer srv.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			srv.logger.Fatal("Server.packetSender", r)
		}
	}()
	var pkt *packet
	for {
		select {
		case pkt = <-srv.packetCh:
			srv.sendPacket(pkt)
		case <-srv.ctx.Done():
			return
		}
	}
}

func (srv *Server) sendPacket(pkt *packet) {
	defer srv.packetCache.Put(pkt)
}

func (srv *Server) isClosed() bool {
	return atomic.LoadInt32(&srv.closed) != 0
}

// Close is used to close accelerator server.
func (srv *Server) Close() error {
	atomic.StoreInt32(&srv.closed, 1)
	var err error
	if srv.tlsListener != nil {
		err = srv.tlsListener.Close()
		if err != nil {
			srv.logger.Error("failed to close tls listener:", err)
		}
		srv.logger.Info("tls listener is closed")
	}
	if srv.quicListener != nil {
		e := srv.quicListener.Close()
		if e != nil {
			srv.logger.Error("failed to close quic listener:", e)
			if err == nil {
				err = e
			}
		}
		srv.logger.Info("quic listener is closed")
	}
	srv.logger.Info("wait listeners stop serve")
	srv.wg.Wait()
	srv.logger.Info("all listeners stop serve")
	srv.logger.Info("close all connection pools")
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
	srv.handle.Close()
	srv.logger.Info("pcap handle is closed")
	srv.logger.Info("accelerator server is stopped")
	e := srv.logger.Close()
	if e != nil && err == nil {
		err = e
	}
	return err
}
