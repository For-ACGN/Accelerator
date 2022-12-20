package accelerator

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/songgao/water"
)

const (
	defaultClientConnPoolSize = 64
	defaultClientTimeout      = 15 * time.Second
)

var errClientClosed = fmt.Errorf("accelerator client is closed")

// Client is the accelerator client.
type Client struct {
	passHash     []byte
	mode         string
	connPoolSize int
	timeout      time.Duration
	remoteNet    string
	remoteAddr   string
	localNet     string
	localAddr    string

	logger    *logger
	tlsConfig *tls.Config
	tapDev    *water.Interface
	connPool  *connPool
	token     atomic.Value

	frameCh    chan *frame
	frameCache sync.Pool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewClient is used to create a new client from configuration.
func NewClient(cfg *ClientConfig) (*Client, error) {
	// check common config
	passHash, err := decodePasswordHash(cfg.Common.PassHash)
	if err != nil {
		return nil, err
	}
	mode := cfg.Client.Mode
	switch mode {
	case "tcp-tls", "udp-quic":
	default:
		return nil, errors.Errorf("invalid transport mode: \"%s\"", mode)
	}
	poolSize := cfg.Client.ConnPoolSize
	if poolSize < 1 {
		poolSize = defaultClientConnPoolSize
	}
	timeout := time.Duration(cfg.Client.Timeout)
	if timeout < 1 {
		timeout = defaultClientTimeout
	}
	remoteNet, remoteAddr, err := getClientRemoteNetworkAndAddress(cfg)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to get remote network and address")
	}
	localNet := getClientLocalNetwork(cfg)
	localAddr, err := getClientLocalAddress(cfg)
	if err != nil {
		return nil, err
	}
	err = checkNetworkAndAddress(localNet, localAddr)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to check local network and address")
	}
	// initialize logger
	var ok bool
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
	tlsConfig, err := newClientTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	// initialize tap device
	tapDev, err := newTAP(cfg)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !ok {
			_ = tapDev.Close()
		}
	}()
	client := Client{
		passHash:     passHash,
		mode:         mode,
		connPoolSize: poolSize,
		timeout:      timeout,
		remoteNet:    remoteNet,
		remoteAddr:   remoteAddr,
		localNet:     localNet,
		localAddr:    localAddr,
		logger:       lg,
		tlsConfig:    tlsConfig,
		tapDev:       tapDev,
		connPool:     newConnPool(poolSize),
		frameCh:      make(chan *frame, 128*poolSize),
	}
	client.frameCache.New = func() interface{} {
		return newFrame()
	}
	client.ctx, client.cancel = context.WithCancel(context.Background())
	client.setSessionToken(emptySessionToken)
	ok = true
	return &client, nil
}

func getClientRemoteNetworkAndAddress(cfg *ClientConfig) (string, string, error) {
	var (
		network string
		address string
	)
	switch cfg.Client.Mode {
	case "tcp-tls":
		network = cfg.TCP.RemoteNetwork
		address = cfg.TCP.RemoteAddress
	case "udp-quic":
		network = cfg.UDP.RemoteNetwork
		address = cfg.UDP.RemoteAddress
	}
	err := checkNetworkAndAddress(network, address)
	if err != nil {
		return "", "", err
	}
	return network, address, nil
}

func getClientLocalNetwork(cfg *ClientConfig) string {
	var network string
	switch cfg.Client.Mode {
	case "tcp-tls":
		network = cfg.TCP.LocalNetwork
	case "udp-quic":
		network = cfg.UDP.LocalNetwork
	}
	if network != "" {
		return network
	}
	switch cfg.Client.Mode {
	case "tcp-tls":
		network = "tcp"
	case "udp-quic":
		network = "udp"
	}
	return network
}

func getClientLocalAddress(cfg *ClientConfig) (string, error) {
	var address string
	switch cfg.Client.Mode {
	case "tcp-tls":
		address = cfg.TCP.LocalAddress
	case "udp-quic":
		address = cfg.UDP.LocalAddress
	}
	if address != "" {
		return address, nil
	}
	name := cfg.Common.Interface
	nic, err := net.InterfaceByName(name)
	if err != nil {
		return "", errors.Wrapf(err, "failed to get info from interface \"%s\"", name)
	}
	addresses, err := nic.Addrs()
	if err != nil {
		return "", errors.Wrap(err, "failed to get network address")
	}
	var remoteAddr string
	switch cfg.Client.Mode {
	case "tcp-tls":
		remoteAddr = cfg.TCP.RemoteAddress
	case "udp-quic":
		remoteAddr = cfg.UDP.RemoteAddress
	}
	addrPort, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return "", errors.Wrap(err, "failed to split remote address")
	}
	isIPv4 := addrPort.Addr().Is4()
	var localIP string
	for i := 0; i < len(addresses); i++ {
		switch addr := addresses[i].(type) {
		case *net.IPAddr:
			address = addr.IP.String()
		case *net.IPNet:
			address = addr.IP.String()
		}
		addr, err := netip.ParseAddr(address)
		if err != nil {
			return "", errors.Wrap(err, "failed to parse ip address")
		}
		if addr.Is4() == isIPv4 {
			localIP = address
			break
		}
	}
	if len(localIP) < 1 {
		return "", errors.Errorf("failed to select address on interface: \"%s\"", name)
	}
	return net.JoinHostPort(localIP, "0"), nil
}

func newClientTLSConfig(cfg *ClientConfig) (*tls.Config, error) {
	caPEM, err := os.ReadFile(cfg.TLS.RootCA)
	if err != nil {
		return nil, err
	}
	certs, err := parseCertificatesPEM(caPEM)
	if err != nil {
		return nil, err
	}
	tlsCert, err := tls.LoadX509KeyPair(cfg.TLS.ClientCert, cfg.TLS.ClientKey)
	if err != nil {
		return nil, err
	}
	config := tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      x509.NewCertPool(),
	}
	for i := 0; i < len(certs); i++ {
		config.RootCAs.AddCert(certs[i])
	}
	return &config, nil
}

func (client *Client) connect(ctx context.Context) (net.Conn, error) {
	conn, err := client.dial(ctx)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to connect server")
	}
	err = client.authenticate(conn)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to authenticate")
	}
	return conn, nil
}

func (client *Client) dial(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	var conn net.Conn
	switch client.mode {
	case "tcp-tls":
		lAddr, err := net.ResolveTCPAddr(client.localNet, client.localAddr)
		if err != nil {
			return nil, err
		}
		dialer := tls.Dialer{
			NetDialer: &net.Dialer{
				LocalAddr: lAddr,
			},
			Config: client.tlsConfig,
		}
		conn, err = dialer.DialContext(ctx, client.remoteNet, client.remoteAddr)
		if err != nil {
			return nil, err
		}
		// set the buffer size near the MTU value
		tcpConn := conn.(*tls.Conn).NetConn().(*net.TCPConn)
		_ = tcpConn.SetReadBuffer(2048)
		_ = tcpConn.SetWriteBuffer(2048)
	case "udp-quic":
		lAddr, err := net.ResolveUDPAddr(client.localNet, client.localAddr)
		if err != nil {
			return nil, err
		}
		rAddr, err := net.ResolveUDPAddr(client.remoteNet, client.remoteAddr)
		if err != nil {
			return nil, err
		}
		conn, err = quicDial(ctx, lAddr, rAddr, client.tlsConfig)
		if err != nil {
			return nil, err
		}
	}
	return conn, nil
}

func (client *Client) authenticate(conn net.Conn) error {
	// send authentication request
	req, err := buildAuthRequest(client.passHash)
	if err != nil {
		return errors.WithMessage(err, "failed to build authentication request")
	}
	_, err = conn.Write(req)
	if err != nil {
		return errors.Wrap(err, "failed to send authentication request")
	}
	// read authentication response
	buf := make([]byte, cmdSize+2) // uint16
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return errors.Wrap(err, "failed to receive authentication response")
	}
	resp := buf[0]
	if resp != authOK {
		return errors.Errorf("invalid authentication response: %d", resp)
	}
	// read padding random data
	size := binary.BigEndian.Uint16(buf[cmdSize:])
	_, err = io.CopyN(io.Discard, conn, int64(size))
	if err != nil {
		return errors.Wrap(err, "failed to receive padding random data")
	}
	return nil
}

// Run is used to run the accelerator client.
func (client *Client) Run() error {
	err := client.login()
	if err != nil {
		return errors.WithMessage(err, "failed to log in")
	}
	client.logger.Info("connect accelerator server successfully")
	// start status watcher
	client.wg.Add(1)
	go client.watcher()
	client.logger.Info("initialize accelerator status watcher")
	select {
	case <-time.After(2 * time.Second):
	case <-client.ctx.Done():
		return errors.WithStack(errClientClosed)
	}
	// start frame reader
	client.wg.Add(1)
	go client.frameReader()
	// start frame writer
	for i := 0; i < client.connPoolSize; i++ {
		client.wg.Add(1)
		go client.frameWriter()
	}
	client.logger.Info("accelerator client is running")
	return nil
}

func (client *Client) getSessionToken() sessionToken {
	return client.token.Load().(sessionToken)
}

func (client *Client) setSessionToken(token sessionToken) {
	client.token.Store(token)
}

func (client *Client) login() error {
	var (
		conn net.Conn
		err  error
	)
	for i := 0; i < 3; i++ {
		conn, err = client.dial(client.ctx)
		if err == nil {
			break
		}
		client.logger.Errorf("%s, wait 3 seconds and try it again.", err)
		select {
		case <-time.After(3 * time.Second):
		case <-client.ctx.Done():
			return errors.WithStack(errClientClosed)
		}
	}
	if err != nil {
		return err
	}
	defer func() {
		err = conn.Close()
		if err != nil {
			client.logger.Error("failed to close connection for log in:", err)
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(client.timeout))
	err = client.authenticate(conn)
	if err != nil {
		return errors.WithMessage(err, "failed to authenticate")
	}
	req := make([]byte, cmdSize+obfSize)
	req[0] = cmdLogin
	_, err = rand.Read(req[cmdSize:])
	if err != nil {
		return errors.WithMessage(err, "failed to generate random data for log in")
	}
	_, err = conn.Write(req)
	if err != nil {
		return errors.WithMessage(err, "failed to send log in request")
	}
	buf := make([]byte, cmdSize+tokenSize)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return errors.WithMessage(err, "failed to receive log in response")
	}
	resp := buf[0]
	if resp != loginOK {
		return errors.Errorf("invalid log in response: %d", resp)
	}
	token := sessionToken{}
	copy(token[:], buf[cmdSize:])
	client.setSessionToken(token)
	return nil
}

func (client *Client) logoff() error {
	token := client.getSessionToken()
	if token == emptySessionToken {
		return nil
	}
	conn, err := client.connect(context.Background())
	if err != nil {
		return err
	}
	defer func() {
		err = conn.Close()
		if err != nil {
			client.logger.Error("failed to close connection for log off:", err)
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(client.timeout))
	req := make([]byte, cmdSize+tokenSize)
	req[0] = cmdLogoff
	copy(req[cmdSize:], token[:])
	_, err = conn.Write(req)
	if err != nil {
		return errors.WithMessage(err, "failed to send log off request")
	}
	buf := make([]byte, cmdSize)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return errors.WithMessage(err, "failed to receive log off response")
	}
	resp := buf[0]
	if resp != logoffOK {
		return errors.Errorf("invalid log off response: %d", resp)
	}
	client.setSessionToken(emptySessionToken)
	return nil
}

// watcher is used to check connection pool is full, if it is not full,
// connect and add new connection to pool. If the server restart, the
// token session will be invalid, watcher will log in again.
func (client *Client) watcher() {
	defer client.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			client.logger.Fatal("Client.watcher", r)
		}
	}()
	const period = 100 * time.Millisecond
	timer := time.NewTimer(period)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			if client.connPool.IsFull() {
				break
			}
			conn, err := client.connect(client.ctx)
			if err == nil {
				client.wg.Add(1)
				go client.transport(conn)
			} else {
				client.logger.Error(err)
			}
		case <-client.ctx.Done():
			return
		}
		timer.Reset(period)
	}
}

// transport will send transport command to server, then it
// starts read frames from server and write to TAP device.
func (client *Client) transport(conn net.Conn) {
	defer client.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			client.logger.Fatal("Client.transport", r)
		}
	}()
	defer func() {
		err := conn.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			client.logger.Error(err)
		}
	}()
	token := client.getSessionToken()
	if token == emptySessionToken {
		return
	}
	_ = conn.SetDeadline(time.Now().Add(client.timeout))
	req := make([]byte, cmdSize+tokenSize)
	req[0] = cmdTransport
	copy(req[cmdSize:], token[:])
	_, err := conn.Write(req)
	if err != nil {
		return
	}
	buf := make([]byte, cmdSize)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return
	}
	resp := buf[0]
	if resp != transOK {
		client.logger.Errorf("invalid transport response: %d", resp)
		return
	}
	if !client.connPool.AddConn(&conn) {
		return
	}
	defer client.connPool.DeleteConn(&conn)
	_ = conn.SetDeadline(time.Time{})
	buf = make([]byte, maxFrameSize)
	var size uint16
	for {
		// read frame size
		_, err = io.ReadFull(conn, buf[:frameHeaderSize])
		if err != nil {
			return
		}
		size = binary.BigEndian.Uint16(buf[:frameHeaderSize])
		if size > maxFrameSize {
			const format = "receive too large frame: 0x%X"
			client.logger.Warningf(format, buf[:frameHeaderSize])
			return
		}
		// read frame data
		_, err = io.ReadFull(conn, buf[:size])
		if err != nil {
			return
		}
		// write to the tap device
		// copy data in buffer for prevent potential
		// data race in the under driver
		data := make([]byte, len(buf[:size]))
		copy(data, buf[:size])
		_, err = client.tapDev.Write(data)
		if err != nil {
			return
		}
	}
}

// frameReader is used to read frames from TAP device
// and send them to the frame channel.
func (client *Client) frameReader() {
	defer client.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			client.logger.Fatal("Client.frameReader", r)
		}
	}()
	var (
		n   int
		fr  *frame
		err error
	)
	buf := make([]byte, maxFrameSize)
	for {
		// read frame data
		n, err = client.tapDev.Read(buf)
		if err != nil {
			return
		}
		// build frame
		fr = client.frameCache.Get().(*frame)
		fr.WriteHeader(n)
		fr.WriteData(buf[:n])
		select {
		case client.frameCh <- fr:
		case <-client.ctx.Done():
			return
		}
	}
}

// frameWriter is used to read frames from frame channel
// and write them to the server by the connection pool.
func (client *Client) frameWriter() {
	defer client.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			client.logger.Fatal("Client.frameWriter", r)
		}
	}()
	var (
		fr  *frame
		err error
	)
	for {
		select {
		case fr = <-client.frameCh:
			_, err = client.connPool.Write(fr.Data())
			if err != nil {
				client.logger.Error("failed to send frame:", err)
			}
			fr.Reset()
			client.frameCache.Put(fr)
		case <-client.ctx.Done():
			return
		}
	}
}

// Close is used to close accelerator client.
func (client *Client) Close() error {
	client.cancel()
	err := client.tapDev.Close()
	if err != nil {
		client.logger.Error("failed to close tap device:", err)
	}
	client.logger.Info("tap device is closed")
	e := client.connPool.Close()
	if e != nil {
		if err == nil {
			err = e
		}
		client.logger.Error("failed to close connection pool:", e)
	}
	client.logger.Info("connection pool is closed")
	client.wg.Wait()
	e = client.logoff()
	if e != nil {
		if err == nil {
			err = e
		}
		client.logger.Error("failed to log off:", e)
	}
	client.logger.Info("accelerator client is stopped")
	e = client.logger.Close()
	if e != nil && err == nil {
		err = e
	}
	return err
}
