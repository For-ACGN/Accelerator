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
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/songgao/water"
)

var errClientClosed = fmt.Errorf("accelerator client is closed")

// Client is the accelerator client.
type Client struct {
	config    *ClientConfig
	passHash  []byte
	localNet  string
	localAddr string

	logger    *logger
	tlsConfig *tls.Config
	tapDev    *water.Interface
	connPool  *connPool
	token     atomic.Value

	packetCh    chan *packet
	packetCache sync.Pool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewClient is used to create a new client from configuration.
func NewClient(cfg *ClientConfig) (*Client, error) {
	// check common config
	mode := cfg.Client.Mode
	switch mode {
	case "tcp-tls", "udp-quic":
	default:
		return nil, errors.Errorf("invalid mode: \"%s\"", mode)
	}
	poolSize := cfg.Client.ConnPoolSize
	if poolSize < 1 || poolSize > 256 {
		return nil, errors.Errorf("invalid conn pool size: \"%d\"", poolSize)
	}
	passHash, err := decodePasswordHash(cfg.Common.PassHash)
	if err != nil {
		return nil, err
	}
	localNet := getLocalNetwork(cfg)
	localAddr, err := getLocalAddress(cfg)
	if err != nil {
		return nil, err
	}
	err = checkNetworkAndAddress(localNet, localAddr)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to check local network and address")
	}
	err = checkRemoteNetworkAndAddress(cfg)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to check remote network and address")
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
		config:    cfg,
		passHash:  passHash,
		localNet:  localNet,
		localAddr: localAddr,
		logger:    lg,
		tlsConfig: tlsConfig,
		tapDev:    tapDev,
		connPool:  newConnPool(poolSize),
		packetCh:  make(chan *packet, 128*poolSize),
	}
	client.packetCache.New = func() interface{} {
		return newPacket()
	}
	client.ctx, client.cancel = context.WithCancel(context.Background())
	client.setSessionToken(emptySessionToken)
	ok = true
	return &client, nil
}

func getLocalNetwork(cfg *ClientConfig) string {
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

func getLocalAddress(cfg *ClientConfig) (string, error) {
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
	if len(addresses) < 1 {
		return "", errors.Errorf("empty address on interface: \"%s\"", name)
	}
	return net.JoinHostPort(addresses[0].String(), "0"), nil
}

func checkRemoteNetworkAndAddress(cfg *ClientConfig) error {
	var err error
	switch cfg.Client.Mode {
	case "tcp-tls":
		err = checkNetworkAndAddress(cfg.TCP.RemoteNetwork, cfg.TCP.RemoteAddress)
	case "udp-quic":
		err = checkNetworkAndAddress(cfg.UDP.RemoteNetwork, cfg.UDP.RemoteAddress)
	}
	return err
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

func (client *Client) connect() (net.Conn, error) {
	conn, err := client.dial()
	if err != nil {
		return nil, errors.WithMessage(err, "failed to connect server")
	}
	err = client.authenticate(conn)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to authenticate")
	}
	return conn, nil
}

func (client *Client) dial() (net.Conn, error) {
	var conn net.Conn
	ctx, cancel := context.WithTimeout(client.ctx, 15*time.Second)
	defer cancel()
	switch client.config.Client.Mode {
	case "tcp-tls":
		lAddr, err := net.ResolveTCPAddr(client.localNet, client.localAddr)
		if err != nil {
			return nil, err
		}
		dialer := net.Dialer{
			LocalAddr: lAddr,
		}
		tcp := client.config.TCP
		conn, err = dialer.DialContext(ctx, tcp.RemoteNetwork, tcp.RemoteAddress)
		if err != nil {
			return nil, err
		}
		// set the buffer size near the MTU value
		tcpConn := conn.(*net.TCPConn)
		_ = tcpConn.SetReadBuffer(2048)
		_ = tcpConn.SetWriteBuffer(2048)
		conn = tls.Client(conn, client.tlsConfig)
	case "udp-quic":
		lAddr, err := net.ResolveUDPAddr(client.localNet, client.localAddr)
		if err != nil {
			return nil, err
		}
		udp := client.config.UDP
		rAddr, err := net.ResolveUDPAddr(udp.RemoteNetwork, udp.RemoteAddress)
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
	buf := make([]byte, cmdSize+2)
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
	client.logger.Info("connect accelerator server successfully!")
	// start connection pool watcher
	client.wg.Add(1)
	go client.connPoolWatcher()
	client.logger.Info("wait connection pool watcher create new connection")
	select {
	case <-time.After(2 * time.Second):
	case <-client.ctx.Done():
		return errors.WithStack(errClientClosed)
	}
	// start packet reader
	client.wg.Add(1)
	go client.packetReader()
	// start packet writer
	for i := 0; i < client.config.Client.ConnPoolSize; i++ {
		client.wg.Add(1)
		go client.packetWriter()
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
		conn, err = client.dial()
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
			client.logger.Error("failed to close connection for log in", err)
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
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
	conn, err := client.connect()
	if err != nil {
		return err
	}
	defer func() {
		err = conn.Close()
		if err != nil {
			client.logger.Error("failed to close connection for log off", err)
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
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

// connPoolWatcher is used to check connection pool is full,
// if it is not full, connect and add new connection to pool.
func (client *Client) connPoolWatcher() {
	defer client.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			client.logger.Fatal("Client.connPoolWatcher", r)
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
			conn, err := client.connect()
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
// starts read packet from server and write to TAP device.
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
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
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
	buf = make([]byte, maxPacketSize)
	var size uint16
	for {
		// read frame packet size
		_, err = io.ReadFull(conn, buf[:frameHeaderSize])
		if err != nil {
			return
		}
		size = binary.BigEndian.Uint16(buf[:frameHeaderSize])
		// read frame packet
		_, err = io.ReadFull(conn, buf[:size])
		if err != nil {
			return
		}
		// write to the tap device
		_, err = client.tapDev.Write(buf[:size])
		if err != nil {
			return
		}
	}
}

// packetReader is used to read packet from TAP device
// and send it to the packet channel.
func (client *Client) packetReader() {
	defer client.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			client.logger.Fatal("Client.packetReader", r)
		}
	}()
	var (
		n    int
		size int
		pkt  *packet
		err  error
	)
	buf := make([]byte, maxPacketSize)
	for {
		// read frame data
		n, err = client.tapDev.Read(buf[frameHeaderSize:])
		if err != nil {
			return
		}
		// put frame data size
		binary.BigEndian.PutUint16(buf, uint16(n))
		// build packet
		pkt = client.packetCache.Get().(*packet)
		size = frameHeaderSize + n
		copy(pkt.buf, buf[:size])
		pkt.size = size
		select {
		case client.packetCh <- pkt:
		case <-client.ctx.Done():
			return
		}
	}
}

// packetWriter is used to read packet from packet channel
// and write it to the server by the connection pool.
func (client *Client) packetWriter() {
	defer client.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			client.logger.Fatal("Client.packetWriter", r)
		}
	}()
	var (
		pkt *packet
		err error
	)
	for {
		select {
		case pkt = <-client.packetCh:
			_, err = client.connPool.Write(pkt.buf[:pkt.size])
			if err != nil {
				client.logger.Error("failed to send packet", err)
			}
			client.packetCache.Put(pkt)
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
		client.logger.Error("failed to close connection pool:", e)
		if err == nil {
			err = e
		}
	}
	client.logger.Info("connection pool is closed")
	client.wg.Wait()
	e = client.logoff()
	if e != nil {
		client.logger.Error("failed to log off:", e)
		if err == nil {
			err = e
		}
	}
	client.logger.Info("accelerator client is stopped")
	e = client.logger.Close()
	if e != nil && err == nil {
		err = e
	}
	return err
}
