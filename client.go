package accelerator

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/songgao/water"
)

var errClientClosed = fmt.Errorf("accelerator client is closed")

// Client is the accelerator client.
type Client struct {
	config    *ClientConfig
	localAddr string

	logger    *logger
	tlsConfig *tls.Config
	tap       *water.Interface
	connPool  *connPool

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
	localAddr, err := getLocalAddress(cfg)
	if err != nil {
		return nil, err
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
	tap, err := newTAP(cfg)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !ok {
			_ = tap.Close()
		}
	}()
	pool := newConnPool(lg, tap, poolSize)
	client := Client{
		config:    cfg,
		localAddr: localAddr,
		logger:    lg,
		tlsConfig: tlsConfig,
		tap:       tap,
		connPool:  pool,
		packetCh:  make(chan *packet, 8192),
	}
	client.packetCache.New = func() interface{} {
		return newPacket()
	}
	client.ctx, client.cancel = context.WithCancel(context.Background())
	ok = true
	return &client, nil
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

func newClientTLSConfig(cfg *ClientConfig) (*tls.Config, error) {
	caPEM, err := os.ReadFile(cfg.TLS.RootCA)
	if err != nil {
		return nil, err
	}
	certs, err := ParseCertificatesPEM(caPEM)
	if err != nil {
		return nil, err
	}
	config := tls.Config{
		RootCAs: x509.NewCertPool(),
	}
	for i := 0; i < len(certs); i++ {
		config.RootCAs.AddCert(certs[i])
	}
	certFile := cfg.TLS.ClientCert
	keyFile := cfg.TLS.ClientKey
	if certFile != "" && keyFile != "" {
		tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		config.Certificates = []tls.Certificate{tlsCert}
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
	switch client.config.Client.Mode {
	case "tcp-tls":
		tcp := client.config.TCP
		lAddr, err := net.ResolveTCPAddr(tcp.LocalNetwork, client.localAddr)
		if err != nil {
			return nil, err
		}
		rAddr, err := net.ResolveTCPAddr(tcp.RemoteNetwork, tcp.RemoteAddress)
		if err != nil {
			return nil, err
		}
		tcpConn, err := net.DialTCP("tcp", lAddr, rAddr)
		if err != nil {
			return nil, err
		}
		// near the MTU
		_ = tcpConn.SetReadBuffer(2048)
		_ = tcpConn.SetWriteBuffer(2048)
		conn = tls.Client(tcpConn, client.tlsConfig)
	case "udp-quic":
		// TODO
	}
	return conn, nil
}

func (client *Client) authenticate(conn net.Conn) error {

	return nil
}

// Run is used to run the accelerator client.
func (client *Client) Run() error {
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
	err = client.authenticate(conn)
	if err != nil {
		return errors.WithMessage(err, "failed to authenticate")
	}
	err = conn.Close()
	if err != nil {
		return errors.WithMessage(err, "failed to close authentication connection")
	}
	client.logger.Info("connect accelerator server ok!")
	// start connection pool watcher

	// wait connection pool watcher create new connection
	select {
	case <-time.After(time.Second):
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
	client.logger.Info("start accelerator client successfully!")
	return nil
}

func (client *Client) packetReader() {
	defer client.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			client.logger.Fatal(r)
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
		n, err = client.tap.Read(buf[frameHeaderSize:])
		if err != nil {
			return
		}
		// put frame data size
		binary.BigEndian.PutUint16(buf, uint16(n))
		// build packet
		pkt = client.packetCache.Get().(*packet)
		size = n + frameHeaderSize
		copy(pkt.buf, buf[:size])
		pkt.size = size
		select {
		case client.packetCh <- pkt:
		case <-client.ctx.Done():
			return
		}
	}
}

func (client *Client) packetWriter() {
	defer client.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			client.logger.Fatal(r)
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
	client.wg.Wait()
	err := client.connPool.Close()
	e := client.tap.Close()
	if e != nil && err == nil {
		err = e
	}
	return err
}
