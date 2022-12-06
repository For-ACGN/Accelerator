package accelerator

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/songgao/water"
)

// Client is the accelerator client.
type Client struct {
	config    *ClientConfig
	localAddr string

	logger    *logger
	tlsConfig *tls.Config
	tap       *water.Interface
	mac       net.HardwareAddr

	wg sync.WaitGroup
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
	if poolSize < 1 {
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
	nic, err := net.InterfaceByName(tap.Name())
	if err != nil {
		return nil, errors.WithStack(err)
	}
	client := Client{
		config:    cfg,
		localAddr: localAddr,
		logger:    lg,
		tlsConfig: tlsConfig,
		tap:       tap,
		mac:       nic.HardwareAddr,
	}
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

func (client *Client) Start() error {
	var err error
	for i := 0; i < 3; i++ {
		err = client.authenticate()
		if err == nil {
			break
		}
		client.logger.Error("failed to authenticate, wait 3 seconds and try it again.")
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		return err
	}
	client.logger.Info("connect accelerator server successfully!")
	client.wg.Add(1)
	go client.readLoop()
	client.wg.Add(1)
	go client.writeLoop()
	return nil
}

func (client *Client) authenticate() error {

	handshake := make([]byte, 1+6) // mac
	handshake[0] = 1
	copy(handshake[1:], client.mac)
	request, err := client.encrypt(handshake)
	if err != nil {
		return err
	}
	_, err = client.packet.WriteTo(request, client.srvAddr)
	if err != nil {
		return err
	}
	_ = client.packet.SetReadDeadline(time.Now().Add(10 * time.Second))
	response := make([]byte, 1024)
	n, addr, err := client.packet.ReadFrom(response)
	if err != nil {
		return err
	}
	if addr.String() != client.addrStr {
		return errors.New("not accelerator server address")
	}
	response, err = client.decrypt(response[:n])
	if err != nil {
		return err
	}
	if len(response) > 1 && response[0] == 1 {
		_ = client.packet.SetDeadline(time.Time{})
		return nil
	}
	return errors.New("failed to authenticate")
}
