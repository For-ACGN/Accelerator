package accelerator

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"

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
	return addresses[0].String(), nil
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
