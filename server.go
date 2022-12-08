package accelerator

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
)

var errServerClosed = fmt.Errorf("accelerator server is closed")

// Server is the accelerator server.
type Server struct {
	config   *ServerConfig
	passHash []byte
	timeout  time.Duration

	handle       *pcap.Handle
	logger       *logger
	tlsListener  net.Listener
	quicListener net.Listener

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
	server := Server{
		config:       cfg,
		passHash:     passHash,
		timeout:      timeout,
		handle:       handle,
		logger:       lg,
		tlsListener:  tlsListener,
		quicListener: quicListener,
	}
	// TODO initialize NAT
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
	cert, err := ParseCertificatePEM(caPEM)
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
