package accelerator

import (
	"net"

	"github.com/pkg/errors"
	"github.com/songgao/water"
)

// Client is the accelerator client.
type Client struct {
	config    *ClientConfig
	localAddr string

	logger *logger
	tap    *water.Interface
	mac    net.HardwareAddr
}

// NewClient is used to create a new client from configuration.
func NewClient(cfg *ClientConfig) (*Client, error) {
	// check mode
	mode := cfg.Client.Mode
	switch mode {
	case "tcp-tls", "udp-quic":
	default:
		return nil, errors.Errorf("invalid mode: \"%s\"", mode)
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
