package accelerator

import (
	"crypto/tls"
	"fmt"

	"github.com/google/gopacket/pcap"
	"github.com/lucas-clemente/quic-go"
	"github.com/pkg/errors"
)

var errServerClosed = fmt.Errorf("accelerator server is closed")

// Server is the accelerator server.
type Server struct {
	config   *ServerConfig
	passHash []byte

	handle    *pcap.Handle
	logger    *logger
	tlsConfig *tls.Config
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
	tlsConfig, err := newClientTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	// start TCP listener

	// start UDP listener

	quic.Listen()

	server := Server{
		config:   cfg,
		passHash: passHash,
	}
	return &server, nil
}

func openPcapDevice(device string) (*pcap.Handle, error) {
	iHandle, err := pcap.NewInactiveHandle(device)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	err = iHandle.SetSnapLen(65535)
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
	return handle, nil
}
