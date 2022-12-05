package accelerator

import (
	"strings"

	"github.com/pkg/errors"
)

// ServerConfig contains accelerator server configurations.
type ServerConfig struct {
	Interface string `toml:"interface"`
	Password  string `toml:"password"`
	LogPath   string `toml:"log_path"`

	TCP struct {
		Enabled bool   `toml:"enabled"`
		Network string `toml:"network"`
		Address string `toml:"address"`
	} `toml:"tcp"`

	UDP struct {
		Enabled bool   `toml:"enabled"`
		Network string `toml:"network"`
		Address string `toml:"address"`
	} `toml:"udp"`

	TLS struct {
		ServerCert string `toml:"server_cert"`
		ServerKey  string `toml:"server_key"`
		ClientCA   string `toml:"client_ca"`
	} `toml:"tls"`

	Gateway struct {
		IPv4 string `toml:"ipv4"`
		IPv6 string `toml:"ipv6"`
		MAC  string `toml:"mac"`
	} `toml:"gateway"`
}

// ClientConfig contains accelerator client configurations.
type ClientConfig struct {
	Mode      string `toml:"mode"`
	Interface string `toml:"interface"`
	Password  string `toml:"password"`
	LogPath   string `toml:"log_path"`
	MaxConn   int    `toml:"max_conn"`

	TCP struct {
		RemoteNetwork string `toml:"remote_network"`
		RemoteAddress string `toml:"remote_address"`
		LocalNetwork  string `toml:"local_network"`
		LocalAddress  string `toml:"local_address"`
	} `toml:"tcp"`

	UDP struct {
		RemoteNetwork string `toml:"remote_network"`
		RemoteAddress string `toml:"remote_address"`
		LocalNetwork  string `toml:"local_network"`
		LocalAddress  string `toml:"local_address"`
	} `toml:"udp"`

	TLS struct {
		CACert     string `toml:"ca_cert"`
		ClientCert string `toml:"client_cert"`
		ClientKey  string `toml:"client_key"`
	} `toml:"tls"`

	TAP struct {
		ComponentID string `toml:"component_id"`
		Name        string `toml:"name"`
	} `toml:"tap"`
}

// CheckNetworkAndAddress is used to check network is supported and address is valid.
func CheckNetworkAndAddress(network, address string) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
	case "udp", "udp4", "udp6":
	default:
		return errors.Errorf("unsupported network: \"%s\"", network)
	}
	if !strings.Contains(address, ":") {
		return errors.New("missing port in address")
	}
	return nil
}
