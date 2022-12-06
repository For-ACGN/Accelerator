package accelerator

import (
	"strings"
	"time"

	"github.com/pkg/errors"
)

// ServerConfig contains accelerator server configurations.
type ServerConfig struct {
	Common struct {
		Interface string `toml:"interface"`
		Password  string `toml:"password"`
		LogPath   string `toml:"log_path"`
	} `toml:"common"`

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

	NAT struct {
		Enabled     bool          `toml:"enabled"`
		GatewayIPv4 string        `toml:"gateway_ipv4"`
		GatewayIPv6 string        `toml:"gateway_ipv6"`
		GatewayMAC  string        `toml:"gateway_mac"`
		UDPTimeout  time.Duration `toml:"udp_timeout"`
	} `toml:"nat"`
}

// ClientConfig contains accelerator client configurations.
type ClientConfig struct {
	Common struct {
		Interface string `toml:"interface"`
		Password  string `toml:"password"`
		LogPath   string `toml:"log_path"`
	} `toml:"common"`

	Client struct {
		Mode         string `toml:"mode"`
		ConnPoolSize int    `toml:"conn_pool_size"`
	} `toml:"client"`

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
		DeviceName  string `toml:"device_name"`
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
