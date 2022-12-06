package accelerator

import (
	"net"
	"time"

	"github.com/lucas-clemente/quic-go"
)

func (client *Client) dialQUIC() (net.Conn, error) {
	udp := client.config.UDP
	lAddr, err := net.ResolveUDPAddr(udp.LocalNetwork, client.localAddr)
	if err != nil {
		return nil, err
	}
	rAddr, err := net.ResolveUDPAddr(udp.RemoteNetwork, udp.RemoteAddress)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", lAddr)
	if err != nil {
		return nil, err
	}
	config := quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       30 * time.Second,
		KeepAlivePeriod:      15 * time.Second,
	}
	conn, err := quic.Dial(udpConn, rAddr, udp.RemoteAddress, client.tlsConfig, &config)
	if err != nil {
		return nil, err
	}
	_ = conn.CloseWithError(0, "")
	_ = udpConn.Close()
	return nil, nil
}
