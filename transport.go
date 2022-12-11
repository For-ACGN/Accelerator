package accelerator

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type transConn struct {
	ctx *Server

	nat    bool
	handle *pcap.Handle
	conn   net.Conn
	token  sessionToken

	eth   *layers.Ethernet
	arp   *layers.ARP
	ipv4  *layers.IPv4
	ipv6  *layers.IPv6
	icmp4 *layers.ICMPv4
	icmp6 *layers.ICMPv6
	tcp   *layers.TCP
	udp   *layers.UDP

	parser  *gopacket.DecodingLayerParser
	decoded *[]gopacket.LayerType

	// check client is income new
	srcMAC []net.HardwareAddr

	slOpt gopacket.SerializeOptions
	slBuf gopacket.SerializeBuffer
}

func (srv *Server) newTransportConn(conn net.Conn, token sessionToken) *transConn {
	nat := srv.config.NAT.Enabled
	eth := new(layers.Ethernet)
	arp := new(layers.ARP)
	ipv4 := new(layers.IPv4)
	ipv6 := new(layers.IPv6)
	icmp4 := new(layers.ICMPv4)
	icmp6 := new(layers.ICMPv6)
	tcp := new(layers.TCP)
	udp := new(layers.UDP)
	var parser *gopacket.DecodingLayerParser
	if nat {
		parser = gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			eth, arp,
			ipv4, icmp4,
			ipv6, icmp6,
			tcp, udp,
		)
	} else {
		parser = gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			eth,
		)
	}
	parser.IgnoreUnsupported = true
	decoded := new([]gopacket.LayerType)
	slOpt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	slBuf := gopacket.NewSerializeBuffer()
	tc := transConn{
		ctx:     srv,
		nat:     nat,
		handle:  srv.handle,
		conn:    conn,
		token:   token,
		eth:     eth,
		arp:     arp,
		ipv4:    ipv4,
		ipv6:    ipv6,
		icmp4:   icmp4,
		icmp6:   icmp6,
		tcp:     tcp,
		udp:     udp,
		parser:  parser,
		decoded: decoded,
		slOpt:   slOpt,
		slBuf:   slBuf,
	}
	return &tc
}

func (tc *transConn) transport() {
	_ = tc.conn.SetDeadline(time.Time{})
	var (
		size uint16
		err  error
	)
	buf := make([]byte, maxPacketSize)
	for {
		// read frame packet size
		_, err = io.ReadFull(tc.conn, buf[:frameHeaderSize])
		if err != nil {
			return
		}
		size = binary.BigEndian.Uint16(buf[:frameHeaderSize])
		// read frame packet
		_, err = io.ReadFull(tc.conn, buf[:size])
		if err != nil {
			return
		}
		if tc.nat {
			tc.decodeWithNAT(buf[:size])
		} else {
			tc.decodeWithoutNAT(buf[:size])
		}
	}
}

func (tc *transConn) decodeWithoutNAT(buf []byte) {
	err := tc.parser.DecodeLayers(buf, tc.decoded)
	if err != nil {
		return
	}
	decoded := *tc.decoded
	if len(decoded) < 1 {
		return
	}
	if decoded[0] != layers.LayerTypeEthernet {
		return
	}
	tc.checkSrcMAC()
	_ = tc.handle.WritePacketData(buf)
}

func (tc *transConn) decodeWithNAT(buf []byte) {
	err := tc.parser.DecodeLayers(buf, tc.decoded)
	if err != nil {
		return
	}
	decoded := *tc.decoded
	for i := 0; i < len(decoded); i++ {
		switch decoded[i] {
		case layers.LayerTypeEthernet:
		case layers.LayerTypeARP:
		case layers.LayerTypeIPv4:
		case layers.LayerTypeIPv6:
		case layers.LayerTypeICMPv4:
		case layers.LayerTypeICMPv6:
		case layers.LayerTypeTCP:
		case layers.LayerTypeUDP:
		}
	}

	// err = tc.handle.WritePacketData()
	// if err != nil {
	// 	return
	// }
}

func (tc *transConn) checkSrcMAC() {
	var exist bool
	for i := 0; i < len(tc.srcMAC); i++ {
		if bytes.Equal(tc.srcMAC[i], tc.eth.SrcMAC) {
			exist = true
			break
		}
	}
	if exist {
		return
	}
	// must copy, because DecodeLayers use reference
	mac := [6]byte{}
	copy(mac[:], tc.eth.SrcMAC)
	tc.srcMAC = append(tc.srcMAC, mac[:])
	tc.ctx.bindMAC(tc.token, mac)
}
