package accelerator

import (
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type transConn struct {
	ctx *Server

	conn net.Conn
	nat  bool

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

	slOpt gopacket.SerializeOptions
	slBuf gopacket.SerializeBuffer
}

func (srv *Server) newTransportConn(conn net.Conn) *transConn {
	eth := new(layers.Ethernet)
	arp := new(layers.ARP)
	ipv4 := new(layers.IPv4)
	ipv6 := new(layers.IPv6)
	icmp4 := new(layers.ICMPv4)
	icmp6 := new(layers.ICMPv6)
	tcp := new(layers.TCP)
	udp := new(layers.UDP)
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		eth, arp,
		ipv4, icmp4,
		ipv6, icmp6,
		tcp, udp,
	)
	parser.IgnoreUnsupported = true
	decoded := new([]gopacket.LayerType)
	slOpt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	slBuf := gopacket.NewSerializeBuffer()
	tc := transConn{
		ctx:     srv,
		conn:    conn,
		nat:     srv.config.NAT.Enabled,
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

func (t *transConn) transport() {
	_ = t.conn.SetDeadline(time.Time{})
	var (
		size uint16
		err  error
	)
	buf := make([]byte, maxPacketSize)
	for {
		// read frame packet size
		_, err = io.ReadFull(t.conn, buf[:frameHeaderSize])
		if err != nil {
			return
		}
		size = binary.BigEndian.Uint16(buf[:frameHeaderSize])
		// read frame packet
		_, err = io.ReadFull(t.conn, buf[:size])
		if err != nil {
			return
		}
		t.decode(buf[:size])
	}
}

func (t *transConn) decode(buf []byte) {
	err := t.parser.DecodeLayers(buf, t.decoded)
	if err != nil {
		return
	}

	for i := 0; i < len(); i++ {
		if decoded[i] != layers.LayerTypeEthernet {
			continue
		}
	}

	if !srv.useNAT {
		err = srv.handle.WritePacketData(buf[:size])
		if err != nil {
			return
		}
		continue
	}
}
