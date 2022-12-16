package accelerator

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// transConn is used to read packet from client side and
// process it, then write it to the destination network
// interface or the other client connection.
type transConn struct {
	ctx *Server

	enableNAT bool

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
	slOpt   gopacket.SerializeOptions
	slBuf   gopacket.SerializeBuffer

	// check has new
	srcMAC  []net.HardwareAddr
	srcIPv4 []net.IP
	srcIPv6 []net.IP

	macCache  sync.Pool
	ipv4Cache sync.Pool
	ipv6Cache sync.Pool
}

func (srv *Server) newTransportConn(conn net.Conn, token sessionToken) *transConn {
	enableNAT := srv.enableNAT
	eth := new(layers.Ethernet)
	arp := new(layers.ARP)
	ip4 := new(layers.IPv4)
	ip6 := new(layers.IPv6)
	icmp4 := new(layers.ICMPv4)
	icmp6 := new(layers.ICMPv6)
	tcp := new(layers.TCP)
	udp := new(layers.UDP)
	var parser *gopacket.DecodingLayerParser
	if enableNAT {
		parser = gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			eth, arp,
			ip4, icmp4,
			ip6, icmp6,
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
		ctx:       srv,
		enableNAT: enableNAT,
		handle:    srv.handle,
		conn:      conn,
		token:     token,
		eth:       eth,
		arp:       arp,
		ipv4:      ip4,
		ipv6:      ip6,
		icmp4:     icmp4,
		icmp6:     icmp6,
		tcp:       tcp,
		udp:       udp,
		parser:    parser,
		decoded:   decoded,
		slOpt:     slOpt,
		slBuf:     slBuf,
	}
	tc.macCache.New = func() interface{} {
		return new(mac)
	}
	tc.ipv4Cache.New = func() interface{} {
		return new(ipv4)
	}
	tc.ipv6Cache.New = func() interface{} {
		return new(ipv6)
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
		if size > maxPacketSize {
			const format = "(%s) receive too large packet: 0x%X"
			tc.ctx.logger.Warningf(format, tc.conn.RemoteAddr(), buf[:frameHeaderSize])
			return
		}
		// read frame packet
		_, err = io.ReadFull(tc.conn, buf[:size])
		if err != nil {
			return
		}
		if tc.enableNAT {
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
	tc.isNewSourceMAC()
	dstMACPtr := tc.macCache.Get().(*mac)
	defer tc.macCache.Put(dstMACPtr)
	dstMAC := *dstMACPtr
	copy(dstMAC[:], tc.eth.DstMAC)
	if dstMAC == broadcast {
		// TODO check handle is closed
		if tc.ctx.isClosed() {
			return
		}
		_ = tc.handle.WritePacketData(buf)

		b := make([]byte, 2+len(buf))
		binary.BigEndian.PutUint16(b, uint16(len(buf)))
		copy(b[2:], buf)

		tc.ctx.broadcastExcept(b, tc.token)
		return
	}
	// check it is sent to one client
	pool := tc.ctx.getConnPoolByMAC(dstMAC)
	if pool != nil {

		b := make([]byte, 2+len(buf))
		binary.BigEndian.PutUint16(b, uint16(len(buf)))
		copy(b[2:], buf)

		_, _ = pool.Write(b)
		return
	}
	// send to the under interface
	// TODO add lock for close handle
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
			tc.isNewSourceMAC()
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

func (tc *transConn) isNewSourceMAC() {
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
	srcMAC := mac{}
	copy(srcMAC[:], tc.eth.SrcMAC)
	if srcMAC == broadcast {
		return
	}
	tc.srcMAC = append(tc.srcMAC, srcMAC[:])
	tc.ctx.bindMAC(tc.token, srcMAC)
}
