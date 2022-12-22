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
	nat    *nat
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
		nat:       srv.nat,
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
	buf := make([]byte, maxFrameSize)
	for {
		// read frame size
		_, err = io.ReadFull(tc.conn, buf[:frameHeaderSize])
		if err != nil {
			return
		}
		size = binary.BigEndian.Uint16(buf[:frameHeaderSize])
		if size > maxFrameSize {
			const format = "(%s) receive too large frame: 0x%X"
			tc.ctx.logger.Warningf(format, tc.conn.RemoteAddr(), buf[:frameHeaderSize])
			return
		}
		// read frame data
		_, err = io.ReadFull(tc.conn, buf[frameHeaderSize:frameHeaderSize+size])
		if err != nil {
			return
		}
		if tc.enableNAT {
			tc.decodeWithNAT(buf[:frameHeaderSize+size])
		} else {
			tc.decodeWithoutNAT(buf[:frameHeaderSize+size])
		}
	}
}

func (tc *transConn) decodeWithoutNAT(buf []byte) {
	frameData := buf[frameHeaderSize:]
	err := tc.parser.DecodeLayers(frameData, tc.decoded)
	if err != nil {
		return
	}
	decoded := *tc.decoded
	if len(decoded) < 1 || decoded[0] != layers.LayerTypeEthernet {
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
		_ = tc.handle.WritePacketData(frameData)

		tc.ctx.broadcastExcept(buf, tc.token)
		return
	}
	// send to the target client
	pool := tc.ctx.getConnPoolByMAC(dstMAC)
	if pool != nil {

		_, _ = pool.Write(buf)
		return
	}
	// send to the under interface
	// TODO add lock for close handle
	_ = tc.handle.WritePacketData(frameData)
}

func (tc *transConn) decodeWithNAT(buf []byte) {
	frameData := buf[frameHeaderSize:]
	err := tc.parser.DecodeLayers(frameData, tc.decoded)
	if err != nil {
		return
	}
	decoded := *tc.decoded
	var (
		isIPv4 bool
		isIPv6 bool
	)
	for i := 0; i < len(decoded); i++ {
		switch decoded[i] {
		case layers.LayerTypeEthernet:
			tc.isNewSourceMAC()
			// TODO client to client
		case layers.LayerTypeARP:
			tc.decodeARP()
			return
		case layers.LayerTypeIPv4:
			tc.isNewSourceIPv4()
			isIPv4 = true
		case layers.LayerTypeIPv6:
			tc.isNewSourceIPv6()
			isIPv6 = true
		case layers.LayerTypeICMPv4:

		case layers.LayerTypeICMPv6:

		case layers.LayerTypeTCP:
			switch {
			case isIPv4:
				tc.decodeIPv4TCP()
			case isIPv6:
				tc.decodeIPv6TCP()
			}
			return
		case layers.LayerTypeUDP:
			switch {
			case isIPv4:
				tc.decodeIPv4UDP()
			case isIPv6:
				tc.decodeIPv6UDP()
			}
			return
		}
	}
}

func (tc *transConn) decodeARP() {
	op := tc.arp.Operation
	switch op {
	case layers.ARPRequest:
		if tc.nat.gatewayIPv4.Equal(tc.arp.DstProtAddress) {
			tc.eth.SrcMAC, tc.eth.DstMAC = tc.nat.gatewayMAC, tc.eth.SrcMAC
			tc.arp.Operation = layers.ARPReply
			tc.arp.DstHwAddress = tc.arp.SourceHwAddress
			tc.arp.DstProtAddress = tc.arp.SourceProtAddress
			tc.arp.SourceHwAddress = tc.nat.gatewayMAC
			tc.arp.SourceProtAddress = tc.nat.gatewayIPv4

			err := gopacket.SerializeLayers(tc.slBuf, tc.slOpt, tc.eth, tc.arp)
			if err != nil {
				const format = "(%s) failed to serialize arp layers: %s"
				tc.ctx.logger.Warningf(format, tc.conn.RemoteAddr(), err)
				return
			}

			sb := tc.slBuf.Bytes()

			// TODO improve performance
			b := make([]byte, frameHeaderSize+len(sb))
			binary.BigEndian.PutUint16(b, uint16(len(sb)))
			copy(b[frameHeaderSize:], sb)

			_, _ = tc.conn.Write(b)

		} else {
			// TODO client side

			// then server side
			return
		}
	case layers.ARPReply:

	default:
		const format = "(%s) invalid arp operation: 0x%X"
		tc.ctx.logger.Warningf(format, tc.conn.RemoteAddr(), op)
	}
}

func (tc *transConn) decodeIPv4TCP() {
	// TODO check is local client
	lIP := tc.ipv4.SrcIP
	lPort := uint16(tc.tcp.SrcPort)
	rIP := tc.ipv4.DstIP
	rPort := uint16(tc.tcp.DstPort)
	natPort := tc.nat.AddIPv4TCPPortMap(lIP, lPort, rIP, rPort)

	tc.eth.SrcMAC = tc.nat.localMAC
	tc.ipv4.SrcIP = tc.nat.localIPv4
	tc.tcp.SrcPort = layers.TCPPort(natPort)

	_ = tc.tcp.SetNetworkLayerForChecksum(tc.ipv4)

	payload := gopacket.Payload(tc.tcp.Payload)

	err := gopacket.SerializeLayers(tc.slBuf, tc.slOpt, tc.eth, tc.ipv4, tc.tcp, payload)
	if err != nil {
		const format = "(%s) failed to serialize ipv4 tcp layers: %s"
		tc.ctx.logger.Warningf(format, tc.conn.RemoteAddr(), err)
		return
	}

	sb := tc.slBuf.Bytes()

	_ = tc.handle.WritePacketData(sb)
}

func (tc *transConn) decodeIPv4UDP() {
	// TODO check is local client
	lIP := tc.ipv4.SrcIP
	lPort := uint16(tc.udp.SrcPort)
	rIP := tc.ipv4.DstIP
	rPort := uint16(tc.udp.DstPort)
	natPort := tc.nat.AddIPv4UDPPortMap(lIP, lPort, rIP, rPort)

	tc.eth.SrcMAC = tc.nat.localMAC
	tc.ipv4.SrcIP = tc.nat.localIPv4
	tc.udp.SrcPort = layers.UDPPort(natPort)

	_ = tc.udp.SetNetworkLayerForChecksum(tc.ipv4)

	// payload := make(gopacket.Payload, len(tc.udp.Payload))
	// copy(payload, tc.udp.Payload)

	payload := gopacket.Payload(tc.udp.Payload)

	err := gopacket.SerializeLayers(tc.slBuf, tc.slOpt, tc.eth, tc.ipv4, tc.udp, payload)
	if err != nil {
		const format = "(%s) failed to serialize ipv4 udp layers: %s"
		tc.ctx.logger.Warningf(format, tc.conn.RemoteAddr(), err)
		return
	}

	sb := tc.slBuf.Bytes()

	_ = tc.handle.WritePacketData(sb)
}

func (tc *transConn) decodeIPv6TCP() {

}

func (tc *transConn) decodeIPv6UDP() {

}

func (tc *transConn) isNewSourceMAC() {
	if bytes.Equal(tc.eth.SrcMAC, broadcast[:]) {
		return
	}
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
	tc.srcMAC = append(tc.srcMAC, srcMAC[:])
	tc.ctx.bindMAC(tc.token, srcMAC)
}

func (tc *transConn) isNewSourceIPv4() {
	if !tc.ipv4.SrcIP.IsGlobalUnicast() {
		return
	}
	var exist bool
	for i := 0; i < len(tc.srcIPv4); i++ {
		if tc.srcIPv4[i].Equal(tc.ipv4.SrcIP) {
			exist = true
			break
		}
	}
	if exist {
		return
	}
	// must copy, because DecodeLayers use reference
	srcIP := ipv4{}
	copy(srcIP[:], tc.ipv4.SrcIP)
	tc.srcIPv4 = append(tc.srcIPv4, srcIP[:])
	if !tc.ctx.bindIPv4(tc.token, srcIP) {
		return
	}
	srcMAC := mac{}
	copy(srcMAC[:], tc.eth.SrcMAC)
	tc.srcMAC = append(tc.srcMAC, srcMAC[:])
	tc.ctx.bindIPv4ToMAC(srcIP, srcMAC)
}

func (tc *transConn) isNewSourceIPv6() {
	if !tc.ipv6.SrcIP.IsGlobalUnicast() {
		return
	}
	var exist bool
	for i := 0; i < len(tc.srcIPv6); i++ {
		if tc.srcIPv6[i].Equal(tc.ipv6.SrcIP) {
			exist = true
			break
		}
	}
	if exist {
		return
	}
	// must copy, because DecodeLayers use reference
	srcIP := ipv6{}
	copy(srcIP[:], tc.ipv6.SrcIP)
	tc.srcIPv6 = append(tc.srcIPv6, srcIP[:])
	if !tc.ctx.bindIPv6(tc.token, srcIP) {
		return
	}
	srcMAC := mac{}
	copy(srcMAC[:], tc.eth.SrcMAC)
	tc.srcMAC = append(tc.srcMAC, srcMAC[:])
	tc.ctx.bindIPv6ToMAC(srcIP, srcMAC)
}
