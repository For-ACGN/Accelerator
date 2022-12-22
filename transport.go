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

// transporter is used to read frame from client side and
// process it, then write it to the destination network
// interface or the other client connection.
type transporter struct {
	ctx *Server

	enableNAT bool

	handle *pcap.Handle
	nat    *nat
	conn   net.Conn
	token  sessionToken

	eth     *layers.Ethernet
	arp     *layers.ARP
	ipv4    *layers.IPv4
	ipv6    *layers.IPv6
	icmp4   *layers.ICMPv4
	icmp6   *layers.ICMPv6
	tcp     *layers.TCP
	udp     *layers.UDP
	payload *gopacket.Payload

	parser  *gopacket.DecodingLayerParser
	decoded *[]gopacket.LayerType
	slOpt   gopacket.SerializeOptions
	slBuf   gopacket.SerializeBuffer

	isIPv4 bool
	isIPv6 bool

	macCache  sync.Pool
	ipv4Cache sync.Pool
	ipv6Cache sync.Pool

	// check has new
	srcMAC  []net.HardwareAddr
	srcIPv4 []net.IP
	srcIPv6 []net.IP
}

func (srv *Server) newTransporter(conn net.Conn, token sessionToken) *transporter {
	enableNAT := srv.enableNAT
	eth := new(layers.Ethernet)
	arp := new(layers.ARP)
	ip4 := new(layers.IPv4)
	ip6 := new(layers.IPv6)
	icmp4 := new(layers.ICMPv4)
	icmp6 := new(layers.ICMPv6)
	tcp := new(layers.TCP)
	udp := new(layers.UDP)
	payload := new(gopacket.Payload)
	var parser *gopacket.DecodingLayerParser
	if enableNAT {
		parser = gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			eth, arp,
			ip4, icmp4,
			ip6, icmp6,
			tcp, udp,
			payload,
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
	tc := transporter{
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
		payload:   payload,
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

func (tr *transporter) transport() {
	_ = tr.conn.SetDeadline(time.Time{})
	var (
		size uint16
		err  error
	)
	buf := make([]byte, maxFrameSize)
	fr := newFrame()
	for {
		// read frame size
		_, err = io.ReadFull(tr.conn, buf[:frameHeaderSize])
		if err != nil {
			return
		}
		size = binary.BigEndian.Uint16(buf[:frameHeaderSize])
		if size > maxFrameSize {
			const format = "(%s) receive too large frame: 0x%X"
			tr.ctx.logger.Warningf(format, tr.conn.RemoteAddr(), buf[:frameHeaderSize])
			return
		}
		// read frame data
		_, err = io.ReadFull(tr.conn, buf[:size])
		if err != nil {
			return
		}
		fr.Reset()
		fr.WriteHeader(int(size))
		fr.WriteData(buf[:size])
		if tr.enableNAT {
			tr.decodeWithNAT(fr)
		} else {
			tr.decodeWithoutNAT(fr)
		}
	}
}

func (tr *transporter) decodeWithoutNAT(frame *frame) {
	err := tr.parser.DecodeLayers(frame.Data(), tr.decoded)
	if err != nil {
		return
	}
	decoded := *tr.decoded
	if len(decoded) < 1 || decoded[0] != layers.LayerTypeEthernet {
		return
	}
	tr.isNewSourceMAC()
	dstMACPtr := tr.macCache.Get().(*mac)
	defer tr.macCache.Put(dstMACPtr)
	dstMAC := *dstMACPtr
	copy(dstMAC[:], tr.eth.DstMAC)
	if dstMAC == broadcast {
		_ = tr.handle.WritePacketData(frame.Data())
		tr.ctx.broadcastExcept(frame.Bytes(), tr.token)
		return
	}
	// send to the target client
	pool := tr.ctx.getConnPoolByMAC(dstMAC)
	if pool != nil {
		_, _ = pool.Write(frame.Bytes())
		return
	}
	// send to the under interface
	_ = tr.handle.WritePacketData(frame.Data())
}

func (tr *transporter) decodeWithNAT(frame *frame) {
	err := tr.parser.DecodeLayers(frame.Data(), tr.decoded)
	if err != nil {
		return
	}
	tr.isIPv4 = false
	tr.isIPv6 = false
	decoded := *tr.decoded
	for i := 0; i < len(decoded); i++ {
		switch decoded[i] {
		case layers.LayerTypeEthernet:
			if !tr.decodeEthernet(frame) {
				return
			}
		case layers.LayerTypeIPv4:
			tr.isNewSourceIPv4()
			tr.isIPv4 = true
		case layers.LayerTypeIPv6:
			tr.isNewSourceIPv6()
			tr.isIPv6 = true
		case layers.LayerTypeICMPv4:
			// TODO ICMP
			return
		case layers.LayerTypeICMPv6:
			// TODO ICMP
			return
		case layers.LayerTypeTCP:
			tr.decodeTCP(frame)
			return
		case layers.LayerTypeUDP:
			tr.decodeUDP(frame)
			return
		}
	}
}

// TODO think ICMPv6 like arp.
func (tr *transporter) decodeEthernet(frame *frame) bool {
	tr.isNewSourceMAC()
	if tr.eth.EthernetType == layers.EthernetTypeARP {
		if tr.decodeARPRequest(frame) {
			return false
		}
	}
	dstMACPtr := tr.macCache.Get().(*mac)
	defer tr.macCache.Put(dstMACPtr)
	dstMAC := *dstMACPtr
	copy(dstMAC[:], tr.eth.DstMAC)
	if dstMAC == broadcast {
		tr.ctx.broadcastExcept(frame.Bytes(), tr.token)
		return false
	}
	// send to the target client
	pool := tr.ctx.getConnPoolByMAC(dstMAC)
	if pool != nil {
		_, _ = pool.Write(frame.Bytes())
		return false
	}
	// send to the gateway
	return true
}

func (tr *transporter) decodeARPRequest(frame *frame) bool {
	op := tr.arp.Operation
	switch op {
	case layers.ARPRequest:
		if !tr.nat.gatewayIPv4.Equal(tr.arp.DstProtAddress) {
			return false
		}
		// replace MAC and IP addresses
		tr.eth.SrcMAC, tr.eth.DstMAC = tr.nat.gatewayMAC, tr.eth.SrcMAC
		tr.arp.Operation = layers.ARPReply
		tr.arp.DstHwAddress = tr.arp.SourceHwAddress
		tr.arp.DstProtAddress = tr.arp.SourceProtAddress
		tr.arp.SourceHwAddress = tr.nat.gatewayMAC
		tr.arp.SourceProtAddress = tr.nat.gatewayIPv4
		// encode data to buffer
		err := gopacket.SerializeLayers(tr.slBuf, tr.slOpt, tr.eth, tr.arp)
		if err != nil {
			const format = "(%s) failed to serialize arp frame: %s"
			tr.ctx.logger.Warningf(format, tr.conn.RemoteAddr(), err)
			return true
		}
		fr := tr.slBuf.Bytes()
		frame.Reset()
		frame.WriteHeader(len(fr))
		frame.WriteData(fr)
		// send to self
		_, _ = tr.conn.Write(frame.Bytes())
		return true
	case layers.ARPReply:
		return false
	default:
		const format = "(%s) invalid arp operation: 0x%X"
		tr.ctx.logger.Warningf(format, tr.conn.RemoteAddr(), op)
		return true
	}
}

func (tr *transporter) decodeTCP(frame *frame) {
	switch {
	case tr.isIPv4:
		tr.decodeIPv4TCP(frame)
	case tr.isIPv6:
		tr.decodeIPv6TCP(frame)
	}
}

func (tr *transporter) decodeUDP(frame *frame) {
	switch {
	case tr.isIPv4:
		tr.decodeIPv4UDP(frame)
	case tr.isIPv6:
		tr.decodeIPv6UDP(frame)
	}
}

func (tr *transporter) decodeIPv4TCP(frame *frame) {
	// TODO check is local client
	lIP := tr.ipv4.SrcIP
	lPort := uint16(tr.tcp.SrcPort)
	rIP := tr.ipv4.DstIP
	rPort := uint16(tr.tcp.DstPort)
	natPort := tr.nat.AddIPv4TCPPortMap(lIP, lPort, rIP, rPort)

	tr.eth.SrcMAC = tr.nat.localMAC
	tr.ipv4.SrcIP = tr.nat.localIPv4
	tr.tcp.SrcPort = layers.TCPPort(natPort)

	_ = tr.tcp.SetNetworkLayerForChecksum(tr.ipv4)

	payload := gopacket.Payload(tr.tcp.Payload)

	err := gopacket.SerializeLayers(tr.slBuf, tr.slOpt, tr.eth, tr.ipv4, tr.tcp, payload)
	if err != nil {
		const format = "(%s) failed to serialize ipv4 tcp frame: %s"
		tr.ctx.logger.Warningf(format, tr.conn.RemoteAddr(), err)
		return
	}

	sb := tr.slBuf.Bytes()

	_ = tr.handle.WritePacketData(sb)
}

func (tr *transporter) decodeIPv4UDP(frame *frame) {
	// TODO check is local client
	lIP := tr.ipv4.SrcIP
	lPort := uint16(tr.udp.SrcPort)
	rIP := tr.ipv4.DstIP
	rPort := uint16(tr.udp.DstPort)
	natPort := tr.nat.AddIPv4UDPPortMap(lIP, lPort, rIP, rPort)

	tr.eth.SrcMAC = tr.nat.localMAC
	tr.ipv4.SrcIP = tr.nat.localIPv4
	tr.udp.SrcPort = layers.UDPPort(natPort)

	_ = tr.udp.SetNetworkLayerForChecksum(tr.ipv4)

	// payload := make(gopacket.Payload, len(tc.udp.Payload))
	// copy(payload, tc.udp.Payload)

	payload := gopacket.Payload(tr.udp.Payload)

	err := gopacket.SerializeLayers(tr.slBuf, tr.slOpt, tr.eth, tr.ipv4, tr.udp, payload)
	if err != nil {
		const format = "(%s) failed to serialize ipv4 udp frame: %s"
		tr.ctx.logger.Warningf(format, tr.conn.RemoteAddr(), err)
		return
	}

	sb := tr.slBuf.Bytes()

	_ = tr.handle.WritePacketData(sb)
}

func (tr *transporter) decodeIPv6TCP(frame *frame) {

}

func (tr *transporter) decodeIPv6UDP(frame *frame) {

}

func (tr *transporter) isNewSourceMAC() {
	if bytes.Equal(tr.eth.SrcMAC, broadcast[:]) {
		return
	}
	var exist bool
	for i := 0; i < len(tr.srcMAC); i++ {
		if bytes.Equal(tr.srcMAC[i], tr.eth.SrcMAC) {
			exist = true
			break
		}
	}
	if exist {
		return
	}
	// must copy, because DecodeLayers use reference
	srcMAC := mac{}
	copy(srcMAC[:], tr.eth.SrcMAC)
	tr.srcMAC = append(tr.srcMAC, srcMAC[:])
	tr.ctx.bindMAC(tr.token, srcMAC)
}

func (tr *transporter) isNewSourceIPv4() {
	if !tr.ipv4.SrcIP.IsGlobalUnicast() {
		return
	}
	var exist bool
	for i := 0; i < len(tr.srcIPv4); i++ {
		if tr.srcIPv4[i].Equal(tr.ipv4.SrcIP) {
			exist = true
			break
		}
	}
	if exist {
		return
	}
	// must copy, because DecodeLayers use reference
	srcIP := ipv4{}
	copy(srcIP[:], tr.ipv4.SrcIP)
	tr.srcIPv4 = append(tr.srcIPv4, srcIP[:])
	if !tr.ctx.bindIPv4(tr.token, srcIP) {
		return
	}
	srcMAC := mac{}
	copy(srcMAC[:], tr.eth.SrcMAC)
	tr.srcMAC = append(tr.srcMAC, srcMAC[:])
	tr.ctx.bindIPv4ToMAC(srcIP, srcMAC)
}

func (tr *transporter) isNewSourceIPv6() {
	if !tr.ipv6.SrcIP.IsGlobalUnicast() {
		return
	}
	var exist bool
	for i := 0; i < len(tr.srcIPv6); i++ {
		if tr.srcIPv6[i].Equal(tr.ipv6.SrcIP) {
			exist = true
			break
		}
	}
	if exist {
		return
	}
	// must copy, because DecodeLayers use reference
	srcIP := ipv6{}
	copy(srcIP[:], tr.ipv6.SrcIP)
	tr.srcIPv6 = append(tr.srcIPv6, srcIP[:])
	if !tr.ctx.bindIPv6(tr.token, srcIP) {
		return
	}
	srcMAC := mac{}
	copy(srcMAC[:], tr.eth.SrcMAC)
	tr.srcMAC = append(tr.srcMAC, srcMAC[:])
	tr.ctx.bindIPv6ToMAC(srcIP, srcMAC)
}
