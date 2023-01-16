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

	eth    *layers.Ethernet
	arp    *layers.ARP
	ipv4   *layers.IPv4
	ipv6   *layers.IPv6
	icmpv4 *layers.ICMPv4
	icmpv6 *layers.ICMPv6
	tcp    *layers.TCP
	udp    *layers.UDP

	parser  *gopacket.DecodingLayerParser
	decoded *[]gopacket.LayerType
	slOpt   gopacket.SerializeOptions
	slBuf   gopacket.SerializeBuffer
	payload gopacket.Payload

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
	eth := new(layers.Ethernet)
	arp := new(layers.ARP)
	ip4 := new(layers.IPv4)
	ip6 := new(layers.IPv6)
	icmpv4 := new(layers.ICMPv4)
	icmpv6 := new(layers.ICMPv6)
	tcp := new(layers.TCP)
	udp := new(layers.UDP)
	var parser *gopacket.DecodingLayerParser
	if srv.enableNAT {
		parser = gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			eth, arp,
			ip4, icmpv4,
			ip6, icmpv6,
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
	tc := transporter{
		ctx:       srv,
		enableNAT: srv.enableNAT,
		handle:    srv.handle,
		nat:       srv.nat,
		conn:      conn,
		token:     token,
		eth:       eth,
		arp:       arp,
		ipv4:      ip4,
		ipv6:      ip6,
		icmpv4:    icmpv4,
		icmpv6:    icmpv6,
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
	tr.bindMAC()
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
		pool.Push(frame.Bytes())
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
			tr.bindIPv4()
			tr.isIPv4 = true
		case layers.LayerTypeIPv6:
			tr.bindIPv6()
			tr.isIPv6 = true
		case layers.LayerTypeICMPv4:
			tr.decodeICMPv4()
			return
		case layers.LayerTypeICMPv6:
			tr.decodeICMPv6()
			return
		case layers.LayerTypeTCP:
			tr.decodeTCP()
			return
		case layers.LayerTypeUDP:
			tr.decodeUDP()
			return
		}
	}
}

// TODO think ICMPv6 like arp.
func (tr *transporter) decodeEthernet(frame *frame) bool {
	tr.bindMAC()
	// special case
	if tr.eth.EthernetType == layers.EthernetTypeARP {
		if tr.decodeARPRequest(frame) {
			return false
		}
	}
	// send to the gateway
	if bytes.Equal(tr.eth.DstMAC, tr.nat.gatewayMAC) {
		return true
	}
	// IPv6 special case about ICMPv6
	if bytes.Equal(tr.eth.DstMAC[:2], []byte{0x33, 0x33}) {
		return true
	}
	dstMACPtr := tr.macCache.Get().(*mac)
	defer tr.macCache.Put(dstMACPtr)
	dstMAC := *dstMACPtr
	copy(dstMAC[:], tr.eth.DstMAC)
	if dstMAC == broadcast {
		tr.ctx.broadcastExcept(frame.Bytes(), tr.token)
		return false
	}
	// ignore multicast
	if tr.eth.SrcMAC[0]&1 == 1 {
		return false
	}
	// send to the target client
	pool := tr.ctx.getConnPoolByMAC(dstMAC)
	if pool != nil {
		pool.Push(frame.Bytes())
	}
	return false
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
		// send to client self
		_ = tr.conn.SetWriteDeadline(time.Now().Add(tr.ctx.timeout))
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

func (tr *transporter) decodeICMPv4() {
	if tr.icmpv4.TypeCode.Type() != layers.ICMPv4TypeEchoRequest {
		return
	}
	if tr.icmpv4.TypeCode.Code() != 0 {
		return
	}
	// add id map to nat
	lIP := tr.ipv4.SrcIP
	lID := tr.icmpv4.Id
	rIP := tr.ipv4.DstIP
	natID := tr.nat.AddICMPv4IDMap(lIP, lID, rIP)
	if natID == 0 {
		tr.ctx.logger.Warning("icmpv4 id map is full")
		return
	}
	// replace MAC, IP addresses and icmp id
	tr.eth.SrcMAC = tr.nat.localMAC
	tr.ipv4.SrcIP = tr.nat.localIPv4
	tr.icmpv4.Id = natID
	tr.payload = tr.icmpv4.Payload
	// encode data to buffer
	err := gopacket.SerializeLayers(tr.slBuf, tr.slOpt, tr.eth, tr.ipv4, tr.icmpv4, tr.payload)
	if err != nil {
		const format = "(%s) failed to serialize icmpv4 echo request frame: %s"
		tr.ctx.logger.Warningf(format, tr.conn.RemoteAddr(), err)
		return
	}
	data := tr.slBuf.Bytes()
	_ = tr.handle.WritePacketData(data)
}

func (tr *transporter) decodeICMPv6() {
	switch tr.icmpv6.TypeCode.Type() {
	case layers.ICMPv6TypeEchoRequest:
		tr.decodeICMPv6EchoRequest()
	case layers.ICMPv6TypeNeighborSolicitation:
		tr.decodeICMPv6NeighborSolicitation()
	case layers.ICMPv6TypeNeighborAdvertisement:
		tr.decodeICMPv6NeighborAdvertisement()
	}
}

func (tr *transporter) decodeICMPv6EchoRequest() {
	if tr.icmpv6.TypeCode.Code() != 0 {
		return
	}
	echo := new(layers.ICMPv6Echo)
	err := echo.DecodeFromBytes(tr.icmpv6.Payload, gopacket.NilDecodeFeedback)
	if err != nil {
		const format = "(%s) failed to decode icmpv6 echo request frame: %s"
		tr.ctx.logger.Warningf(format, tr.conn.RemoteAddr(), err)
		return
	}
	// add id map to nat
	lIP := tr.ipv6.SrcIP
	lID := echo.Identifier
	rIP := tr.ipv6.DstIP
	natID := tr.nat.AddICMPv6IDMap(lIP, lID, rIP)
	if natID == 0 {
		tr.ctx.logger.Warning("icmpv6 id map is full")
		return
	}
	// replace MAC, IP addresses and icmp id
	tr.eth.SrcMAC = tr.nat.localMAC
	tr.ipv6.SrcIP = tr.nat.localIPv6
	_ = tr.icmpv6.SetNetworkLayerForChecksum(tr.ipv6)
	echo.Identifier = natID
	tr.payload = tr.icmpv6.Payload[4:] // size of ICMPv6Echo
	// encode data to buffer
	err = gopacket.SerializeLayers(tr.slBuf, tr.slOpt, tr.eth, tr.ipv6, tr.icmpv6, echo, tr.payload)
	if err != nil {
		const format = "(%s) failed to serialize icmpv6 echo request frame: %s"
		tr.ctx.logger.Warningf(format, tr.conn.RemoteAddr(), err)
		return
	}
	data := tr.slBuf.Bytes()
	_ = tr.handle.WritePacketData(data)
}

func (tr *transporter) decodeICMPv6NeighborSolicitation() {
	if tr.icmpv6.TypeCode.Code() != 0 {
		return
	}
	ns := new(layers.ICMPv6NeighborSolicitation)
	err := ns.DecodeFromBytes(tr.icmpv6.Payload, gopacket.NilDecodeFeedback)
	if err != nil {
		const format = "(%s) failed to decode icmpv6 neighbor solicitation frame: %s"
		tr.ctx.logger.Warningf(format, tr.conn.RemoteAddr(), err)
		return
	}
	if !tr.nat.gatewayIPv6.Equal(ns.TargetAddress) {
		// TODO common case
		return
	}
	na := new(layers.ICMPv6NeighborAdvertisement)
	na.Flags = 0xE0
	na.TargetAddress = tr.nat.gatewayIPv6
	opt := layers.ICMPv6Option{
		Type: layers.ICMPv6OptTargetAddress,
		Data: tr.nat.gatewayMAC,
	}
	na.Options = append(na.Options, opt)
	// replace MAC and IP addresses
	tr.eth.SrcMAC, tr.eth.DstMAC = tr.nat.gatewayMAC, tr.eth.SrcMAC
	tr.ipv6.SrcIP, tr.ipv6.DstIP = tr.nat.gatewayIPv6, tr.ipv6.SrcIP
	tr.icmpv6.TypeCode = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0)
	_ = tr.icmpv6.SetNetworkLayerForChecksum(tr.ipv6)
	// encode data to buffer
	err = gopacket.SerializeLayers(tr.slBuf, tr.slOpt, tr.eth, tr.ipv6, tr.icmpv6, na)
	if err != nil {
		const format = "(%s) failed to serialize icmpv6 echo request frame: %s"
		tr.ctx.logger.Warningf(format, tr.conn.RemoteAddr(), err)
		return
	}
	fr := tr.slBuf.Bytes()
	// TODO think reuse frame
	f := newFrame()
	f.WriteHeader(len(fr))
	f.WriteData(fr)
	// send to client self
	_ = tr.conn.SetWriteDeadline(time.Now().Add(tr.ctx.timeout))
	_, _ = tr.conn.Write(f.Bytes())
}

func (tr *transporter) decodeICMPv6NeighborAdvertisement() {
	if tr.icmpv6.TypeCode.Code() != 0 {
		return
	}
}

func (tr *transporter) decodeTCP() {
	switch {
	case tr.isIPv4:
		tr.decodeIPv4TCP()
	case tr.isIPv6:
		tr.decodeIPv6TCP()
	}
}

func (tr *transporter) decodeIPv4TCP() {
	// add port map to nat
	lIP := tr.ipv4.SrcIP
	lPort := uint16(tr.tcp.SrcPort)
	rIP := tr.ipv4.DstIP
	rPort := uint16(tr.tcp.DstPort)
	natPort := tr.nat.AddIPv4TCPPortMap(lIP, lPort, rIP, rPort)
	if natPort == 0 {
		tr.ctx.logger.Warning("ipv4 tcp port map is full")
		return
	}
	// replace MAC, IP addresses and port
	tr.eth.SrcMAC = tr.nat.localMAC
	tr.ipv4.SrcIP = tr.nat.localIPv4
	tr.tcp.SrcPort = layers.TCPPort(natPort)
	_ = tr.tcp.SetNetworkLayerForChecksum(tr.ipv4)
	tr.payload = tr.tcp.Payload
	// encode data to buffer
	err := gopacket.SerializeLayers(tr.slBuf, tr.slOpt, tr.eth, tr.ipv4, tr.tcp, tr.payload)
	if err != nil {
		const format = "(%s) failed to serialize ipv4 tcp frame: %s"
		tr.ctx.logger.Warningf(format, tr.conn.RemoteAddr(), err)
		return
	}
	data := tr.slBuf.Bytes()
	_ = tr.handle.WritePacketData(data)
}

func (tr *transporter) decodeIPv6TCP() {
	// add port map to nat
	lIP := tr.ipv6.SrcIP
	lPort := uint16(tr.tcp.SrcPort)
	rIP := tr.ipv6.DstIP
	rPort := uint16(tr.tcp.DstPort)
	natPort := tr.nat.AddIPv6TCPPortMap(lIP, lPort, rIP, rPort)
	if natPort == 0 {
		tr.ctx.logger.Warning("ipv6 tcp port map is full")
		return
	}
	// replace MAC, IP addresses and port
	tr.eth.SrcMAC = tr.nat.localMAC
	tr.ipv6.SrcIP = tr.nat.localIPv6
	tr.tcp.SrcPort = layers.TCPPort(natPort)
	_ = tr.tcp.SetNetworkLayerForChecksum(tr.ipv6)
	tr.payload = tr.tcp.Payload
	// encode data to buffer
	err := gopacket.SerializeLayers(tr.slBuf, tr.slOpt, tr.eth, tr.ipv6, tr.tcp, tr.payload)
	if err != nil {
		const format = "(%s) failed to serialize ipv6 tcp frame: %s"
		tr.ctx.logger.Warningf(format, tr.conn.RemoteAddr(), err)
		return
	}
	data := tr.slBuf.Bytes()
	_ = tr.handle.WritePacketData(data)
}

func (tr *transporter) decodeUDP() {
	switch {
	case tr.isIPv4:
		tr.decodeIPv4UDP()
	case tr.isIPv6:
		tr.decodeIPv6UDP()
	}
}

func (tr *transporter) decodeIPv4UDP() {
	// add port map to nat
	lIP := tr.ipv4.SrcIP
	lPort := uint16(tr.udp.SrcPort)
	rIP := tr.ipv4.DstIP
	rPort := uint16(tr.udp.DstPort)
	natPort := tr.nat.AddIPv4UDPPortMap(lIP, lPort, rIP, rPort)
	if natPort == 0 {
		tr.ctx.logger.Warning("ipv4 udp port map is full")
		return
	}
	// replace MAC, IP addresses and port
	tr.eth.SrcMAC = tr.nat.localMAC
	tr.ipv4.SrcIP = tr.nat.localIPv4
	tr.udp.SrcPort = layers.UDPPort(natPort)
	_ = tr.udp.SetNetworkLayerForChecksum(tr.ipv4)
	tr.payload = tr.udp.Payload
	// encode data to buffer
	err := gopacket.SerializeLayers(tr.slBuf, tr.slOpt, tr.eth, tr.ipv4, tr.udp, tr.payload)
	if err != nil {
		const format = "(%s) failed to serialize ipv4 udp frame: %s"
		tr.ctx.logger.Warningf(format, tr.conn.RemoteAddr(), err)
		return
	}
	data := tr.slBuf.Bytes()
	_ = tr.handle.WritePacketData(data)
}

func (tr *transporter) decodeIPv6UDP() {
	// add port map to nat
	lIP := tr.ipv6.SrcIP
	lPort := uint16(tr.udp.SrcPort)
	rIP := tr.ipv6.DstIP
	rPort := uint16(tr.udp.DstPort)
	natPort := tr.nat.AddIPv6UDPPortMap(lIP, lPort, rIP, rPort)
	if natPort == 0 {
		tr.ctx.logger.Warning("ipv6 udp port map is full")
		return
	}
	// replace MAC, IP addresses and port
	tr.eth.SrcMAC = tr.nat.localMAC
	tr.ipv6.SrcIP = tr.nat.localIPv6
	tr.udp.SrcPort = layers.UDPPort(natPort)
	_ = tr.udp.SetNetworkLayerForChecksum(tr.ipv6)
	tr.payload = tr.udp.Payload
	// encode data to buffer
	err := gopacket.SerializeLayers(tr.slBuf, tr.slOpt, tr.eth, tr.ipv6, tr.udp, tr.payload)
	if err != nil {
		const format = "(%s) failed to serialize ipv6 udp frame: %s"
		tr.ctx.logger.Warningf(format, tr.conn.RemoteAddr(), err)
		return
	}
	data := tr.slBuf.Bytes()
	_ = tr.handle.WritePacketData(data)
}

func (tr *transporter) bindMAC() {
	if tr.eth.SrcMAC[0]&1 == 1 { // not unicast
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
	if !tr.ctx.bindMAC(tr.token, srcMAC) {
		// TODO add warning
	}
}

func (tr *transporter) bindIPv4() {
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
		// TODO add warning
		return
	}
	srcMAC := mac{}
	copy(srcMAC[:], tr.eth.SrcMAC)
	tr.srcMAC = append(tr.srcMAC, srcMAC[:])
	tr.ctx.bindIPv4ToMAC(srcIP, srcMAC)
}

func (tr *transporter) bindIPv6() {
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
		// TODO add warning
		return
	}
	srcMAC := mac{}
	copy(srcMAC[:], tr.eth.SrcMAC)
	tr.srcMAC = append(tr.srcMAC, srcMAC[:])
	tr.ctx.bindIPv6ToMAC(srcIP, srcMAC)
}
