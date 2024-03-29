package accelerator

import (
	"bytes"
	"encoding/binary"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// frameSender is used to parse frame from destination network
// interface, if the source MAC address or IP address is matched
// in clients map, it will be sent to the connection about client.
type frameSender struct {
	ctx *Server

	enableNAT bool

	handle     *pcap.Handle
	nat        *nat
	frameCh    chan *frame
	frameCache *sync.Pool

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
}

func (srv *Server) newFrameSender() *frameSender {
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
	sender := frameSender{
		ctx:        srv,
		enableNAT:  srv.enableNAT,
		handle:     srv.handle,
		nat:        srv.nat,
		frameCh:    srv.frameCh,
		frameCache: srv.frameCache,
		eth:        eth,
		arp:        arp,
		ipv4:       ip4,
		ipv6:       ip6,
		icmpv4:     icmpv4,
		icmpv6:     icmpv6,
		tcp:        tcp,
		udp:        udp,
		parser:     parser,
		decoded:    decoded,
		slOpt:      slOpt,
		slBuf:      slBuf,
	}
	sender.macCache.New = func() interface{} {
		return new(mac)
	}
	sender.ipv4Cache.New = func() interface{} {
		return new(ipv4)
	}
	sender.ipv6Cache.New = func() interface{} {
		return new(ipv6)
	}
	return &sender
}

func (s *frameSender) sendLoop() {
	defer s.ctx.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			s.ctx.logger.Fatal("frameSender.sendLoop", r)
			// restart frame sender
			time.Sleep(time.Second)
			s.ctx.wg.Add(1)
			go s.sendLoop()
		}
	}()
	var fr *frame
	for {
		select {
		case fr = <-s.frameCh:
			if s.enableNAT {
				s.sendWithNAT(fr)
			} else {
				s.sendWithBridge(fr)
			}
		case <-s.ctx.ctx.Done():
			return
		}
	}
}

func (s *frameSender) sendWithBridge(frame *frame) {
	defer func() {
		frame.Reset()
		s.frameCache.Put(frame)
	}()

	err := s.parser.DecodeLayers(frame.Data(), s.decoded)
	if err != nil {
		return
	}
	decoded := *s.decoded
	if len(decoded) < 1 || decoded[0] != layers.LayerTypeEthernet {
		return
	}
	// invalid destination mac address
	if bytes.Equal(s.eth.DstMAC, zeroMAC) {
		return
	}
	dstMACPtr := s.macCache.Get().(*mac)
	defer s.macCache.Put(dstMACPtr)
	dstMAC := *dstMACPtr
	copy(dstMAC[:], s.eth.DstMAC)
	// broadcast and multicast
	if dstMAC[0]&1 == 1 {
		s.ctx.broadcast(frame.Bytes())
		return
	}
	// send to the target client
	pool := s.ctx.getConnPoolByMACAddress(dstMAC)
	if pool == nil {
		return
	}
	pool.Push(frame.Bytes())
}

func (s *frameSender) sendWithNAT(frame *frame) {
	defer func() {
		frame.Reset()
		s.frameCache.Put(frame)
	}()

	err := s.parser.DecodeLayers(frame.Data(), s.decoded)
	if err != nil {
		return
	}
	s.isIPv4 = false
	s.isIPv6 = false
	decoded := *s.decoded
	for i := 0; i < len(decoded); i++ {
		switch decoded[i] {
		case layers.LayerTypeEthernet:
			// invalid destination mac address
			if bytes.Equal(s.eth.DstMAC, zeroMAC) {
				return
			}
			// process arp request from gateway
			if bytes.Equal(s.eth.DstMAC, broadcast[:]) {
				s.sendARPReply()
				return
			}
			// process ICMPv6 Solicitation/Advertisement from gateway
			if bytes.Equal(s.eth.DstMAC[:2], []byte{0x33, 0x33}) {
				// TODO ICMPv6
				return
			}
			// ignore frames with different MAC address
			if !bytes.Equal(s.eth.DstMAC, s.nat.localMAC) {
				return
			}
		case layers.LayerTypeIPv4:
			if !s.nat.enableIPv4 {
				return
			}
			s.isIPv4 = true
		case layers.LayerTypeIPv6:
			if !s.nat.enableIPv6 {
				return
			}
			s.isIPv6 = true
		case layers.LayerTypeICMPv4:
			s.sendICMPv4(frame)
			return
		case layers.LayerTypeICMPv6:
			s.sendICMPv6(frame)
			return
		case layers.LayerTypeTCP:
			s.sendTCP(frame)
			return
		case layers.LayerTypeUDP:
			s.sendUDP(frame)
			return
		}
	}
}

func (s *frameSender) sendARPReply() {
	if s.eth.EthernetType != layers.EthernetTypeARP {
		return
	}
	if s.arp.Operation != layers.ARPRequest {
		return
	}
	if !s.nat.localIPv4.Equal(s.arp.DstProtAddress) {
		return
	}
	s.eth.SrcMAC, s.eth.DstMAC = s.nat.localMAC, s.eth.SrcMAC
	s.arp.Operation = layers.ARPReply
	s.arp.DstHwAddress = s.arp.SourceHwAddress
	s.arp.DstProtAddress = s.arp.SourceProtAddress
	s.arp.SourceHwAddress = s.nat.localMAC
	s.arp.SourceProtAddress = s.nat.localIPv4
	// encode data to buffer
	err := gopacket.SerializeLayers(s.slBuf, s.slOpt, s.eth, s.arp)
	if err != nil {
		s.ctx.logger.Warning("failed to serialize arp reply frame:", err)
		return
	}
	data := s.slBuf.Bytes()
	s.writeToInterface(data)
}

func (s *frameSender) sendICMPv4(frame *frame) {
	switch s.icmpv4.TypeCode.Type() {
	case layers.ICMPv4TypeEchoReply:
		s.sendICMPv4EchoReply(frame)
	case layers.ICMPv4TypeTimeExceeded:
		s.sendICMPv4TimeExceeded(frame)
	case layers.ICMPv4TypeDestinationUnreachable:
		s.sendICMPv4DestinationUnreachable(frame)
	}
}

func (s *frameSender) sendICMPv4EchoReply(frame *frame) {
	if s.icmpv4.TypeCode.Code() != 0 {
		return
	}
	rIP := s.ipv4.SrcIP
	natID := s.icmpv4.Id
	li := s.nat.QueryICMPv4IDMap(rIP, natID)
	if li == nil {
		return
	}
	// replace MAC, IP address and icmp id
	dstMAC := s.ctx.ipv4ToMAC(li.localIP)
	s.eth.DstMAC = dstMAC[:]
	copy(s.ipv4.DstIP, li.localIP[:])
	s.icmpv4.Id = binary.BigEndian.Uint16(li.localID[:])
	s.payload = s.icmpv4.Payload
	err := gopacket.SerializeLayers(s.slBuf, s.slOpt, s.eth, s.ipv4, s.icmpv4, s.payload)
	if err != nil {
		s.ctx.logger.Warning("failed to serialize icmpv4 echo reply frame:", err)
		return
	}
	fr := s.slBuf.Bytes()
	frame.Reset()
	frame.WriteHeader(len(fr))
	frame.WriteData(fr)
	// send to the target client
	dstIPv4Ptr := s.ipv4Cache.Get().(*ipv4)
	defer s.ipv4Cache.Put(dstIPv4Ptr)
	dstIPv4 := *dstIPv4Ptr
	copy(dstIPv4[:], s.ipv4.DstIP)
	pool := s.ctx.getConnPoolByIPv4Address(dstIPv4)
	if pool == nil {
		return
	}
	pool.Push(frame.Bytes())
}

func (s *frameSender) sendICMPv4TimeExceeded(frame *frame) {
	if s.icmpv4.TypeCode.Code() != layers.ICMPv4CodeTTLExceeded {
		return
	}
	// get original frame information
	ip4 := new(layers.IPv4)
	icmpv4 := new(layers.ICMPv4)
	payload := new(gopacket.Payload)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, ip4, icmpv4, payload)
	parser.IgnoreUnsupported = true
	var decoded []gopacket.LayerType
	err := parser.DecodeLayers(s.icmpv4.Payload, &decoded)
	if err != nil {
		s.ctx.logger.Warning("failed to decode icmpv4 ttl exceeded payload:", err)
		return
	}
	if len(decoded) != 3 {
		return
	}
	rIP := ip4.DstIP
	natID := icmpv4.Id
	li := s.nat.QueryICMPv4IDMap(rIP, natID)
	if li == nil {
		return
	}
	// replace IP address and icmp id in icmp payload
	copy(ip4.SrcIP, li.localIP[:])
	icmpv4.Id = binary.BigEndian.Uint16(li.localID[:])
	s.payload = *payload
	err = gopacket.SerializeLayers(s.slBuf, s.slOpt, ip4, icmpv4, s.payload)
	if err != nil {
		s.ctx.logger.Warning("failed to serialize icmpv4 ttl exceeded frame payload:", err)
		return
	}
	b := s.slBuf.Bytes()
	p := make([]byte, len(b))
	copy(p, b)
	// replace MAC, IP address
	dstMAC := s.ctx.ipv4ToMAC(li.localIP)
	s.eth.DstMAC = dstMAC[:]
	copy(s.ipv4.DstIP, li.localIP[:])
	s.payload = p
	err = gopacket.SerializeLayers(s.slBuf, s.slOpt, s.eth, s.ipv4, s.icmpv4, s.payload)
	if err != nil {
		s.ctx.logger.Warning("failed to serialize icmpv4 ttl exceeded frame:", err)
		return
	}
	fr := s.slBuf.Bytes()
	frame.Reset()
	frame.WriteHeader(len(fr))
	frame.WriteData(fr)
	// send to the target client
	dstIPv4Ptr := s.ipv4Cache.Get().(*ipv4)
	defer s.ipv4Cache.Put(dstIPv4Ptr)
	dstIPv4 := *dstIPv4Ptr
	copy(dstIPv4[:], s.ipv4.DstIP)
	pool := s.ctx.getConnPoolByIPv4Address(dstIPv4)
	if pool == nil {
		return
	}
	pool.Push(frame.Bytes())
}

func (s *frameSender) sendICMPv4DestinationUnreachable(frame *frame) {
	if s.icmpv4.TypeCode.Code() != layers.ICMPv4CodePort {
		return
	}
	// get original frame information
	ip4 := new(layers.IPv4)
	udp := new(layers.UDP)
	payload := new(gopacket.Payload)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, ip4, udp, payload)
	parser.IgnoreUnsupported = true
	var decoded []gopacket.LayerType
	err := parser.DecodeLayers(s.icmpv4.Payload, &decoded)
	if err != nil {
		s.ctx.logger.Warning("failed to decode icmpv4 port unreachable payload:", err)
		return
	}
	if len(decoded) != 3 {
		return
	}
	rIP := ip4.DstIP
	rPort := uint16(udp.DstPort)
	natPort := uint16(udp.SrcPort)
	li := s.nat.QueryIPv4UDPPortMap(rIP, rPort, natPort)
	if li == nil {
		return
	}
	// replace IP address and udp port in icmp payload
	copy(ip4.SrcIP, li.localIP[:])
	udp.SrcPort = layers.UDPPort(binary.BigEndian.Uint16(li.localPort[:]))
	s.payload = *payload
	err = gopacket.SerializeLayers(s.slBuf, s.slOpt, ip4, udp, s.payload)
	if err != nil {
		s.ctx.logger.Warning("failed to serialize icmpv4 port unreachable payload:", err)
		return
	}
	b := s.slBuf.Bytes()
	p := make([]byte, len(b))
	copy(p, b)
	// replace MAC, IP address
	dstMAC := s.ctx.ipv4ToMAC(li.localIP)
	s.eth.DstMAC = dstMAC[:]
	copy(s.ipv4.DstIP, li.localIP[:])
	s.payload = p
	err = gopacket.SerializeLayers(s.slBuf, s.slOpt, s.eth, s.ipv4, s.icmpv4, s.payload)
	if err != nil {
		s.ctx.logger.Warning("failed to serialize icmpv4 port unreachable frame:", err)
		return
	}
	fr := s.slBuf.Bytes()
	frame.Reset()
	frame.WriteHeader(len(fr))
	frame.WriteData(fr)
	// send to the target client
	dstIPv4Ptr := s.ipv4Cache.Get().(*ipv4)
	defer s.ipv4Cache.Put(dstIPv4Ptr)
	dstIPv4 := *dstIPv4Ptr
	copy(dstIPv4[:], s.ipv4.DstIP)
	pool := s.ctx.getConnPoolByIPv4Address(dstIPv4)
	if pool == nil {
		return
	}
	pool.Push(frame.Bytes())
}

func (s *frameSender) sendICMPv6(frame *frame) {
	switch s.icmpv6.TypeCode.Type() {
	case layers.ICMPv6TypeEchoReply:
		s.sendICMPv6EchoReply(frame)
	case layers.ICMPv6TypeTimeExceeded:
		s.sendICMPv6TimeExceeded(frame)
	case layers.ICMPv6TypeDestinationUnreachable:
		s.sendICMPv6DestinationUnreachable(frame)
	}
}

func (s *frameSender) sendICMPv6EchoReply(frame *frame) {
	if s.icmpv6.TypeCode.Code() != 0 {
		return
	}
	echo := new(layers.ICMPv6Echo)
	err := echo.DecodeFromBytes(s.icmpv6.Payload, gopacket.NilDecodeFeedback)
	if err != nil {
		s.ctx.logger.Warning("failed to decode icmpv6 echo reply frame:", err)
		return
	}
	rIP := s.ipv6.SrcIP
	natID := echo.Identifier
	li := s.nat.QueryICMPv6IDMap(rIP, natID)
	if li == nil {
		return
	}
	// replace MAC, IP address and icmp id
	dstMAC := s.ctx.ipv6ToMAC(li.localIP)
	s.eth.DstMAC = dstMAC[:]
	copy(s.ipv6.DstIP, li.localIP[:])
	_ = s.icmpv6.SetNetworkLayerForChecksum(s.ipv6)
	echo.Identifier = binary.BigEndian.Uint16(li.localID[:])
	s.payload = s.icmpv6.Payload[4:] // size of ICMPv6Echo
	// encode data to buffer
	err = gopacket.SerializeLayers(s.slBuf, s.slOpt, s.eth, s.ipv6, s.icmpv6, echo, s.payload)
	if err != nil {
		s.ctx.logger.Warning("failed to serialize icmpv6 echo reply frame:", err)
		return
	}
	fr := s.slBuf.Bytes()
	frame.Reset()
	frame.WriteHeader(len(fr))
	frame.WriteData(fr)
	// send to the target client
	dstIPv6Ptr := s.ipv6Cache.Get().(*ipv6)
	defer s.ipv6Cache.Put(dstIPv6Ptr)
	dstIPv6 := *dstIPv6Ptr
	copy(dstIPv6[:], s.ipv6.DstIP)
	pool := s.ctx.getConnPoolByIPv6Address(dstIPv6)
	if pool == nil {
		return
	}
	pool.Push(frame.Bytes())
}

func (s *frameSender) sendICMPv6TimeExceeded(frame *frame) {
	if s.icmpv6.TypeCode.Code() != layers.ICMPv6CodeHopLimitExceeded {
		return
	}
	// get original frame information
	ip6 := new(layers.IPv6)
	icmpv6 := new(layers.ICMPv6)
	echo := new(layers.ICMPv6Echo)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, ip6, icmpv6, echo)
	parser.IgnoreUnsupported = true
	var decoded []gopacket.LayerType
	err := parser.DecodeLayers(s.icmpv6.Payload[4:], &decoded) // size of reserved
	if err != nil {
		s.ctx.logger.Warning("failed to decode icmpv6 hop limit exceeded payload:", err)
		return
	}
	if len(decoded) != 3 {
		return
	}
	rIP := ip6.DstIP
	natID := echo.Identifier
	li := s.nat.QueryICMPv6IDMap(rIP, natID)
	if li == nil {
		return
	}
	// replace IP address and icmp id in icmp payload
	copy(ip6.SrcIP, li.localIP[:])
	_ = icmpv6.SetNetworkLayerForChecksum(ip6)
	echo.Identifier = binary.BigEndian.Uint16(li.localID[:])
	s.payload = icmpv6.Payload[4:] // size of ICMPv6Echo
	err = gopacket.SerializeLayers(s.slBuf, s.slOpt, ip6, icmpv6, echo, s.payload)
	if err != nil {
		s.ctx.logger.Warning("failed to serialize icmpv6 hop limit exceeded frame payload:", err)
		return
	}
	b := s.slBuf.Bytes()
	p := make([]byte, 4+len(b)) // padding ICMPv6 reserved
	copy(p[4:], b)
	// replace MAC, IP address
	dstMAC := s.ctx.ipv6ToMAC(li.localIP)
	s.eth.DstMAC = dstMAC[:]
	copy(s.ipv6.DstIP, li.localIP[:])
	_ = s.icmpv6.SetNetworkLayerForChecksum(s.ipv6)
	s.payload = p
	err = gopacket.SerializeLayers(s.slBuf, s.slOpt, s.eth, s.ipv6, s.icmpv6, s.payload)
	if err != nil {
		s.ctx.logger.Warning("failed to serialize icmpv6 hop limit exceeded frame:", err)
		return
	}
	fr := s.slBuf.Bytes()
	frame.Reset()
	frame.WriteHeader(len(fr))
	frame.WriteData(fr)
	// send to the target client
	dstIPv6Ptr := s.ipv6Cache.Get().(*ipv6)
	defer s.ipv6Cache.Put(dstIPv6Ptr)
	dstIPv6 := *dstIPv6Ptr
	copy(dstIPv6[:], s.ipv6.DstIP)
	pool := s.ctx.getConnPoolByIPv6Address(dstIPv6)
	if pool == nil {
		return
	}
	pool.Push(frame.Bytes())
}

func (s *frameSender) sendICMPv6DestinationUnreachable(frame *frame) {
	if s.icmpv6.TypeCode.Code() != layers.ICMPv6CodePortUnreachable {
		return
	}
	// get original frame information
	ip6 := new(layers.IPv6)
	udp := new(layers.UDP)
	payload := new(gopacket.Payload)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, ip6, udp, payload)
	parser.IgnoreUnsupported = true
	var decoded []gopacket.LayerType
	err := parser.DecodeLayers(s.icmpv6.Payload, &decoded)
	if err != nil {
		s.ctx.logger.Warning("failed to decode icmpv6 port unreachable payload:", err)
		return
	}
	if len(decoded) != 3 {
		return
	}
	rIP := ip6.DstIP
	rPort := uint16(udp.DstPort)
	natPort := uint16(udp.SrcPort)
	li := s.nat.QueryIPv6UDPPortMap(rIP, rPort, natPort)
	if li == nil {
		return
	}
	// replace IP address and udp port in icmp payload
	copy(ip6.SrcIP, li.localIP[:])
	udp.SrcPort = layers.UDPPort(binary.BigEndian.Uint16(li.localPort[:]))
	s.payload = *payload
	err = gopacket.SerializeLayers(s.slBuf, s.slOpt, ip6, udp, s.payload)
	if err != nil {
		s.ctx.logger.Warning("failed to serialize icmpv6 port unreachable payload:", err)
		return
	}
	b := s.slBuf.Bytes()
	p := make([]byte, len(b))
	copy(p, b)
	// replace MAC, IP address
	dstMAC := s.ctx.ipv6ToMAC(li.localIP)
	s.eth.DstMAC = dstMAC[:]
	copy(s.ipv6.DstIP, li.localIP[:])
	s.payload = p
	err = gopacket.SerializeLayers(s.slBuf, s.slOpt, s.eth, s.ipv6, s.icmpv6, s.payload)
	if err != nil {
		s.ctx.logger.Warning("failed to serialize icmpv6 port unreachable frame:", err)
		return
	}
	fr := s.slBuf.Bytes()
	frame.Reset()
	frame.WriteHeader(len(fr))
	frame.WriteData(fr)
	// send to the target client
	dstIPv6Ptr := s.ipv6Cache.Get().(*ipv6)
	defer s.ipv6Cache.Put(dstIPv6Ptr)
	dstIPv6 := *dstIPv6Ptr
	copy(dstIPv6[:], s.ipv6.DstIP)
	pool := s.ctx.getConnPoolByIPv6Address(dstIPv6)
	if pool == nil {
		return
	}
	pool.Push(frame.Bytes())
}

func (s *frameSender) sendTCP(frame *frame) {
	switch {
	case s.isIPv4:
		s.sendIPv4TCP(frame)
	case s.isIPv6:
		s.sendIPv6TCP(frame)
	}
}

func (s *frameSender) sendIPv4TCP(frame *frame) {
	rIP := s.ipv4.SrcIP
	rPort := uint16(s.tcp.SrcPort)
	natPort := uint16(s.tcp.DstPort)
	li := s.nat.QueryIPv4TCPPortMap(rIP, rPort, natPort)
	if li == nil {
		return
	}
	// replace MAC, IP address and tcp port
	dstMAC := s.ctx.ipv4ToMAC(li.localIP)
	s.eth.DstMAC = dstMAC[:]
	copy(s.ipv4.DstIP, li.localIP[:])
	s.tcp.DstPort = layers.TCPPort(binary.BigEndian.Uint16(li.localPort[:]))
	_ = s.tcp.SetNetworkLayerForChecksum(s.ipv4)
	s.payload = s.tcp.Payload
	// encode data to buffer
	err := gopacket.SerializeLayers(s.slBuf, s.slOpt, s.eth, s.ipv4, s.tcp, s.payload)
	if err != nil {
		s.ctx.logger.Warning("failed to serialize ipv4 tcp frame:", err)
		return
	}
	fr := s.slBuf.Bytes()
	frame.Reset()
	frame.WriteHeader(len(fr))
	frame.WriteData(fr)
	// send to the target client
	dstIPv4Ptr := s.ipv4Cache.Get().(*ipv4)
	defer s.ipv4Cache.Put(dstIPv4Ptr)
	dstIPv4 := *dstIPv4Ptr
	copy(dstIPv4[:], s.ipv4.DstIP)
	pool := s.ctx.getConnPoolByIPv4Address(dstIPv4)
	if pool == nil {
		return
	}
	pool.Push(frame.Bytes())
}

func (s *frameSender) sendIPv6TCP(frame *frame) {
	rIP := s.ipv6.SrcIP
	rPort := uint16(s.tcp.SrcPort)
	natPort := uint16(s.tcp.DstPort)
	li := s.nat.QueryIPv6TCPPortMap(rIP, rPort, natPort)
	if li == nil {
		return
	}
	// replace MAC, IP address and tcp port
	dstMAC := s.ctx.ipv6ToMAC(li.localIP)
	s.eth.DstMAC = dstMAC[:]
	copy(s.ipv6.DstIP, li.localIP[:])
	s.tcp.DstPort = layers.TCPPort(binary.BigEndian.Uint16(li.localPort[:]))
	_ = s.tcp.SetNetworkLayerForChecksum(s.ipv6)
	s.payload = s.tcp.Payload
	// encode data to buffer
	err := gopacket.SerializeLayers(s.slBuf, s.slOpt, s.eth, s.ipv6, s.tcp, s.payload)
	if err != nil {
		s.ctx.logger.Warning("failed to serialize ipv6 tcp frame:", err)
		return
	}
	fr := s.slBuf.Bytes()
	frame.Reset()
	frame.WriteHeader(len(fr))
	frame.WriteData(fr)
	// send to the target client
	dstIPv6Ptr := s.ipv6Cache.Get().(*ipv6)
	defer s.ipv6Cache.Put(dstIPv6Ptr)
	dstIPv6 := *dstIPv6Ptr
	copy(dstIPv6[:], s.ipv6.DstIP)
	pool := s.ctx.getConnPoolByIPv6Address(dstIPv6)
	if pool == nil {
		return
	}
	pool.Push(frame.Bytes())
}

func (s *frameSender) sendUDP(frame *frame) {
	switch {
	case s.isIPv4:
		s.sendIPv4UDP(frame)
	case s.isIPv6:
		s.sendIPv6UDP(frame)
	}
}

func (s *frameSender) sendIPv4UDP(frame *frame) {
	rIP := s.ipv4.SrcIP
	rPort := uint16(s.udp.SrcPort)
	natPort := uint16(s.udp.DstPort)
	li := s.nat.QueryIPv4UDPPortMap(rIP, rPort, natPort)
	if li == nil {
		return
	}
	// replace MAC, IP address and udp port
	dstMAC := s.ctx.ipv4ToMAC(li.localIP)
	s.eth.DstMAC = dstMAC[:]
	copy(s.ipv4.DstIP, li.localIP[:])
	s.udp.DstPort = layers.UDPPort(binary.BigEndian.Uint16(li.localPort[:]))
	_ = s.udp.SetNetworkLayerForChecksum(s.ipv4)
	s.payload = s.udp.Payload
	// encode data to buffer
	err := gopacket.SerializeLayers(s.slBuf, s.slOpt, s.eth, s.ipv4, s.udp, s.payload)
	if err != nil {
		s.ctx.logger.Warning("failed to serialize ipv4 udp frame:", err)
		return
	}
	fr := s.slBuf.Bytes()
	frame.Reset()
	frame.WriteHeader(len(fr))
	frame.WriteData(fr)
	// send to the target client
	dstIPv4Ptr := s.ipv4Cache.Get().(*ipv4)
	defer s.ipv4Cache.Put(dstIPv4Ptr)
	dstIPv4 := *dstIPv4Ptr
	copy(dstIPv4[:], s.ipv4.DstIP)
	pool := s.ctx.getConnPoolByIPv4Address(dstIPv4)
	if pool == nil {
		return
	}
	pool.Push(frame.Bytes())
}

func (s *frameSender) sendIPv6UDP(frame *frame) {
	rIP := s.ipv6.SrcIP
	rPort := uint16(s.udp.SrcPort)
	natPort := uint16(s.udp.DstPort)
	li := s.nat.QueryIPv6UDPPortMap(rIP, rPort, natPort)
	if li == nil {
		return
	}
	// replace MAC, IP address and udp port
	dstMAC := s.ctx.ipv6ToMAC(li.localIP)
	s.eth.DstMAC = dstMAC[:]
	copy(s.ipv6.DstIP, li.localIP[:])
	s.udp.DstPort = layers.UDPPort(binary.BigEndian.Uint16(li.localPort[:]))
	_ = s.udp.SetNetworkLayerForChecksum(s.ipv6)
	s.payload = s.udp.Payload
	// encode data to buffer
	err := gopacket.SerializeLayers(s.slBuf, s.slOpt, s.eth, s.ipv6, s.udp, s.payload)
	if err != nil {
		s.ctx.logger.Warning("failed to serialize ipv6 udp frame:", err)
		return
	}
	fr := s.slBuf.Bytes()
	frame.Reset()
	frame.WriteHeader(len(fr))
	frame.WriteData(fr)
	// send to the target client
	dstIPv6Ptr := s.ipv6Cache.Get().(*ipv6)
	defer s.ipv6Cache.Put(dstIPv6Ptr)
	dstIPv6 := *dstIPv6Ptr
	copy(dstIPv6[:], s.ipv6.DstIP)
	pool := s.ctx.getConnPoolByIPv6Address(dstIPv6)
	if pool == nil {
		return
	}
	pool.Push(frame.Bytes())
}

func (s *frameSender) writeToInterface(data []byte) {
	_ = s.handle.WritePacketData(data)
}
