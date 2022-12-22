package accelerator

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// frameSender is used to parse frame from destination network
// interface, if the source MAC address or IP address is matched
// in clients map, it will be sent to the connection about client.
type frameSender struct {
	ctx *Server

	enableNAT bool

	nat        *nat
	frameCh    chan *frame
	frameCache *sync.Pool

	eth     *layers.Ethernet
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
}

func (srv *Server) newFrameSender() *frameSender {
	enableNAT := srv.enableNAT
	eth := new(layers.Ethernet)
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
			eth,
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
	sender := frameSender{
		ctx:        srv,
		enableNAT:  enableNAT,
		nat:        srv.nat,
		frameCh:    srv.frameCh,
		frameCache: srv.frameCache,
		eth:        eth,
		ipv4:       ip4,
		ipv6:       ip6,
		icmp4:      icmp4,
		icmp6:      icmp6,
		tcp:        tcp,
		udp:        udp,
		payload:    payload,
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
			// restart sender
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
				s.sendWithoutNAT(fr)
			}
		case <-s.ctx.ctx.Done():
			return
		}
	}
}

func (s *frameSender) sendWithoutNAT(frame *frame) {
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

	dstMACPtr := s.macCache.Get().(*mac)
	defer s.macCache.Put(dstMACPtr)
	dstMAC := *dstMACPtr
	copy(dstMAC[:], s.eth.DstMAC)

	if dstMAC == broadcast {
		s.ctx.broadcast(frame.Bytes())
		return
	}
	// send to the target client
	pool := s.ctx.getConnPoolByMAC(dstMAC)
	if pool == nil {
		return
	}
	_, _ = pool.Write(frame.Bytes())
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
		case layers.LayerTypeIPv4:
			if !s.ipv4.DstIP.Equal(s.nat.localIPv4) {
				return
			}
			s.isIPv4 = true
		case layers.LayerTypeIPv6:
			if !s.ipv6.DstIP.Equal(s.nat.localIPv6) {
				return
			}
			s.isIPv6 = true
		case layers.LayerTypeICMPv4:
			// TODO ICMP
			return
		case layers.LayerTypeICMPv6:
			// TODO ICMP
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

func (s *frameSender) sendTCP(frame *frame) {
	switch {
	case s.isIPv4:
		s.sendIPv4TCP(frame)
	case s.isIPv6:
		s.sendIPv6TCP(frame)
	}
}

func (s *frameSender) sendUDP(frame *frame) {
	switch {
	case s.isIPv4:
		s.sendIPv4UDP(frame)
	case s.isIPv6:
		s.sendIPv6UDP(frame)
	}
}

func (s *frameSender) sendIPv4TCP(frame *frame) {
	rIP := s.ipv4.SrcIP
	rPort := uint16(s.tcp.SrcPort)
	lPort := uint16(s.tcp.DstPort)
	li := s.nat.QueryIPv4TCPPortMap(rIP, rPort, lPort)
	if li == nil {
		return
	}
	// replace IP address and tcp port
	dstMAC := s.ctx.ipv4ToMAC(li.localIP)
	s.eth.DstMAC = dstMAC[:]
	copy(s.ipv4.DstIP, li.localIP[:])
	s.tcp.DstPort = layers.TCPPort(binary.BigEndian.Uint16(li.localPort[:]))
	_ = s.tcp.SetNetworkLayerForChecksum(s.ipv4)
	// encode data to buffer
	err := gopacket.SerializeLayers(s.slBuf, s.slOpt, s.eth, s.ipv4, s.tcp, s.payload)
	if err != nil {
		const format = "failed to serialize ipv4 tcp frame: %s"
		s.ctx.logger.Warningf(format, err)
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
	pool := s.ctx.getConnPoolByIPv4(dstIPv4)
	if pool == nil {
		return
	}
	_, _ = pool.Write(frame.Bytes())
}

func (s *frameSender) sendIPv6TCP(frame *frame) {
	rIP := s.ipv6.SrcIP
	rPort := uint16(s.tcp.SrcPort)
	lPort := uint16(s.tcp.DstPort)
	li := s.nat.QueryIPv6TCPPortMap(rIP, rPort, lPort)
	if li == nil {
		return
	}
	// replace IP address and tcp port
	dstMAC := s.ctx.ipv6ToMAC(li.localIP)
	s.eth.DstMAC = dstMAC[:]
	copy(s.ipv6.DstIP, li.localIP[:])
	s.tcp.DstPort = layers.TCPPort(binary.BigEndian.Uint16(li.localPort[:]))
	_ = s.tcp.SetNetworkLayerForChecksum(s.ipv6)
	// encode data to buffer
	err := gopacket.SerializeLayers(s.slBuf, s.slOpt, s.eth, s.ipv6, s.tcp, s.payload)
	if err != nil {
		const format = "failed to serialize ipv6 tcp frame: %s"
		s.ctx.logger.Warningf(format, err)
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
	pool := s.ctx.getConnPoolByIPv6(dstIPv6)
	if pool == nil {
		return
	}
	_, _ = pool.Write(frame.Bytes())
}

func (s *frameSender) sendIPv4UDP(frame *frame) {
	rIP := s.ipv4.SrcIP
	rPort := uint16(s.udp.SrcPort)
	lPort := uint16(s.udp.DstPort)
	li := s.nat.QueryIPv4UDPPortMap(rIP, rPort, lPort)
	if li == nil {
		return
	}
	// replace IP address and udp port
	dstMAC := s.ctx.ipv4ToMAC(li.localIP)
	s.eth.DstMAC = dstMAC[:]
	copy(s.ipv4.DstIP, li.localIP[:])
	s.udp.DstPort = layers.UDPPort(binary.BigEndian.Uint16(li.localPort[:]))
	_ = s.udp.SetNetworkLayerForChecksum(s.ipv4)
	// encode data to buffer
	err := gopacket.SerializeLayers(s.slBuf, s.slOpt, s.eth, s.ipv4, s.udp, s.payload)
	if err != nil {
		const format = "failed to serialize ipv4 udp frame: %s"
		s.ctx.logger.Warningf(format, err)
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
	pool := s.ctx.getConnPoolByIPv4(dstIPv4)
	if pool == nil {
		return
	}
	_, _ = pool.Write(frame.Bytes())
}

func (s *frameSender) sendIPv6UDP(frame *frame) {
	rIP := s.ipv6.SrcIP
	rPort := uint16(s.udp.SrcPort)
	lPort := uint16(s.udp.DstPort)
	li := s.nat.QueryIPv6UDPPortMap(rIP, rPort, lPort)
	if li == nil {
		return
	}
	// replace IP address and udp port
	dstMAC := s.ctx.ipv6ToMAC(li.localIP)
	s.eth.DstMAC = dstMAC[:]
	copy(s.ipv6.DstIP, li.localIP[:])
	s.udp.DstPort = layers.UDPPort(binary.BigEndian.Uint16(li.localPort[:]))
	_ = s.udp.SetNetworkLayerForChecksum(s.ipv6)
	// encode data to buffer
	err := gopacket.SerializeLayers(s.slBuf, s.slOpt, s.eth, s.ipv6, s.udp, s.payload)
	if err != nil {
		const format = "failed to serialize ipv6 udp frame: %s"
		s.ctx.logger.Warningf(format, err)
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
	pool := s.ctx.getConnPoolByIPv6(dstIPv6)
	if pool == nil {
		return
	}
	_, _ = pool.Write(frame.Bytes())
}
