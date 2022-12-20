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

	macCache  sync.Pool
	ipv4Cache sync.Pool
	ipv6Cache sync.Pool
}

func (srv *Server) newFrameSender() *frameSender {
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
	sender := frameSender{
		ctx:        srv,
		enableNAT:  enableNAT,
		nat:        srv.nat,
		frameCh:    srv.frameCh,
		frameCache: srv.frameCache,
		eth:        eth,
		arp:        arp,
		ipv4:       ip4,
		ipv6:       ip6,
		icmp4:      icmp4,
		icmp6:      icmp6,
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
	if len(decoded) < 1 {
		return
	}
	if decoded[0] != layers.LayerTypeEthernet {
		return
	}

	dstMACPtr := s.macCache.Get().(*mac)
	defer s.macCache.Put(dstMACPtr)
	dstMAC := *dstMACPtr
	copy(dstMAC[:], s.eth.DstMAC)

	b := frame.Bytes()
	if dstMAC == broadcast {
		s.ctx.broadcast(b)
		return
	}
	// check it is sent to one client
	pool := s.ctx.getConnPoolByMAC(dstMAC)
	if pool == nil {
		return
	}
	_, _ = pool.Write(b)
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
	decoded := *s.decoded
	var (
		isIPv4 bool
		isIPv6 bool
	)
	for i := 0; i < len(decoded); i++ {
		switch decoded[i] {
		case layers.LayerTypeEthernet:

		case layers.LayerTypeARP:

		case layers.LayerTypeIPv4:
			isIPv4 = true
		case layers.LayerTypeIPv6:
			isIPv6 = true
		case layers.LayerTypeICMPv4:

		case layers.LayerTypeICMPv6:

		case layers.LayerTypeTCP:
			switch {
			case isIPv4:
				s.sendIPv4TCP()
			case isIPv6:
				s.sendIPv6TCP()
			}
			return
		case layers.LayerTypeUDP:
			switch {
			case isIPv4:
				s.sendIPv4UDP()
			case isIPv6:
				s.sendIPv6UDP()
			}
			return
		}
	}
}

func (s *frameSender) sendIPv4TCP() {
	rIP := s.ipv4.SrcIP
	rPort := uint16(s.tcp.SrcPort)
	lIP := s.ipv4.DstIP
	lPort := uint16(s.tcp.DstPort)
	if !lIP.Equal(s.nat.localIPv4) {
		return
	}
	li := s.nat.QueryIPv4TCPPortMap(rIP, rPort, lPort)
	if li == nil {
		return
	}

	dstMAC := s.ctx.ipv4ToMAC(li.localIP)
	s.eth.DstMAC = dstMAC[:]
	copy(s.ipv4.DstIP, li.localIP[:])
	s.tcp.DstPort = layers.TCPPort(binary.BigEndian.Uint16(li.localPort[:]))

	_ = s.tcp.SetNetworkLayerForChecksum(s.ipv4)

	payload := gopacket.Payload(s.tcp.Payload)

	err := gopacket.SerializeLayers(s.slBuf, s.slOpt, s.eth, s.ipv4, s.tcp, payload)
	if err != nil {
		const format = "failed to serialize ipv4 tcp layers: %s"
		s.ctx.logger.Warningf(format, err)
		return
	}

	sb := s.slBuf.Bytes()

	dstIPv4Ptr := s.ipv4Cache.Get().(*ipv4)
	defer s.ipv4Cache.Put(dstIPv4Ptr)
	dstIPv4 := *dstIPv4Ptr
	copy(dstIPv4[:], s.ipv4.DstIP)
	// encode packet size
	buf := make([]byte, frameHeaderSize+len(sb))
	binary.BigEndian.PutUint16(buf, uint16(len(sb)))
	copy(buf[frameHeaderSize:], sb)

	// check it is sent to one client
	pool := s.ctx.getConnPoolByIPv4(dstIPv4)
	if pool == nil {
		return
	}
	_, _ = pool.Write(buf)
}

func (s *frameSender) sendIPv4UDP() {
	rIP := s.ipv4.SrcIP
	rPort := uint16(s.udp.SrcPort)
	lIP := s.ipv4.DstIP
	lPort := uint16(s.udp.DstPort)
	if !lIP.Equal(s.nat.localIPv4) {
		return
	}
	li := s.nat.QueryIPv4UDPPortMap(rIP, rPort, lPort)
	if li == nil {
		return
	}

	dstMAC := s.ctx.ipv4ToMAC(li.localIP)
	s.eth.DstMAC = dstMAC[:]
	copy(s.ipv4.DstIP, li.localIP[:])
	s.udp.DstPort = layers.UDPPort(binary.BigEndian.Uint16(li.localPort[:]))

	_ = s.udp.SetNetworkLayerForChecksum(s.ipv4)

	payload := gopacket.Payload(s.udp.Payload)

	err := gopacket.SerializeLayers(s.slBuf, s.slOpt, s.eth, s.ipv4, s.udp, payload)
	if err != nil {
		const format = "failed to serialize ipv4 udp layers: %s"
		s.ctx.logger.Warningf(format, err)
		return
	}

	sb := s.slBuf.Bytes()

	dstIPv4Ptr := s.ipv4Cache.Get().(*ipv4)
	defer s.ipv4Cache.Put(dstIPv4Ptr)
	dstIPv4 := *dstIPv4Ptr
	copy(dstIPv4[:], s.ipv4.DstIP)
	// encode packet size
	buf := make([]byte, frameHeaderSize+len(sb))
	binary.BigEndian.PutUint16(buf, uint16(len(sb)))
	copy(buf[frameHeaderSize:], sb)

	// check it is sent to one client
	pool := s.ctx.getConnPoolByIPv4(dstIPv4)
	if pool == nil {
		return
	}
	_, _ = pool.Write(buf)
}

func (s *frameSender) sendIPv6TCP() {

}

func (s *frameSender) sendIPv6UDP() {

}
