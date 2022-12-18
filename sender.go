package accelerator

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// packetSender is used to parse packet from destination network
// interface, if the source MAC address or IP address is matched
// in clients map, it will be sent to the connection about client.
type packetSender struct {
	ctx *Server

	enableNAT bool

	nat         *nat
	packetCh    chan *packet
	packetCache *sync.Pool

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

func (srv *Server) newPacketSender() *packetSender {
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
	sender := packetSender{
		ctx:         srv,
		enableNAT:   enableNAT,
		nat:         srv.nat,
		packetCh:    srv.packetCh,
		packetCache: srv.packetCache,
		eth:         eth,
		arp:         arp,
		ipv4:        ip4,
		ipv6:        ip6,
		icmp4:       icmp4,
		icmp6:       icmp6,
		tcp:         tcp,
		udp:         udp,
		parser:      parser,
		decoded:     decoded,
		slOpt:       slOpt,
		slBuf:       slBuf,
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

func (s *packetSender) sendLoop() {
	defer s.ctx.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			s.ctx.logger.Fatal("packetSender.sendLoop", r)
			// restart sender
			time.Sleep(time.Second)
			s.ctx.wg.Add(1)
			go s.sendLoop()
		}
	}()
	var pkt *packet
	for {
		select {
		case pkt = <-s.packetCh:
			if s.enableNAT {
				s.sendWithNAT(pkt)
			} else {
				s.sendWithoutNAT(pkt)
			}
		case <-s.ctx.ctx.Done():
			return
		}
	}
}

func (s *packetSender) sendWithoutNAT(pkt *packet) {
	defer s.packetCache.Put(pkt)
	data := pkt.buf[frameHeaderSize : frameHeaderSize+pkt.size]
	err := s.parser.DecodeLayers(data, s.decoded)
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
	// encode packet size
	buf := pkt.buf[:frameHeaderSize+pkt.size]
	binary.BigEndian.PutUint16(buf, pkt.size)
	if dstMAC == broadcast {
		s.ctx.broadcast(buf)
		return
	}
	// check it is sent to one client
	pool := s.ctx.getConnPoolByMAC(dstMAC)
	if pool == nil {
		return
	}
	_, _ = pool.Write(buf)
}

func (s *packetSender) sendWithNAT(pkt *packet) {
	defer s.packetCache.Put(pkt)
	data := pkt.buf[frameHeaderSize : frameHeaderSize+pkt.size]
	err := s.parser.DecodeLayers(data, s.decoded)
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

func (s *packetSender) sendIPv4TCP() {
	rIP := s.ipv4.SrcIP
	rPort := uint16(s.tcp.SrcPort)
	lIP := s.ipv4.DstIP
	lPort := uint16(s.tcp.DstPort)
	if !lIP.Equal(s.nat.gatewayIPv4) {
		return
	}
	li := s.nat.QueryIPv4TCPPortMap(rIP, rPort, lPort)
	if li == nil {
		return
	}

	copy(s.ipv4.DstIP, li.localIP[:])
	s.tcp.DstPort = layers.TCPPort(binary.BigEndian.Uint16(li.localPort[:]))

	_ = s.tcp.SetNetworkLayerForChecksum(s.ipv4)

	err := gopacket.SerializeLayers(s.slBuf, s.slOpt, s.eth, s.ipv4, s.tcp)
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

func (s *packetSender) sendIPv4UDP() {
	rIP := s.ipv4.SrcIP
	rPort := uint16(s.udp.SrcPort)
	lIP := s.ipv4.DstIP
	lPort := uint16(s.udp.DstPort)
	if !lIP.Equal(s.nat.gatewayIPv4) {
		return
	}
	li := s.nat.QueryIPv4UDPPortMap(rIP, rPort, lPort)
	if li == nil {
		return
	}

	copy(s.ipv4.DstIP, li.localIP[:])
	s.udp.DstPort = layers.UDPPort(binary.BigEndian.Uint16(li.localPort[:]))

	_ = s.udp.SetNetworkLayerForChecksum(s.ipv4)

	err := gopacket.SerializeLayers(s.slBuf, s.slOpt, s.eth, s.ipv4, s.udp)
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

func (s *packetSender) sendIPv6TCP() {

}

func (s *packetSender) sendIPv6UDP() {

}
