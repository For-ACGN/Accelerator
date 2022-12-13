package accelerator

import (
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
	buf := pkt.buf[:pkt.size]
	err := s.parser.DecodeLayers(buf, s.decoded)
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
}
