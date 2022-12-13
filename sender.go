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

	nat bool

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
}

func (srv *Server) newPacketSender() *packetSender {
	nat := srv.nat
	eth := new(layers.Ethernet)
	arp := new(layers.ARP)
	ip4 := new(layers.IPv4)
	ip6 := new(layers.IPv6)
	icmp4 := new(layers.ICMPv4)
	icmp6 := new(layers.ICMPv6)
	tcp := new(layers.TCP)
	udp := new(layers.UDP)
	var parser *gopacket.DecodingLayerParser
	if nat {
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
		nat:         nat,
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
			s.send(pkt)
		case <-s.ctx.ctx.Done():
			return
		}
	}
}

func (s *packetSender) send(pkt *packet) {
	defer s.packetCache.Put(pkt)
}
