package accelerator

import (
	"sync"
)

// packetSender is used to parse packet from destination network
// interface, if the source MAC address or IP address is matched
// in clients map, it will be sent to the connection about client.
type packetSender struct {
	ctx *Server

	packetCh    chan *packet
	packetCache *sync.Pool
}

func (srv *Server) newPacketSender() *packetSender {
	sender := packetSender{
		ctx:         srv,
		packetCh:    srv.packetCh,
		packetCache: srv.packetCache,
	}
	return &sender
}

func (s *packetSender) sendLoop() {
	defer s.ctx.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			s.ctx.logger.Fatal("packetSender.sendLoop", r)
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
