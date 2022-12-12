package accelerator

// captureLoop is used to capture packet from destination network
// interface and send it to the packet channel for packetSender.
func (srv *Server) captureLoop() {
	defer srv.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			srv.logger.Fatal("Server.captureLoop", r)
		}
	}()
	defer srv.handle.Close()
	var (
		data []byte
		pkt  *packet
		err  error
	)
	for {
		data, _, err = srv.handle.ZeroCopyReadPacketData()
		if err != nil {
			return
		}
		pkt = srv.packetCache.Get().(*packet)
		pkt.size = copy(pkt.buf, data)
		select {
		case srv.packetCh <- pkt:
		case <-srv.ctx.Done():
			return
		}
	}
}

// packetSender is used to parse packet from destination network
// interface, if the source MAC address or IP address is matched
// in clients map, it will be sent to the connection about client.
func (srv *Server) packetSender() {
	defer srv.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			srv.logger.Fatal("Server.packetSender", r)
		}
	}()
	var pkt *packet
	for {
		select {
		case pkt = <-srv.packetCh:
			srv.sendPacket(pkt)
		case <-srv.ctx.Done():
			return
		}
	}
}

func (srv *Server) sendPacket(pkt *packet) {
	defer srv.packetCache.Put(pkt)
}
