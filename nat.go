package accelerator

import (
	"context"
	"sync"
	"time"
)

type ipv4RI struct {
	remoteIP   ipv4
	remotePort port
	natPort    port
}

type ipv4LI struct {
	localIP   ipv4
	localPort port
}

type ipv6RI struct {
	remoteIP   ipv6
	remotePort port
	natPort    port
}

type ipv6LI struct {
	localIP   ipv6
	localPort port
}

type nat struct {
	logger *logger

	gatewayIPv4 ipv4
	gatewayIPv6 ipv6
	gatewayMAC  mac
	mapTimeout  time.Duration

	ipv4    map[ipv4RI]*ipv4LI
	ipv4RWM sync.RWMutex
	ipv6    map[ipv6RI]*ipv6LI
	ipv6RWM sync.RWMutex

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newNAT(lg *logger, cfg *ServerConfig) (*nat, error) {

	n := nat{
		logger: lg,
		ipv4:   make(map[ipv4RI]*ipv4LI, 512),
		ipv6:   make(map[ipv6RI]*ipv6LI, 512),
	}
	n.ctx, n.cancel = context.WithCancel(context.Background())
	return &n, nil
}

func (nat *nat) Run() {
	nat.wg.Add(1)
	go nat.cleaner()
}

func (nat *nat) cleaner() {
	defer nat.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			nat.logger.Fatal("nat.cleaner", r)
		}
	}()
	const period = 10 * time.Second
	timer := time.NewTimer(period)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			nat.clean()
		case <-nat.ctx.Done():
			return
		}
		timer.Reset(period)
	}
}

func (nat *nat) clean() {

}

func (nat *nat) Close() {
	nat.cancel()
	nat.wg.Wait()
}
