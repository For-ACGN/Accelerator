package accelerator

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
)

const minMapTimeout = 30 * time.Second

type ipv4RI struct {
	remoteIP   ipv4
	remotePort port
	natPort    port
}

type ipv4LI struct {
	localIP   ipv4
	localPort port
	preCtr    *uint32
	curCtr    *uint32
	createAt  time.Time
}

type ipv6RI struct {
	remoteIP   ipv6
	remotePort port
	natPort    port
}

type ipv6LI struct {
	localIP   ipv6
	localPort port
	preCtr    *uint32
	curCtr    *uint32
	createAt  time.Time
}

type nat struct {
	logger *logger

	gatewayMAC  net.HardwareAddr
	gatewayIPv4 net.IP
	gatewayIPv6 net.IP
	mapTimeout  time.Duration

	tcpIPv4    map[ipv4RI]*ipv4LI
	tcpIPv4RWM sync.RWMutex
	udpIPv4    map[ipv4RI]*ipv4LI
	udpIPv4RWM sync.RWMutex

	tcpIPv6    map[ipv6RI]*ipv6LI
	tcpIPv6RWM sync.RWMutex
	udpIPv6    map[ipv6RI]*ipv6LI
	udpIPv6RWM sync.RWMutex

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newNAT(lg *logger, cfg *ServerConfig) (*nat, error) {
	var (
		gatewayMAC  net.HardwareAddr
		gatewayIPv4 net.IP
		gatewayIPv6 net.IP
		hasGateway  bool
		err         error
	)
	nc := cfg.NAT
	gatewayMAC, err = net.ParseMAC(nc.GatewayMAC)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse NAT gateway MAC address")
	}
	if len(gatewayMAC) != 6 {
		return nil, errors.New("invalid NAT gateway MAC address")
	}
	if nc.GatewayIPv4 != "" {
		ip := net.ParseIP(nc.GatewayIPv4)
		if ip.To4() == nil {
			return nil, errors.Wrap(err, "invalid NAT gateway IPv4 address")
		}
		gatewayIPv4 = ip
		hasGateway = true
	}
	if nc.GatewayIPv6 != "" {
		ip := net.ParseIP(nc.GatewayIPv6)
		if ip.To4() == nil && ip.To16() == nil {
			return nil, errors.Wrap(err, "invalid NAT gateway IPv6 address")
		}
		gatewayIPv6 = ip
		hasGateway = true
	}
	if !hasGateway {
		return nil, errors.New("empty NAT gateway IP address")
	}
	mapTimeout := time.Duration(nc.MapTimeout)
	if mapTimeout < minMapTimeout {
		mapTimeout = minMapTimeout
	}
	n := nat{
		logger:      lg,
		gatewayMAC:  gatewayMAC,
		gatewayIPv4: gatewayIPv4,
		gatewayIPv6: gatewayIPv6,
		mapTimeout:  mapTimeout,
		tcpIPv4:     make(map[ipv4RI]*ipv4LI, 512),
		udpIPv4:     make(map[ipv4RI]*ipv4LI, 512),
		tcpIPv6:     make(map[ipv6RI]*ipv6LI, 512),
		udpIPv6:     make(map[ipv6RI]*ipv6LI, 512),
	}
	n.ctx, n.cancel = context.WithCancel(context.Background())
	return &n, nil
}

func (nat *nat) Run() {
	nat.wg.Add(1)
	go nat.cleaner()
}

func (nat *nat) AddTCPIPv4Map(ri ipv4RI) {
	nat.tcpIPv4RWM.Lock()
	defer nat.tcpIPv4RWM.Unlock()

}

func (nat *nat) AddUDPIPv6Map(ri ipv4RI) {
	nat.tcpIPv6RWM.Lock()
	defer nat.tcpIPv6RWM.Unlock()
}

func (nat *nat) DeleteTCPIPv4Map(ri ipv4RI) {
	nat.tcpIPv4RWM.Lock()
	defer nat.tcpIPv4RWM.Unlock()
	delete(nat.tcpIPv4, ri)
}

func (nat *nat) DeleteUDPIPv4Map(ri ipv4RI) {
	nat.udpIPv4RWM.Lock()
	defer nat.udpIPv4RWM.Unlock()
	delete(nat.udpIPv4, ri)
}

func (nat *nat) DeleteTCPIPv6Map(ri ipv6RI) {
	nat.tcpIPv6RWM.Lock()
	defer nat.tcpIPv6RWM.Unlock()
	delete(nat.tcpIPv6, ri)
}

func (nat *nat) DeleteUDPIPv6Map(ri ipv6RI) {
	nat.udpIPv6RWM.Lock()
	defer nat.udpIPv6RWM.Unlock()
	delete(nat.udpIPv6, ri)
}

func (nat *nat) cleaner() {
	defer nat.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			nat.logger.Fatal("nat.cleaner", r)
			// restart cleaner
			time.Sleep(time.Second)
			nat.wg.Add(1)
			go nat.cleaner()
		}
	}()
	timer := time.NewTimer(nat.mapTimeout)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			nat.clean()
		case <-nat.ctx.Done():
			return
		}
		timer.Reset(nat.mapTimeout)
	}
}

func (nat *nat) clean() {
	if nat.gatewayIPv4 != nil {
		nat.cleanTCPIPv4()
		nat.cleanUDPIPv4()
	}
	if nat.gatewayIPv6 != nil {
		nat.cleanTCPIPv6()
		nat.cleanUDPIPv6()
	}
}

func (nat *nat) cleanTCPIPv4() {
	var (
		prevent uint32
		current uint32
	)
	now := time.Now()
	nat.tcpIPv4RWM.Lock()
	defer nat.tcpIPv4RWM.Unlock()
	for ri, li := range nat.tcpIPv4 {
		if now.Sub(li.createAt) < nat.mapTimeout {
			continue
		}
		prevent = atomic.LoadUint32(li.preCtr)
		current = atomic.LoadUint32(li.curCtr)
		if prevent != current {
			atomic.StoreUint32(li.preCtr, current)
			continue
		}
		nat.DeleteTCPIPv4Map(ri)
	}
}

func (nat *nat) cleanUDPIPv4() {
	var (
		prevent uint32
		current uint32
	)
	now := time.Now()
	nat.udpIPv4RWM.Lock()
	defer nat.udpIPv4RWM.Unlock()
	for ri, li := range nat.udpIPv4 {
		if now.Sub(li.createAt) < nat.mapTimeout {
			continue
		}
		prevent = atomic.LoadUint32(li.preCtr)
		current = atomic.LoadUint32(li.curCtr)
		if prevent != current {
			atomic.StoreUint32(li.preCtr, current)
			continue
		}
		nat.DeleteUDPIPv4Map(ri)
	}
}

func (nat *nat) cleanTCPIPv6() {
	var (
		prevent uint32
		current uint32
	)
	now := time.Now()
	nat.tcpIPv6RWM.Lock()
	defer nat.tcpIPv6RWM.Unlock()
	for ri, li := range nat.tcpIPv6 {
		if now.Sub(li.createAt) < nat.mapTimeout {
			continue
		}
		prevent = atomic.LoadUint32(li.preCtr)
		current = atomic.LoadUint32(li.curCtr)
		if prevent != current {
			atomic.StoreUint32(li.preCtr, current)
			continue
		}
		nat.DeleteTCPIPv6Map(ri)
	}
}

func (nat *nat) cleanUDPIPv6() {
	var (
		prevent uint32
		current uint32
	)
	now := time.Now()
	nat.udpIPv6RWM.Lock()
	defer nat.udpIPv6RWM.Unlock()
	for ri, li := range nat.udpIPv6 {
		if now.Sub(li.createAt) < nat.mapTimeout {
			continue
		}
		prevent = atomic.LoadUint32(li.preCtr)
		current = atomic.LoadUint32(li.curCtr)
		if prevent != current {
			atomic.StoreUint32(li.preCtr, current)
			continue
		}
		nat.DeleteUDPIPv6Map(ri)
	}
}

func (nat *nat) Close() {
	nat.cancel()
	nat.wg.Wait()
}
