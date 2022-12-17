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

	ipv4    map[ipv4RI]*ipv4LI
	ipv4RWM sync.RWMutex
	ipv6    map[ipv6RI]*ipv6LI
	ipv6RWM sync.RWMutex

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
		ipv4:        make(map[ipv4RI]*ipv4LI, 512),
		ipv6:        make(map[ipv6RI]*ipv6LI, 512),
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
		nat.cleanIPv4()
	}
	if nat.gatewayIPv6 != nil {
		nat.cleanIPv6()
	}
}

func (nat *nat) cleanIPv4() {
	var (
		prevent uint32
		current uint32
	)
	now := time.Now()
	nat.ipv4RWM.Lock()
	defer nat.ipv4RWM.Unlock()
	for _, item := range nat.ipv4 {
		if now.Sub(item.createAt) < nat.mapTimeout {
			continue
		}
		prevent = atomic.LoadUint32(item.preCtr)
		current = atomic.LoadUint32(item.curCtr)
		if prevent == current {

		}

	}

}

func (nat *nat) cleanIPv6() {
	nat.ipv6RWM.Lock()
	defer nat.ipv6RWM.Unlock()
}

func (nat *nat) Close() {
	nat.cancel()
	nat.wg.Wait()
}
