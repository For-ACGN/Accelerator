package accelerator

import (
	"context"
	"encoding/binary"
	"math/rand"
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

	ipv4TCP    map[ipv4RI]*ipv4LI
	ipv4TCPRWM sync.RWMutex
	ipv4UDP    map[ipv4RI]*ipv4LI
	ipv4UDPRWM sync.RWMutex

	ipv6TCP    map[ipv6RI]*ipv6LI
	ipv6TCPRWM sync.RWMutex
	ipv6UDP    map[ipv6RI]*ipv6LI
	ipv6UDPRWM sync.RWMutex

	rand   *rand.Rand
	randMu sync.Mutex

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
		ipv4TCP:     make(map[ipv4RI]*ipv4LI, 512),
		ipv4UDP:     make(map[ipv4RI]*ipv4LI, 512),
		ipv6TCP:     make(map[ipv6RI]*ipv6LI, 512),
		ipv6UDP:     make(map[ipv6RI]*ipv6LI, 512),
		rand:        rand.New(rand.NewSource(time.Now().UnixNano())), // #nosec
	}
	n.ctx, n.cancel = context.WithCancel(context.Background())
	return &n, nil
}

func (nat *nat) Run() {
	nat.wg.Add(1)
	go nat.cleaner()
}

func (nat *nat) AddIPv4TCPMap(rIP net.IP, rPort uint16, lIP net.IP, lPort uint16) {
	ri := ipv4RI{}
	copy(ri.remoteIP[:], rIP)
	binary.BigEndian.PutUint16(ri.remotePort[:], rPort)
	li := &ipv4LI{
		preCtr:   new(uint32),
		curCtr:   new(uint32),
		createAt: time.Now(),
	}
	copy(li.localIP[:], lIP)
	binary.BigEndian.PutUint16(li.localPort[:], lPort)
	nat.ipv4TCPRWM.Lock()
	defer nat.ipv4TCPRWM.Unlock()
	// try to get random port
	var ok bool
	for i := 0; i < 256; i++ {
		p := nat.selectRandomIPv4TCPPort()
		binary.BigEndian.PutUint16(ri.natPort[:], p)
		_, ok = nat.ipv4TCP[ri]
		if ok {
			continue
		}
		nat.ipv4TCP[ri] = li
		return
	}
	// check all ports
	for p := 1025; p < 65536; p++ {
		binary.BigEndian.PutUint16(ri.natPort[:], uint16(p))
		_, ok = nat.ipv4TCP[ri]
		if ok {
			continue
		}
		nat.ipv4TCP[ri] = li
		return
	}
}

func (nat *nat) AddIPv4UDPMap(rIP net.IP, rPort uint16, lIP net.IP, lPort uint16) {
	ri := ipv4RI{}
	copy(ri.remoteIP[:], rIP)
	binary.BigEndian.PutUint16(ri.remotePort[:], rPort)
	li := &ipv4LI{
		preCtr:   new(uint32),
		curCtr:   new(uint32),
		createAt: time.Now(),
	}
	copy(li.localIP[:], lIP)
	binary.BigEndian.PutUint16(li.localPort[:], lPort)
	nat.ipv4UDPRWM.Lock()
	defer nat.ipv4UDPRWM.Unlock()
	// try to get random port
	var ok bool
	for i := 0; i < 256; i++ {
		p := nat.selectRandomIPv4UDPPort()
		binary.BigEndian.PutUint16(ri.natPort[:], p)
		_, ok = nat.ipv4UDP[ri]
		if ok {
			continue
		}
		nat.ipv4UDP[ri] = li
		return
	}
	// check all ports
	for p := 1025; p < 65536; p++ {
		binary.BigEndian.PutUint16(ri.natPort[:], uint16(p))
		_, ok = nat.ipv4UDP[ri]
		if ok {
			continue
		}
		nat.ipv4UDP[ri] = li
		return
	}
}

func (nat *nat) AddIPv6TCPMap(rIP net.IP, rPort uint16, lIP net.IP, lPort uint16) {
	ri := ipv6RI{}
	copy(ri.remoteIP[:], rIP)
	binary.BigEndian.PutUint16(ri.remotePort[:], rPort)
	li := &ipv6LI{
		preCtr:   new(uint32),
		curCtr:   new(uint32),
		createAt: time.Now(),
	}
	copy(li.localIP[:], lIP)
	binary.BigEndian.PutUint16(li.localPort[:], lPort)
	nat.ipv6TCPRWM.Lock()
	defer nat.ipv6TCPRWM.Unlock()
	// try to get random port
	var ok bool
	for i := 0; i < 256; i++ {
		p := nat.selectRandomIPv6TCPPort()
		binary.BigEndian.PutUint16(ri.natPort[:], p)
		_, ok = nat.ipv6TCP[ri]
		if ok {
			continue
		}
		nat.ipv6TCP[ri] = li
		return
	}
	// check all ports
	for p := 1025; p < 65536; p++ {
		binary.BigEndian.PutUint16(ri.natPort[:], uint16(p))
		_, ok = nat.ipv6TCP[ri]
		if ok {
			continue
		}
		nat.ipv6TCP[ri] = li
		return
	}
}

func (nat *nat) AddIPv6UDPMap(rIP net.IP, rPort uint16, lIP net.IP, lPort uint16) {
	ri := ipv6RI{}
	copy(ri.remoteIP[:], rIP)
	binary.BigEndian.PutUint16(ri.remotePort[:], rPort)
	li := &ipv6LI{
		preCtr:   new(uint32),
		curCtr:   new(uint32),
		createAt: time.Now(),
	}
	copy(li.localIP[:], lIP)
	binary.BigEndian.PutUint16(li.localPort[:], lPort)
	nat.ipv6UDPRWM.Lock()
	defer nat.ipv6UDPRWM.Unlock()
	// try to get random port
	var ok bool
	for i := 0; i < 256; i++ {
		p := nat.selectRandomIPv6UDPPort()
		binary.BigEndian.PutUint16(ri.natPort[:], p)
		_, ok = nat.ipv6UDP[ri]
		if ok {
			continue
		}
		nat.ipv6UDP[ri] = li
		return
	}
	// check all ports
	for p := 1025; p < 65536; p++ {
		binary.BigEndian.PutUint16(ri.natPort[:], uint16(p))
		_, ok = nat.ipv6UDP[ri]
		if ok {
			continue
		}
		nat.ipv6UDP[ri] = li
		return
	}
}

func (nat *nat) DeleteIPv4TCPMap(ri ipv4RI) {
	nat.ipv4TCPRWM.Lock()
	defer nat.ipv4TCPRWM.Unlock()
	delete(nat.ipv4TCP, ri)
}

func (nat *nat) DeleteIPv4UDPMap(ri ipv4RI) {
	nat.ipv4UDPRWM.Lock()
	defer nat.ipv4UDPRWM.Unlock()
	delete(nat.ipv4UDP, ri)
}

func (nat *nat) DeleteIPv6TCPMap(ri ipv6RI) {
	nat.ipv6TCPRWM.Lock()
	defer nat.ipv6TCPRWM.Unlock()
	delete(nat.ipv6TCP, ri)
}

func (nat *nat) DeleteIPv6UDPMap(ri ipv6RI) {
	nat.ipv6UDPRWM.Lock()
	defer nat.ipv6UDPRWM.Unlock()
	delete(nat.ipv6UDP, ri)
}

func (nat *nat) selectRandomIPv4TCPPort() uint16 {
	return nat.selectRandomPort()
}

func (nat *nat) selectRandomIPv4UDPPort() uint16 {
	return nat.selectRandomPort()
}

func (nat *nat) selectRandomIPv6TCPPort() uint16 {
	return nat.selectRandomPort()
}

func (nat *nat) selectRandomIPv6UDPPort() uint16 {
	return nat.selectRandomPort()
}

func (nat *nat) selectRandomPort() uint16 {
	nat.randMu.Lock()
	defer nat.randMu.Unlock()
	return 1025 + uint16(nat.rand.Intn(65536-1025))
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
		nat.cleanIPv4TCP()
		nat.cleanIPv4UDP()
	}
	if nat.gatewayIPv6 != nil {
		nat.cleanIPv6TCP()
		nat.cleanIPv6UDP()
	}
}

func (nat *nat) cleanIPv4TCP() {
	var (
		prevent uint32
		current uint32
	)
	now := time.Now()
	nat.ipv4TCPRWM.Lock()
	defer nat.ipv4TCPRWM.Unlock()
	for ri, li := range nat.ipv4TCP {
		if now.Sub(li.createAt) < nat.mapTimeout {
			continue
		}
		prevent = atomic.LoadUint32(li.preCtr)
		current = atomic.LoadUint32(li.curCtr)
		if prevent != current {
			atomic.StoreUint32(li.preCtr, current)
			continue
		}
		nat.DeleteIPv4TCPMap(ri)
	}
}

func (nat *nat) cleanIPv4UDP() {
	var (
		prevent uint32
		current uint32
	)
	now := time.Now()
	nat.ipv4UDPRWM.Lock()
	defer nat.ipv4UDPRWM.Unlock()
	for ri, li := range nat.ipv4UDP {
		if now.Sub(li.createAt) < nat.mapTimeout {
			continue
		}
		prevent = atomic.LoadUint32(li.preCtr)
		current = atomic.LoadUint32(li.curCtr)
		if prevent != current {
			atomic.StoreUint32(li.preCtr, current)
			continue
		}
		nat.DeleteIPv4UDPMap(ri)
	}
}

func (nat *nat) cleanIPv6TCP() {
	var (
		prevent uint32
		current uint32
	)
	now := time.Now()
	nat.ipv6TCPRWM.Lock()
	defer nat.ipv6TCPRWM.Unlock()
	for ri, li := range nat.ipv6TCP {
		if now.Sub(li.createAt) < nat.mapTimeout {
			continue
		}
		prevent = atomic.LoadUint32(li.preCtr)
		current = atomic.LoadUint32(li.curCtr)
		if prevent != current {
			atomic.StoreUint32(li.preCtr, current)
			continue
		}
		nat.DeleteIPv6TCPMap(ri)
	}
}

func (nat *nat) cleanIPv6UDP() {
	var (
		prevent uint32
		current uint32
	)
	now := time.Now()
	nat.ipv6UDPRWM.Lock()
	defer nat.ipv6UDPRWM.Unlock()
	for ri, li := range nat.ipv6UDP {
		if now.Sub(li.createAt) < nat.mapTimeout {
			continue
		}
		prevent = atomic.LoadUint32(li.preCtr)
		current = atomic.LoadUint32(li.curCtr)
		if prevent != current {
			atomic.StoreUint32(li.preCtr, current)
			continue
		}
		nat.DeleteIPv6UDPMap(ri)
	}
}

func (nat *nat) Close() {
	nat.cancel()
	nat.wg.Wait()
}
