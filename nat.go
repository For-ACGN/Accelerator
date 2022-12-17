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

const minNATMapTimeout = 30 * time.Second

// PM is used to find NAT local port for send data
// LI and RI is used to find internal client local
// IP address and port for receive data.

type ipv4PM struct {
	localIP    ipv4
	localPort  port
	remoteIP   ipv4
	remotePort port
}

type ipv4LI struct {
	localIP   ipv4
	localPort port
	preCtr    *uint32
	curCtr    *uint32
	createAt  time.Time
}

type ipv4RI struct {
	remoteIP   ipv4
	remotePort port
	natPort    port
}

type ipv6PM struct {
	localIP    ipv6
	localPort  port
	remoteIP   ipv6
	remotePort port
}

type ipv6LI struct {
	localIP   ipv6
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

type nat struct {
	logger *logger

	gatewayMAC  net.HardwareAddr
	gatewayIPv4 net.IP
	gatewayIPv6 net.IP
	mapTimeout  time.Duration

	ipv4TCPPM  map[ipv4PM]uint16
	ipv4TCPRL  map[ipv4RI]*ipv4LI
	ipv4TCPRWM sync.RWMutex

	ipv4UDPPM  map[ipv4PM]uint16
	ipv4UDPRL  map[ipv4RI]*ipv4LI
	ipv4UDPRWM sync.RWMutex

	ipv6TCPPM  map[ipv6PM]uint16
	ipv6TCPRL  map[ipv6RI]*ipv6LI
	ipv6TCPRWM sync.RWMutex

	ipv6UDPPM  map[ipv6PM]uint16
	ipv6UDPRL  map[ipv6RI]*ipv6LI
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
	if mapTimeout < minNATMapTimeout {
		mapTimeout = minNATMapTimeout
	}
	rd := rand.New(rand.NewSource(time.Now().UnixNano())) // #nosec
	n := nat{
		logger:      lg,
		gatewayMAC:  gatewayMAC,
		gatewayIPv4: gatewayIPv4,
		gatewayIPv6: gatewayIPv6,
		mapTimeout:  mapTimeout,
		ipv4TCPPM:   make(map[ipv4PM]uint16, 512),
		ipv4TCPRL:   make(map[ipv4RI]*ipv4LI, 512),
		ipv4UDPPM:   make(map[ipv4PM]uint16, 512),
		ipv4UDPRL:   make(map[ipv4RI]*ipv4LI, 512),
		ipv6TCPPM:   make(map[ipv6PM]uint16, 512),
		ipv6TCPRL:   make(map[ipv6RI]*ipv6LI, 512),
		ipv6UDPPM:   make(map[ipv6PM]uint16, 512),
		ipv6UDPRL:   make(map[ipv6RI]*ipv6LI, 512),
		rand:        rd,
	}
	n.ctx, n.cancel = context.WithCancel(context.Background())
	return &n, nil
}

func (nat *nat) Run() {
	nat.wg.Add(1)
	go nat.cleaner()
}

func (nat *nat) AddIPv4TCPMap(rIP net.IP, rPort uint16, lIP net.IP, lPort uint16) uint16 {
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
		p := nat.generateRandomPortIPv4TCPPort()
		binary.BigEndian.PutUint16(ri.natPort[:], p)
		_, ok = nat.ipv4TCPRL[ri]
		if ok {
			continue
		}
		nat.ipv4TCPRL[ri] = li
		return p
	}
	// check all ports
	for i := 1025; i < 65536; i++ {
		p := uint16(i)
		binary.BigEndian.PutUint16(ri.natPort[:], p)
		_, ok = nat.ipv4TCPRL[ri]
		if ok {
			continue
		}
		nat.ipv4TCPRL[ri] = li
		return p
	}
	return 0
}

func (nat *nat) AddIPv4UDPMap(rIP net.IP, rPort uint16, lIP net.IP, lPort uint16) uint16 {
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
		p := nat.generateRandomPortIPv4UDPPort()
		binary.BigEndian.PutUint16(ri.natPort[:], p)
		_, ok = nat.ipv4UDPRL[ri]
		if ok {
			continue
		}
		nat.ipv4UDPRL[ri] = li
		return p
	}
	// check all ports
	for i := 1025; i < 65536; i++ {
		p := uint16(i)
		binary.BigEndian.PutUint16(ri.natPort[:], p)
		_, ok = nat.ipv4UDPRL[ri]
		if ok {
			continue
		}
		nat.ipv4UDPRL[ri] = li
		return p
	}
	return 0
}

func (nat *nat) AddIPv6TCPMap(rIP net.IP, rPort uint16, lIP net.IP, lPort uint16) uint16 {
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
		p := nat.generateRandomPortIPv6TCPPort()
		binary.BigEndian.PutUint16(ri.natPort[:], p)
		_, ok = nat.ipv6TCPRL[ri]
		if ok {
			continue
		}
		nat.ipv6TCPRL[ri] = li
		return p
	}
	// check all ports
	for i := 1025; i < 65536; i++ {
		p := uint16(i)
		binary.BigEndian.PutUint16(ri.natPort[:], p)
		_, ok = nat.ipv6TCPRL[ri]
		if ok {
			continue
		}
		nat.ipv6TCPRL[ri] = li
		return p
	}
	return 0
}

func (nat *nat) AddIPv6UDPMap(rIP net.IP, rPort uint16, lIP net.IP, lPort uint16) uint16 {
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
		p := nat.generateRandomPortIPv6UDPPort()
		binary.BigEndian.PutUint16(ri.natPort[:], p)
		_, ok = nat.ipv6UDPRL[ri]
		if ok {
			continue
		}
		nat.ipv6UDPRL[ri] = li
		return p
	}
	// check all ports
	for i := 1025; i < 65536; i++ {
		p := uint16(i)
		binary.BigEndian.PutUint16(ri.natPort[:], p)
		_, ok = nat.ipv6UDPRL[ri]
		if ok {
			continue
		}
		nat.ipv6UDPRL[ri] = li
		return p
	}
	return 0
}

func (nat *nat) DeleteIPv4TCPMap(ri ipv4RI) {
	nat.ipv4TCPRWM.Lock()
	defer nat.ipv4TCPRWM.Unlock()
	delete(nat.ipv4TCPRL, ri)
}

func (nat *nat) DeleteIPv4UDPMap(ri ipv4RI) {
	nat.ipv4UDPRWM.Lock()
	defer nat.ipv4UDPRWM.Unlock()
	delete(nat.ipv4UDPRL, ri)
}

func (nat *nat) DeleteIPv6TCPMap(ri ipv6RI) {
	nat.ipv6TCPRWM.Lock()
	defer nat.ipv6TCPRWM.Unlock()
	delete(nat.ipv6TCPRL, ri)
}

func (nat *nat) DeleteIPv6UDPMap(ri ipv6RI) {
	nat.ipv6UDPRWM.Lock()
	defer nat.ipv6UDPRWM.Unlock()
	delete(nat.ipv6UDPRL, ri)
}

func (nat *nat) generateRandomPortIPv4TCPPort() uint16 {
	return nat.generateRandomPortPort()
}

func (nat *nat) generateRandomPortIPv4UDPPort() uint16 {
	return nat.generateRandomPortPort()
}

func (nat *nat) generateRandomPortIPv6TCPPort() uint16 {
	return nat.generateRandomPortPort()
}

func (nat *nat) generateRandomPortIPv6UDPPort() uint16 {
	return nat.generateRandomPortPort()
}

func (nat *nat) generateRandomPortPort() uint16 {
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
	for ri, li := range nat.ipv4TCPRL {
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
	for ri, li := range nat.ipv4UDPRL {
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
	for ri, li := range nat.ipv6TCPRL {
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
	for ri, li := range nat.ipv6UDPRL {
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
