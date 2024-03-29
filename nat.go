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

const minNATMapTimeout = 3 * time.Minute

type port = [2]byte
type icmpID = [2]byte

// PM and PI are used to find NAT local port for send data.
// LI and RI are used to find internal client local IP address
// and port for receive data.

type ipv4PM struct {
	localIP    ipv4
	localPort  port
	remoteIP   ipv4
	remotePort port
}

type ipv4PI struct {
	natPort uint16
	curCtr  *uint32
}

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

type icmpv4PM struct {
	localIP  ipv4
	localID  icmpID
	remoteIP ipv4
}

type icmpv4PI struct {
	natID  uint16
	curCtr *uint32
}

type icmpv4RI struct {
	remoteIP ipv4
	natID    icmpID
}

type icmpv4LI struct {
	localIP  ipv4
	localID  icmpID
	preCtr   *uint32
	curCtr   *uint32
	createAt time.Time
}

type ipv6PM struct {
	localIP    ipv6
	localPort  port
	remoteIP   ipv6
	remotePort port
}

type ipv6PI struct {
	natPort uint16
	curCtr  *uint32
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

type icmpv6PM struct {
	localIP  ipv6
	localID  icmpID
	remoteIP ipv6
}

type icmpv6PI struct {
	natID  uint16
	curCtr *uint32
}

type icmpv6RI struct {
	remoteIP ipv6
	natID    icmpID
}

type icmpv6LI struct {
	localIP  ipv6
	localID  icmpID
	preCtr   *uint32
	curCtr   *uint32
	createAt time.Time
}

type nat struct {
	logger *logger

	mapTimeout time.Duration
	enableIPv4 bool
	enableIPv6 bool

	localMAC    net.HardwareAddr
	gatewayMAC  net.HardwareAddr
	localIPv4   net.IP
	gatewayIPv4 net.IP
	localIPv6   net.IP
	gatewayIPv6 net.IP

	ipv4TCPPM  map[ipv4PM]*ipv4PI
	ipv4TCPRL  map[ipv4RI]*ipv4LI
	ipv4TCPRWM sync.RWMutex

	ipv4UDPPM  map[ipv4PM]*ipv4PI
	ipv4UDPRL  map[ipv4RI]*ipv4LI
	ipv4UDPRWM sync.RWMutex

	icmpv4PM  map[icmpv4PM]*icmpv4PI
	icmpv4RL  map[icmpv4RI]*icmpv4LI
	icmpv4RWM sync.RWMutex

	ipv6TCPPM  map[ipv6PM]*ipv6PI
	ipv6TCPRL  map[ipv6RI]*ipv6LI
	ipv6TCPRWM sync.RWMutex

	ipv6UDPPM  map[ipv6PM]*ipv6PI
	ipv6UDPRL  map[ipv6RI]*ipv6LI
	ipv6UDPRWM sync.RWMutex

	icmpv6PM  map[icmpv6PM]*icmpv6PI
	icmpv6RL  map[icmpv6RI]*icmpv6LI
	icmpv6RWM sync.RWMutex

	rand   *rand.Rand
	randMu sync.Mutex

	ipv4PMCache   sync.Pool
	ipv4RICache   sync.Pool
	icmpv4PMCache sync.Pool
	icmpv4RICache sync.Pool
	ipv6PMCache   sync.Pool
	ipv6RICache   sync.Pool
	icmpv6PMCache sync.Pool
	icmpv6RICache sync.Pool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newNAT(lg *logger, cfg *ServerConfig) (*nat, error) {
	var (
		localMAC     net.HardwareAddr
		gatewayMAC   net.HardwareAddr
		localIPv4    net.IP
		gatewayIPv4  net.IP
		localIPv6    net.IP
		gatewayIPv6  net.IP
		hasGatewayIP bool
		err          error
	)
	nc := cfg.NAT
	mapTimeout := time.Duration(nc.Timeout)
	if mapTimeout < minNATMapTimeout {
		mapTimeout = minNATMapTimeout
	}
	localMAC, err = net.ParseMAC(nc.MAC.Local)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse NAT local MAC address")
	}
	if len(localMAC) != 6 {
		return nil, errors.New("invalid NAT local MAC address")
	}
	gatewayMAC, err = net.ParseMAC(nc.MAC.Gateway)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse NAT gateway MAC address")
	}
	if len(gatewayMAC) != 6 {
		return nil, errors.New("invalid NAT gateway MAC address")
	}
	if nc.IPv4.Enabled {
		ip := net.ParseIP(nc.IPv4.Local)
		if ip.To4() == nil {
			return nil, errors.Wrap(err, "invalid NAT local IPv4 address")
		}
		localIPv4 = ip.To4()
		ip = net.ParseIP(nc.IPv4.Gateway)
		if ip.To4() == nil {
			return nil, errors.Wrap(err, "invalid NAT gateway IPv4 address")
		}
		gatewayIPv4 = ip.To4()
		hasGatewayIP = true
	}
	if nc.IPv6.Enabled {
		ip := net.ParseIP(nc.IPv6.Local)
		if !(ip.To4() == nil && ip.To16() != nil) {
			return nil, errors.Wrap(err, "invalid NAT local IPv6 address")
		}
		localIPv6 = ip.To16()
		ip = net.ParseIP(nc.IPv6.Gateway)
		if !(ip.To4() == nil && ip.To16() != nil) {
			return nil, errors.Wrap(err, "invalid NAT gateway IPv6 address")
		}
		gatewayIPv6 = ip.To16()
		hasGatewayIP = true
	}
	if !hasGatewayIP {
		return nil, errors.New("empty NAT gateway IP address")
	}
	rd := rand.New(rand.NewSource(time.Now().UnixNano())) // #nosec
	n := nat{
		logger:      lg,
		mapTimeout:  mapTimeout,
		enableIPv4:  nc.IPv4.Enabled,
		enableIPv6:  nc.IPv6.Enabled,
		localMAC:    localMAC,
		gatewayMAC:  gatewayMAC,
		localIPv4:   localIPv4,
		gatewayIPv4: gatewayIPv4,
		localIPv6:   localIPv6,
		gatewayIPv6: gatewayIPv6,
		ipv4TCPPM:   make(map[ipv4PM]*ipv4PI, 512),
		ipv4TCPRL:   make(map[ipv4RI]*ipv4LI, 512),
		ipv4UDPPM:   make(map[ipv4PM]*ipv4PI, 512),
		ipv4UDPRL:   make(map[ipv4RI]*ipv4LI, 512),
		icmpv4PM:    make(map[icmpv4PM]*icmpv4PI, 512),
		icmpv4RL:    make(map[icmpv4RI]*icmpv4LI, 512),
		ipv6TCPPM:   make(map[ipv6PM]*ipv6PI, 512),
		ipv6TCPRL:   make(map[ipv6RI]*ipv6LI, 512),
		ipv6UDPPM:   make(map[ipv6PM]*ipv6PI, 512),
		ipv6UDPRL:   make(map[ipv6RI]*ipv6LI, 512),
		icmpv6PM:    make(map[icmpv6PM]*icmpv6PI, 512),
		icmpv6RL:    make(map[icmpv6RI]*icmpv6LI, 512),
		rand:        rd,
	}
	n.ipv4PMCache.New = func() interface{} {
		return new(ipv4PM)
	}
	n.ipv4RICache.New = func() interface{} {
		return new(ipv4RI)
	}
	n.icmpv4PMCache.New = func() interface{} {
		return new(icmpv4PM)
	}
	n.icmpv4RICache.New = func() interface{} {
		return new(icmpv4RI)
	}
	n.ipv6PMCache.New = func() interface{} {
		return new(ipv6PM)
	}
	n.ipv6RICache.New = func() interface{} {
		return new(ipv6RI)
	}
	n.icmpv6PMCache.New = func() interface{} {
		return new(icmpv6PM)
	}
	n.icmpv6RICache.New = func() interface{} {
		return new(icmpv6RI)
	}
	n.ctx, n.cancel = context.WithCancel(context.Background())
	return &n, nil
}

func (nat *nat) Run() {
	nat.wg.Add(1)
	go nat.cleaner()
}

func (nat *nat) AddIPv4TCPPortMap(lIP net.IP, lPort uint16, rIP net.IP, rPort uint16) uint16 {
	// check is create port map
	pm := nat.ipv4PMCache.Get().(*ipv4PM)
	defer nat.ipv4PMCache.Put(pm)
	copy(pm.localIP[:], lIP)
	binary.BigEndian.PutUint16(pm.localPort[:], lPort)
	copy(pm.remoteIP[:], rIP)
	binary.BigEndian.PutUint16(pm.remotePort[:], rPort)
	nat.ipv4TCPRWM.Lock()
	defer nat.ipv4TCPRWM.Unlock()
	pi, ok := nat.ipv4TCPPM[*pm]
	if ok {
		atomic.AddUint32(pi.curCtr, 1)
		return pi.natPort
	}
	// create new port map
	li := &ipv4LI{
		preCtr:   new(uint32),
		curCtr:   new(uint32),
		createAt: time.Now(),
	}
	copy(li.localIP[:], lIP)
	binary.BigEndian.PutUint16(li.localPort[:], lPort)
	ri := ipv4RI{}
	copy(ri.remoteIP[:], rIP)
	binary.BigEndian.PutUint16(ri.remotePort[:], rPort)
	// try to get random port
	var p uint16
	for i := 0; i < 256; i++ {
		p = nat.generateRandomIPv4TCPPort()
		binary.BigEndian.PutUint16(ri.natPort[:], p)
		_, ok = nat.ipv4TCPRL[ri]
		if ok {
			continue
		}
		nat.ipv4TCPPM[*pm] = &ipv4PI{
			natPort: p,
			curCtr:  li.curCtr,
		}
		nat.ipv4TCPRL[ri] = li
		return p
	}
	// check all ports
	for i := 1025; i < 65536; i++ {
		p = uint16(i)
		binary.BigEndian.PutUint16(ri.natPort[:], p)
		_, ok = nat.ipv4TCPRL[ri]
		if ok {
			continue
		}
		nat.ipv4TCPPM[*pm] = &ipv4PI{
			natPort: p,
			curCtr:  li.curCtr,
		}
		nat.ipv4TCPRL[ri] = li
		return p
	}
	return 0
}

func (nat *nat) AddIPv4UDPPortMap(lIP net.IP, lPort uint16, rIP net.IP, rPort uint16) uint16 {
	// check is create port map
	pm := nat.ipv4PMCache.Get().(*ipv4PM)
	defer nat.ipv4PMCache.Put(pm)
	copy(pm.localIP[:], lIP)
	binary.BigEndian.PutUint16(pm.localPort[:], lPort)
	copy(pm.remoteIP[:], rIP)
	binary.BigEndian.PutUint16(pm.remotePort[:], rPort)
	nat.ipv4UDPRWM.Lock()
	defer nat.ipv4UDPRWM.Unlock()
	pi, ok := nat.ipv4UDPPM[*pm]
	if ok {
		atomic.AddUint32(pi.curCtr, 1)
		return pi.natPort
	}
	// create new port map
	li := &ipv4LI{
		preCtr:   new(uint32),
		curCtr:   new(uint32),
		createAt: time.Now(),
	}
	copy(li.localIP[:], lIP)
	binary.BigEndian.PutUint16(li.localPort[:], lPort)
	ri := ipv4RI{}
	copy(ri.remoteIP[:], rIP)
	binary.BigEndian.PutUint16(ri.remotePort[:], rPort)
	// try to get random port
	var p uint16
	for i := 0; i < 256; i++ {
		p = nat.generateRandomIPv4UDPPort()
		binary.BigEndian.PutUint16(ri.natPort[:], p)
		_, ok = nat.ipv4UDPRL[ri]
		if ok {
			continue
		}
		nat.ipv4UDPPM[*pm] = &ipv4PI{
			natPort: p,
			curCtr:  li.curCtr,
		}
		nat.ipv4UDPRL[ri] = li
		return p
	}
	// check all ports
	for i := 1025; i < 65536; i++ {
		p = uint16(i)
		binary.BigEndian.PutUint16(ri.natPort[:], p)
		_, ok = nat.ipv4UDPRL[ri]
		if ok {
			continue
		}
		nat.ipv4UDPPM[*pm] = &ipv4PI{
			natPort: p,
			curCtr:  li.curCtr,
		}
		nat.ipv4UDPRL[ri] = li
		return p
	}
	return 0
}

func (nat *nat) AddICMPv4IDMap(lIP net.IP, lID uint16, rIP net.IP) uint16 {
	// check is create id map
	pm := nat.icmpv4PMCache.Get().(*icmpv4PM)
	defer nat.icmpv4PMCache.Put(pm)
	copy(pm.localIP[:], lIP)
	binary.BigEndian.PutUint16(pm.localID[:], lID)
	copy(pm.remoteIP[:], rIP)
	nat.icmpv4RWM.Lock()
	defer nat.icmpv4RWM.Unlock()
	pi, ok := nat.icmpv4PM[*pm]
	if ok {
		atomic.AddUint32(pi.curCtr, 1)
		return pi.natID
	}
	// create new id map
	li := &icmpv4LI{
		preCtr:   new(uint32),
		curCtr:   new(uint32),
		createAt: time.Now(),
	}
	copy(li.localIP[:], lIP)
	binary.BigEndian.PutUint16(li.localID[:], lID)
	ri := icmpv4RI{}
	copy(ri.remoteIP[:], rIP)
	// try to get random id
	var id uint16
	for i := 0; i < 256; i++ {
		id = nat.generateRandomICMPv4ID()
		binary.BigEndian.PutUint16(ri.natID[:], id)
		_, ok = nat.icmpv4RL[ri]
		if ok {
			continue
		}
		nat.icmpv4PM[*pm] = &icmpv4PI{
			natID:  id,
			curCtr: li.curCtr,
		}
		nat.icmpv4RL[ri] = li
		return id
	}
	// check all id
	for i := 0; i < 65536; i++ {
		id = uint16(i)
		binary.BigEndian.PutUint16(ri.natID[:], id)
		_, ok = nat.icmpv4RL[ri]
		if ok {
			continue
		}
		nat.icmpv4PM[*pm] = &icmpv4PI{
			natID:  id,
			curCtr: li.curCtr,
		}
		nat.icmpv4RL[ri] = li
		return id
	}
	return 0
}

func (nat *nat) AddIPv6TCPPortMap(lIP net.IP, lPort uint16, rIP net.IP, rPort uint16) uint16 {
	// check is create port map
	pm := nat.ipv6PMCache.Get().(*ipv6PM)
	defer nat.ipv6PMCache.Put(pm)
	copy(pm.localIP[:], lIP)
	binary.BigEndian.PutUint16(pm.localPort[:], lPort)
	copy(pm.remoteIP[:], rIP)
	binary.BigEndian.PutUint16(pm.remotePort[:], rPort)
	nat.ipv6TCPRWM.Lock()
	defer nat.ipv6TCPRWM.Unlock()
	pi, ok := nat.ipv6TCPPM[*pm]
	if ok {
		atomic.AddUint32(pi.curCtr, 1)
		return pi.natPort
	}
	// create new port map
	li := &ipv6LI{
		preCtr:   new(uint32),
		curCtr:   new(uint32),
		createAt: time.Now(),
	}
	copy(li.localIP[:], lIP)
	binary.BigEndian.PutUint16(li.localPort[:], lPort)
	ri := ipv6RI{}
	copy(ri.remoteIP[:], rIP)
	binary.BigEndian.PutUint16(ri.remotePort[:], rPort)
	// try to get random port
	var p uint16
	for i := 0; i < 256; i++ {
		p = nat.generateRandomIPv6TCPPort()
		binary.BigEndian.PutUint16(ri.natPort[:], p)
		_, ok = nat.ipv6TCPRL[ri]
		if ok {
			continue
		}
		nat.ipv6TCPPM[*pm] = &ipv6PI{
			natPort: p,
			curCtr:  li.curCtr,
		}
		nat.ipv6TCPRL[ri] = li
		return p
	}
	// check all ports
	for i := 1025; i < 65536; i++ {
		p = uint16(i)
		binary.BigEndian.PutUint16(ri.natPort[:], p)
		_, ok = nat.ipv6TCPRL[ri]
		if ok {
			continue
		}
		nat.ipv6TCPPM[*pm] = &ipv6PI{
			natPort: p,
			curCtr:  li.curCtr,
		}
		nat.ipv6TCPRL[ri] = li
		return p
	}
	return 0
}

func (nat *nat) AddIPv6UDPPortMap(lIP net.IP, lPort uint16, rIP net.IP, rPort uint16) uint16 {
	// check is create port map
	pm := nat.ipv6PMCache.Get().(*ipv6PM)
	defer nat.ipv6PMCache.Put(pm)
	copy(pm.localIP[:], lIP)
	binary.BigEndian.PutUint16(pm.localPort[:], lPort)
	copy(pm.remoteIP[:], rIP)
	binary.BigEndian.PutUint16(pm.remotePort[:], rPort)
	nat.ipv6UDPRWM.Lock()
	defer nat.ipv6UDPRWM.Unlock()
	pi, ok := nat.ipv6UDPPM[*pm]
	if ok {
		atomic.AddUint32(pi.curCtr, 1)
		return pi.natPort
	}
	// create new port map
	li := &ipv6LI{
		preCtr:   new(uint32),
		curCtr:   new(uint32),
		createAt: time.Now(),
	}
	copy(li.localIP[:], lIP)
	binary.BigEndian.PutUint16(li.localPort[:], lPort)
	ri := ipv6RI{}
	copy(ri.remoteIP[:], rIP)
	binary.BigEndian.PutUint16(ri.remotePort[:], rPort)
	// try to get random port
	var p uint16
	for i := 0; i < 256; i++ {
		p = nat.generateRandomIPv6UDPPort()
		binary.BigEndian.PutUint16(ri.natPort[:], p)
		_, ok = nat.ipv6UDPRL[ri]
		if ok {
			continue
		}
		nat.ipv6UDPPM[*pm] = &ipv6PI{
			natPort: p,
			curCtr:  li.curCtr,
		}
		nat.ipv6UDPRL[ri] = li
		return p
	}
	// check all ports
	for i := 1025; i < 65536; i++ {
		p = uint16(i)
		binary.BigEndian.PutUint16(ri.natPort[:], p)
		_, ok = nat.ipv6UDPRL[ri]
		if ok {
			continue
		}
		nat.ipv6UDPPM[*pm] = &ipv6PI{
			natPort: p,
			curCtr:  li.curCtr,
		}
		nat.ipv6UDPRL[ri] = li
		return p
	}
	return 0
}

func (nat *nat) AddICMPv6IDMap(lIP net.IP, lID uint16, rIP net.IP) uint16 {
	// check is create id map
	pm := nat.icmpv6PMCache.Get().(*icmpv6PM)
	defer nat.icmpv6PMCache.Put(pm)
	copy(pm.localIP[:], lIP)
	binary.BigEndian.PutUint16(pm.localID[:], lID)
	copy(pm.remoteIP[:], rIP)
	nat.icmpv6RWM.Lock()
	defer nat.icmpv6RWM.Unlock()
	pi, ok := nat.icmpv6PM[*pm]
	if ok {
		atomic.AddUint32(pi.curCtr, 1)
		return pi.natID
	}
	// create new id map
	li := &icmpv6LI{
		preCtr:   new(uint32),
		curCtr:   new(uint32),
		createAt: time.Now(),
	}
	copy(li.localIP[:], lIP)
	binary.BigEndian.PutUint16(li.localID[:], lID)
	ri := icmpv6RI{}
	copy(ri.remoteIP[:], rIP)
	// try to get random id
	var id uint16
	for i := 0; i < 256; i++ {
		id = nat.generateRandomICMPv6ID()
		binary.BigEndian.PutUint16(ri.natID[:], id)
		_, ok = nat.icmpv6RL[ri]
		if ok {
			continue
		}
		nat.icmpv6PM[*pm] = &icmpv6PI{
			natID:  id,
			curCtr: li.curCtr,
		}
		nat.icmpv6RL[ri] = li
		return id
	}
	// check all id
	for i := 0; i < 65536; i++ {
		id = uint16(i)
		binary.BigEndian.PutUint16(ri.natID[:], id)
		_, ok = nat.icmpv6RL[ri]
		if ok {
			continue
		}
		nat.icmpv6PM[*pm] = &icmpv6PI{
			natID:  id,
			curCtr: li.curCtr,
		}
		nat.icmpv6RL[ri] = li
		return id
	}
	return 0
}

func (nat *nat) QueryIPv4TCPPortMap(rIP net.IP, rPort, natPort uint16) *ipv4LI {
	ri := nat.ipv4RICache.Get().(*ipv4RI)
	defer nat.ipv4RICache.Put(ri)
	copy(ri.remoteIP[:], rIP)
	binary.BigEndian.PutUint16(ri.remotePort[:], rPort)
	binary.BigEndian.PutUint16(ri.natPort[:], natPort)
	nat.ipv4TCPRWM.RLock()
	defer nat.ipv4TCPRWM.RUnlock()
	li, ok := nat.ipv4TCPRL[*ri]
	if !ok {
		return nil
	}
	atomic.AddUint32(li.curCtr, 1)
	return li
}

func (nat *nat) QueryIPv4UDPPortMap(rIP net.IP, rPort, natPort uint16) *ipv4LI {
	ri := nat.ipv4RICache.Get().(*ipv4RI)
	defer nat.ipv4RICache.Put(ri)
	copy(ri.remoteIP[:], rIP)
	binary.BigEndian.PutUint16(ri.remotePort[:], rPort)
	binary.BigEndian.PutUint16(ri.natPort[:], natPort)
	nat.ipv4UDPRWM.RLock()
	defer nat.ipv4UDPRWM.RUnlock()
	li, ok := nat.ipv4UDPRL[*ri]
	if !ok {
		return nil
	}
	atomic.AddUint32(li.curCtr, 1)
	return li
}

func (nat *nat) QueryICMPv4IDMap(rIP net.IP, natID uint16) *icmpv4LI {
	ri := nat.icmpv4RICache.Get().(*icmpv4RI)
	defer nat.icmpv4RICache.Put(ri)
	copy(ri.remoteIP[:], rIP)
	binary.BigEndian.PutUint16(ri.natID[:], natID)
	nat.icmpv4RWM.RLock()
	defer nat.icmpv4RWM.RUnlock()
	li, ok := nat.icmpv4RL[*ri]
	if !ok {
		return nil
	}
	atomic.AddUint32(li.curCtr, 1)
	return li
}

func (nat *nat) QueryIPv6TCPPortMap(rIP net.IP, rPort, natPort uint16) *ipv6LI {
	ri := nat.ipv6RICache.Get().(*ipv6RI)
	defer nat.ipv6RICache.Put(ri)
	copy(ri.remoteIP[:], rIP)
	binary.BigEndian.PutUint16(ri.remotePort[:], rPort)
	binary.BigEndian.PutUint16(ri.natPort[:], natPort)
	nat.ipv6TCPRWM.RLock()
	defer nat.ipv6TCPRWM.RUnlock()
	li, ok := nat.ipv6TCPRL[*ri]
	if !ok {
		return nil
	}
	atomic.AddUint32(li.curCtr, 1)
	return li
}

func (nat *nat) QueryIPv6UDPPortMap(rIP net.IP, rPort, natPort uint16) *ipv6LI {
	ri := nat.ipv6RICache.Get().(*ipv6RI)
	defer nat.ipv6RICache.Put(ri)
	copy(ri.remoteIP[:], rIP)
	binary.BigEndian.PutUint16(ri.remotePort[:], rPort)
	binary.BigEndian.PutUint16(ri.natPort[:], natPort)
	nat.ipv6UDPRWM.RLock()
	defer nat.ipv6UDPRWM.RUnlock()
	li, ok := nat.ipv6UDPRL[*ri]
	if !ok {
		return nil
	}
	atomic.AddUint32(li.curCtr, 1)
	return li
}

func (nat *nat) QueryICMPv6IDMap(rIP net.IP, natID uint16) *icmpv6LI {
	ri := nat.icmpv6RICache.Get().(*icmpv6RI)
	defer nat.icmpv6RICache.Put(ri)
	copy(ri.remoteIP[:], rIP)
	binary.BigEndian.PutUint16(ri.natID[:], natID)
	nat.icmpv6RWM.RLock()
	defer nat.icmpv6RWM.RUnlock()
	li, ok := nat.icmpv6RL[*ri]
	if !ok {
		return nil
	}
	atomic.AddUint32(li.curCtr, 1)
	return li
}

func (nat *nat) deleteIPv4TCPPortMap(li *ipv4LI, ri ipv4RI) {
	pm := ipv4PM{
		localIP:    li.localIP,
		localPort:  li.localPort,
		remoteIP:   ri.remoteIP,
		remotePort: ri.remotePort,
	}
	delete(nat.ipv4TCPPM, pm)
	delete(nat.ipv4TCPRL, ri)
}

func (nat *nat) deleteIPv4UDPPortMap(li *ipv4LI, ri ipv4RI) {
	pm := ipv4PM{
		localIP:    li.localIP,
		localPort:  li.localPort,
		remoteIP:   ri.remoteIP,
		remotePort: ri.remotePort,
	}
	delete(nat.ipv4UDPPM, pm)
	delete(nat.ipv4UDPRL, ri)
}

func (nat *nat) deleteICMPv4IDMap(li *icmpv4LI, ri icmpv4RI) {
	pm := icmpv4PM{
		localIP:  li.localIP,
		localID:  li.localID,
		remoteIP: ri.remoteIP,
	}
	delete(nat.icmpv4PM, pm)
	delete(nat.icmpv4RL, ri)
}

func (nat *nat) deleteIPv6TCPPortMap(li *ipv6LI, ri ipv6RI) {
	pm := ipv6PM{
		localIP:    li.localIP,
		localPort:  li.localPort,
		remoteIP:   ri.remoteIP,
		remotePort: ri.remotePort,
	}
	delete(nat.ipv6TCPPM, pm)
	delete(nat.ipv6TCPRL, ri)
}

func (nat *nat) deleteIPv6UDPPortMap(li *ipv6LI, ri ipv6RI) {
	pm := ipv6PM{
		localIP:    li.localIP,
		localPort:  li.localPort,
		remoteIP:   ri.remoteIP,
		remotePort: ri.remotePort,
	}
	delete(nat.ipv6UDPPM, pm)
	delete(nat.ipv6UDPRL, ri)
}

func (nat *nat) deleteICMPv6IDMap(li *icmpv6LI, ri icmpv6RI) {
	pm := icmpv6PM{
		localIP:  li.localIP,
		localID:  li.localID,
		remoteIP: ri.remoteIP,
	}
	delete(nat.icmpv6PM, pm)
	delete(nat.icmpv6RL, ri)
}

// TODO previous collide with static port map
func (nat *nat) generateRandomIPv4TCPPort() uint16 {
	return nat.generateRandomPort()
}

func (nat *nat) generateRandomIPv4UDPPort() uint16 {
	return nat.generateRandomPort()
}

func (nat *nat) generateRandomICMPv4ID() uint16 {
	return nat.generateRandomID()
}

func (nat *nat) generateRandomIPv6TCPPort() uint16 {
	return nat.generateRandomPort()
}

func (nat *nat) generateRandomIPv6UDPPort() uint16 {
	return nat.generateRandomPort()
}

func (nat *nat) generateRandomICMPv6ID() uint16 {
	return nat.generateRandomID()
}

func (nat *nat) generateRandomPort() uint16 {
	nat.randMu.Lock()
	defer nat.randMu.Unlock()
	return 1024 + uint16(nat.rand.Intn(65536-1024)) // 1024-65535
}

func (nat *nat) generateRandomID() uint16 {
	nat.randMu.Lock()
	defer nat.randMu.Unlock()
	return 1 + uint16(nat.rand.Intn(65535)) // 1-65535
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
		nat.cleanIPv4TCPPortMap()
		nat.cleanIPv4UDPPortMap()
		nat.cleanICMPv4IDMap()
	}
	if nat.gatewayIPv6 != nil {
		nat.cleanIPv6TCPPortMap()
		nat.cleanIPv6UDPPortMap()
		nat.cleanICMPv6IDMap()
	}
}

func (nat *nat) cleanIPv4TCPPortMap() {
	var (
		previous uint32
		current  uint32
	)
	now := time.Now()
	nat.ipv4TCPRWM.Lock()
	defer nat.ipv4TCPRWM.Unlock()
	for ri, li := range nat.ipv4TCPRL {
		if now.Sub(li.createAt) < nat.mapTimeout {
			continue
		}
		previous = atomic.LoadUint32(li.preCtr)
		current = atomic.LoadUint32(li.curCtr)
		if previous != current {
			atomic.StoreUint32(li.preCtr, current)
			continue
		}
		nat.deleteIPv4TCPPortMap(li, ri)
	}
}

func (nat *nat) cleanIPv4UDPPortMap() {
	var (
		previous uint32
		current  uint32
	)
	now := time.Now()
	nat.ipv4UDPRWM.Lock()
	defer nat.ipv4UDPRWM.Unlock()
	for ri, li := range nat.ipv4UDPRL {
		if now.Sub(li.createAt) < nat.mapTimeout {
			continue
		}
		previous = atomic.LoadUint32(li.preCtr)
		current = atomic.LoadUint32(li.curCtr)
		if previous != current {
			atomic.StoreUint32(li.preCtr, current)
			continue
		}
		nat.deleteIPv4UDPPortMap(li, ri)
	}
}

func (nat *nat) cleanICMPv4IDMap() {
	var (
		previous uint32
		current  uint32
	)
	now := time.Now()
	nat.icmpv4RWM.Lock()
	defer nat.icmpv4RWM.Unlock()
	for ri, li := range nat.icmpv4RL {
		if now.Sub(li.createAt) < nat.mapTimeout {
			continue
		}
		previous = atomic.LoadUint32(li.preCtr)
		current = atomic.LoadUint32(li.curCtr)
		if previous != current {
			atomic.StoreUint32(li.preCtr, current)
			continue
		}
		nat.deleteICMPv4IDMap(li, ri)
	}
}

func (nat *nat) cleanIPv6TCPPortMap() {
	var (
		previous uint32
		current  uint32
	)
	now := time.Now()
	nat.ipv6TCPRWM.Lock()
	defer nat.ipv6TCPRWM.Unlock()
	for ri, li := range nat.ipv6TCPRL {
		if now.Sub(li.createAt) < nat.mapTimeout {
			continue
		}
		previous = atomic.LoadUint32(li.preCtr)
		current = atomic.LoadUint32(li.curCtr)
		if previous != current {
			atomic.StoreUint32(li.preCtr, current)
			continue
		}
		nat.deleteIPv6TCPPortMap(li, ri)
	}
}

func (nat *nat) cleanIPv6UDPPortMap() {
	var (
		previous uint32
		current  uint32
	)
	now := time.Now()
	nat.ipv6UDPRWM.Lock()
	defer nat.ipv6UDPRWM.Unlock()
	for ri, li := range nat.ipv6UDPRL {
		if now.Sub(li.createAt) < nat.mapTimeout {
			continue
		}
		previous = atomic.LoadUint32(li.preCtr)
		current = atomic.LoadUint32(li.curCtr)
		if previous != current {
			atomic.StoreUint32(li.preCtr, current)
			continue
		}
		nat.deleteIPv6UDPPortMap(li, ri)
	}
}

func (nat *nat) cleanICMPv6IDMap() {
	var (
		previous uint32
		current  uint32
	)
	now := time.Now()
	nat.icmpv6RWM.Lock()
	defer nat.icmpv6RWM.Unlock()
	for ri, li := range nat.icmpv6RL {
		if now.Sub(li.createAt) < nat.mapTimeout {
			continue
		}
		previous = atomic.LoadUint32(li.preCtr)
		current = atomic.LoadUint32(li.curCtr)
		if previous != current {
			atomic.StoreUint32(li.preCtr, current)
			continue
		}
		nat.deleteICMPv6IDMap(li, ri)
	}
}

func (nat *nat) Close() {
	nat.cancel()
	nat.wg.Wait()
}
