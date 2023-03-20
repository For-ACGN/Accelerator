package accelerator

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var (
	errEmptyConnPool  = errors.New("empty connection pool")
	errConnPoolClosed = errors.New("connection pool is closed")
)

// connPool is used to send frame packet for lower RTT.
// Server side use Push for delegate data to sender in
// the conn pool for prevent block when one user block.
type connPool struct {
	size    atomic.Value
	timeout time.Duration

	conns    map[*net.Conn]bool
	connsRWM sync.RWMutex

	frameCh chan []byte

	closed int32

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newConnPool(size int, timeout time.Duration, server bool) *connPool {
	pool := connPool{
		timeout: timeout,
		conns:   make(map[*net.Conn]bool, size),
	}
	pool.ctx, pool.cancel = context.WithCancel(context.Background())
	pool.SetSize(size)
	if !server {
		return &pool
	}
	pool.frameCh = make(chan []byte, 128*size)
	for i := 0; i < size; i++ {
		pool.wg.Add(1)
		go pool.sendLoop()
	}
	return &pool
}

// SetSize is used to set connection pool size.
func (pool *connPool) SetSize(size int) {
	pool.size.Store(size)
}

// GetSize is used to get connection pool size.
func (pool *connPool) GetSize() int {
	return pool.size.Load().(int)
}

// IsEmpty is used to check connection pool is empty.
func (pool *connPool) IsEmpty() bool {
	if pool.isClosed() {
		return true
	}
	pool.connsRWM.RLock()
	defer pool.connsRWM.RUnlock()
	return len(pool.conns) < 1
}

// IsFull is used to check connection pool is full.
func (pool *connPool) IsFull() bool {
	if pool.isClosed() {
		return true
	}
	pool.connsRWM.RLock()
	defer pool.connsRWM.RUnlock()
	return pool.isFull()
}

func (pool *connPool) isFull() bool {
	return len(pool.conns) >= pool.GetSize()
}

// AddConn is used to add new connection to the pool.
func (pool *connPool) AddConn(conn *net.Conn) bool {
	pool.connsRWM.Lock()
	defer pool.connsRWM.Unlock()
	if pool.isFull() || pool.isClosed() {
		return false
	}
	pool.conns[conn] = false
	return true
}

// DeleteConn is used to delete connection in the pool.
func (pool *connPool) DeleteConn(conn *net.Conn) {
	pool.connsRWM.Lock()
	defer pool.connsRWM.Unlock()
	if pool.isClosed() {
		return
	}
	delete(pool.conns, conn)
}

// Push is used to push data to connection pool and wait sender
// to send data, if send queue is full, data will be dropped.
func (pool *connPool) Push(b []byte) {
	data := make([]byte, len(b))
	copy(data, b)
	select {
	case pool.frameCh <- data:
	default:
	}
}

func (pool *connPool) sendLoop() {
	defer pool.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			// pool.ctx.logger.Fatal("connPool.sendLoop", r)
			// restart frame sender
			time.Sleep(time.Second)
			pool.wg.Add(1)
			go pool.sendLoop()
		}
	}()
	var b []byte
	for {
		select {
		case b = <-pool.frameCh:
			_, _ = pool.Write(b)
		case <-pool.ctx.Done():
			return
		}
	}
}

// Write is used to select one connection for write data.
func (pool *connPool) Write(b []byte) (int, error) {
	var (
		conn net.Conn
		n    int
		err  error
	)
	for i := 0; i < 10; i++ {
		conn, err = pool.getConn()
		if err != nil {
			if err != errEmptyConnPool {
				return 0, err
			}
			// wait some time for add new connection
			select {
			case <-time.After(10 * time.Millisecond):
			case <-pool.ctx.Done():
				return 0, errConnPoolClosed
			}
			continue
		}
		err = conn.SetWriteDeadline(time.Now().Add(pool.timeout))
		if err != nil {
			continue
		}
		n, err = conn.Write(b)
		if err == nil {
			return n, nil
		}
		_ = conn.Close()
	}
	return n, err
}

func (pool *connPool) getConn() (net.Conn, error) {
	pool.connsRWM.Lock()
	defer pool.connsRWM.Unlock()
	if len(pool.conns) < 1 {
		return nil, errEmptyConnPool
	}
	for {
		if pool.isClosed() {
			return nil, errConnPoolClosed
		}
		// select unused connection
		for conn, used := range pool.conns {
			if !used {
				pool.conns[conn] = true
				return *conn, nil
			}
		}
		// reset all used flags
		for conn := range pool.conns {
			pool.conns[conn] = false
		}
	}
}

func (pool *connPool) isClosed() bool {
	return atomic.LoadInt32(&pool.closed) != 0
}

// Close is used to close all connections.
func (pool *connPool) Close() error {
	atomic.StoreInt32(&pool.closed, 1)
	pool.cancel()
	pool.wg.Wait()
	var err error
	pool.connsRWM.Lock()
	defer pool.connsRWM.Unlock()
	for conn := range pool.conns {
		e := (*conn).Close()
		if e != nil && !errors.Is(e, net.ErrClosed) && err == nil {
			err = e
		}
		delete(pool.conns, conn)
	}
	return err
}
