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

// connPool is used to send frame packet with lower RTT.
type connPool struct {
	size int
	
	conns   map[*net.Conn]bool
	connsMu sync.Mutex
	
	closed int32
	
	ctx    context.Context
	cancel context.CancelFunc
}

func newConnPool(size int) *connPool {
	pool := connPool{
		size:  size,
		conns: make(map[*net.Conn]bool, size),
	}
	pool.ctx, pool.cancel = context.WithCancel(context.Background())
	return &pool
}

// IsFull is used to check connection pool is full.
func (pool *connPool) IsFull() bool {
	if pool.isClosed() {
		return true
	}
	pool.connsMu.Lock()
	defer pool.connsMu.Unlock()
	return pool.isFull()
}

func (pool *connPool) isFull() bool {
	return len(pool.conns) >= pool.size
}

// AddConn is used to add new connection to the pool.
func (pool *connPool) AddConn(conn *net.Conn) bool {
	pool.connsMu.Lock()
	defer pool.connsMu.Unlock()
	if pool.isFull() || pool.isClosed() {
		return false
	}
	pool.conns[conn] = false
	return true
}

// DeleteConn is used to delete connection in the pool.
func (pool *connPool) DeleteConn(conn *net.Conn) {
	pool.connsMu.Lock()
	defer pool.connsMu.Unlock()
	if pool.isClosed() {
		return
	}
	delete(pool.conns, conn)
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
			case <-time.After(250 * time.Millisecond):
			case <-pool.ctx.Done():
				return 0, errConnPoolClosed
			}
			continue
		}
		n, err = conn.Write(b)
		if err == nil {
			return n, nil
		}
	}
	return n, err
}

func (pool *connPool) getConn() (net.Conn, error) {
	pool.connsMu.Lock()
	defer pool.connsMu.Unlock()
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
	var err error
	pool.connsMu.Lock()
	defer pool.connsMu.Unlock()
	for conn := range pool.conns {
		e := (*conn).Close()
		if e != nil && err == nil {
			err = e
		}
		delete(pool.conns, conn)
	}
	return err
}
