package accelerator

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// connPool is used to send frame packet with lower RTT.
type connPool struct {
	logger *logger
	writer io.Writer

	conns   map[*net.Conn]bool
	connsMu sync.Mutex

	closed int32
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newConnPool(ctx context.Context, size int) *connPool {
	pool := connPool{
		conns: make(map[*net.Conn]bool, size),
	}
	pool.ctx, pool.cancel = context.WithCancel(ctx)
	return &pool
}

func (pool *connPool) SetLogger(lg *logger) {
	pool.logger = lg
}

func (pool *connPool) SetWriter(w io.Writer) {
	pool.writer = w
}

func (pool *connPool) AddConn(conn *net.Conn) {
	pool.connsMu.Lock()
	defer pool.connsMu.Unlock()
	if pool.isClosed() {
		_ = (*conn).Close()
		return
	}
	pool.conns[conn] = false
	pool.wg.Add(1)
	go pool.readLoop(conn)
}

func (pool *connPool) deleteConn(conn *net.Conn) {
	pool.connsMu.Lock()
	defer pool.connsMu.Unlock()
	if pool.isClosed() {
		return
	}
	delete(pool.conns, conn)
}

func (pool *connPool) readLoop(conn *net.Conn) {
	defer pool.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			pool.logger.Fatal(r)
		}
	}()
	defer pool.deleteConn(conn)
	c := *conn
	buf := make([]byte, 64*1024)
	var (
		size uint16
		err  error
	)
	for {
		// read frame packet size
		_, err = io.ReadFull(c, buf[:2])
		if err != nil {
			return
		}
		size = binary.BigEndian.Uint16(buf[:2])
		// read frame packet
		_, err = io.ReadFull(c, buf[:size])
		if err != nil {
			return
		}
		// write to under writer
		_, err = pool.writer.Write(buf[:size])
		if err != nil {
			return
		}
	}
}

func (pool *connPool) isClosed() bool {
	return atomic.LoadInt32(&pool.closed) != 0
}

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
	}
	pool.wg.Wait()
	return err
}
