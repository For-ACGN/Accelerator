package accelerator

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

var (
	errEmptyConnPool  = errors.New("empty connection pool")
	errConnPoolClosed = errors.New("connection pool is closed")
)

// connPool is used to send frame packet with lower RTT.
type connPool struct {
	logger *logger
	writer io.Writer

	conns   map[*net.Conn]bool
	connsMu sync.Mutex

	closed int32
	wg     sync.WaitGroup
}

func newConnPool(logger *logger, writer io.Writer, size int) *connPool {
	pool := connPool{
		logger: logger,
		writer: writer,
		conns:  make(map[*net.Conn]bool, size),
	}
	return &pool
}

// AddConn is used to add new connection to the pool.
func (pool *connPool) AddConn(conn net.Conn) {
	pool.connsMu.Lock()
	defer pool.connsMu.Unlock()
	if pool.isClosed() {
		err := conn.Close()
		if err != nil {
			pool.logger.Error(err)
		}
		return
	}
	c := &conn
	pool.conns[c] = false
	pool.wg.Add(1)
	go pool.readLoop(c)
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
	defer func() {
		err := c.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			pool.logger.Error(err)
		}
	}()
	buf := make([]byte, maxPacketSize)
	var (
		size uint16
		err  error
	)
	for {
		// read frame packet size
		_, err = io.ReadFull(c, buf[:frameHeaderSize])
		if err != nil {
			return
		}
		size = binary.BigEndian.Uint16(buf[:frameHeaderSize])
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

// Write is used to select one connection for write data.
func (pool *connPool) Write(b []byte) (int, error) {
	conn, err := pool.getConn()
	if err != nil {
		return 0, err
	}
	return conn.Write(b)
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
