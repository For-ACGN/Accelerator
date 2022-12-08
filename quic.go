package accelerator

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
)

var errQUICConnClosed = errors.New("quic connection is closed")

type qConn struct {
	// must close rawConn manually to prevent goroutine leak
	// in package github.com/lucas-clemente/quic-go
	// go m.listen() in newPacketHandlerMap()
	rawConn net.PacketConn

	conn   quic.Connection
	stream quic.Stream

	// must use extra Mutex because SendStream
	// is not safe for use by multiple goroutines
	//
	// stream.Close() must not be called concurrently with Write()
	sendMu sync.Mutex

	// only server connection need it
	timeout    time.Duration
	ctx        context.Context
	cancel     context.CancelFunc
	acceptErr  error
	acceptOnce sync.Once
}

func (c *qConn) acceptStream() error {
	c.acceptOnce.Do(func() {
		if c.stream == nil {
			defer c.cancel()
			c.stream, c.acceptErr = c.conn.AcceptStream(c.ctx)
			if c.acceptErr != nil {
				return
			}
			// read data for trigger handshake
			_ = c.stream.SetReadDeadline(time.Now().Add(c.timeout))
			buf := make([]byte, 1)
			_, c.acceptErr = c.stream.Read(buf)
		}
	})
	return c.acceptErr
}

// Read reads data from the connection.
func (c *qConn) Read(b []byte) (n int, err error) {
	err = c.acceptStream()
	if err != nil {
		return
	}
	return c.stream.Read(b)
}

// Write writes data to the connection.
func (c *qConn) Write(b []byte) (n int, err error) {
	err = c.acceptStream()
	if err != nil {
		return
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return c.stream.Write(b)
}

// SetDeadline is used to set read and write deadline.
func (c *qConn) SetDeadline(t time.Time) error {
	err := c.SetReadDeadline(t)
	if err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetReadDeadline is used to set read deadline.
func (c *qConn) SetReadDeadline(t time.Time) error {
	err := c.acceptStream()
	if err != nil {
		return err
	}
	return c.stream.SetReadDeadline(t)
}

// SetWriteDeadline is used to set write deadline.
func (c *qConn) SetWriteDeadline(t time.Time) error {
	err := c.acceptStream()
	if err != nil {
		return err
	}
	return c.stream.SetWriteDeadline(t)
}

// LocalAddr is used to get local address.
func (c *qConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr is used to get remote address.
func (c *qConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// Close is used to close connection.
func (c *qConn) Close() error {
	if c.cancel != nil {
		c.cancel()
	}
	c.acceptOnce.Do(func() {
		c.acceptErr = errQUICConnClosed
	})
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if c.stream != nil {
		_ = c.stream.Close()
	}
	err := c.conn.CloseWithError(0, "")
	if c.rawConn != nil {
		e := c.rawConn.Close()
		if e != nil && err == nil {
			err = e
		}
	}
	return err
}

type qListener struct {
	net.Listener
}

func (client *Client) dialQUIC() (net.Conn, error) {
	udp := client.config.UDP
	lAddr, err := net.ResolveUDPAddr(udp.LocalNetwork, client.localAddr)
	if err != nil {
		return nil, err
	}
	rAddr, err := net.ResolveUDPAddr(udp.RemoteNetwork, udp.RemoteAddress)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", lAddr)
	if err != nil {
		return nil, err
	}
	config := quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       30 * time.Second,
		KeepAlivePeriod:      15 * time.Second,
	}
	conn, err := quic.Dial(udpConn, rAddr, udp.RemoteAddress, client.tlsConfig, &config)
	if err != nil {
		return nil, err
	}
	_ = conn.CloseWithError(0, "")
	_ = udpConn.Close()
	return nil, nil
}
