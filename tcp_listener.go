package accelerator

import (
	"net"
	"time"
)

type tcpListener struct {
	*net.TCPListener
}

func (l *tcpListener) Accept() (net.Conn, error) {
	conn, err := l.TCPListener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	_ = conn.SetNoDelay(true)
	_ = conn.SetKeepAlive(true)
	_ = conn.SetKeepAlivePeriod(15 * time.Second)
	return conn, nil
}
