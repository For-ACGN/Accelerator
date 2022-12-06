package accelerator

import (
	"net"
)

type connPool struct {
	conns map[net.Conn]bool
}
