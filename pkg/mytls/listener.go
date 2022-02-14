package mytls

import (
	"net"
)

type (
	listener struct {
		net.Listener

		upgradeConn func(net.Conn) net.Conn
	}
)

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return c, err
	}
	return l.upgradeConn(c), nil
}
