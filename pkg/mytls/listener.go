package mytls

import (
	"net"
)

type (
	listener struct {
		net.Listener
		u *ConnUpgrader
	}
)

// UpgradeListener upgrades a net.Listener for Accept()ing secure
// connections.
func UpgradeListener(l net.Listener, u *ConnUpgrader) net.Listener {
	return &listener{
		Listener: l,
		u:        u,
	}
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return c, err
	}
	return l.u.Upgrade(c), nil
}
