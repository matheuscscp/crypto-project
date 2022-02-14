package mytls

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
)

type (
	MyTLS interface {
		UpgradeConn(c net.Conn) net.Conn
		UpgradeListener(l net.Listener) net.Listener
		Transport() http.RoundTripper
	}

	myTLS struct {
		sharedKey []byte
	}
)

func New(sharedKey []byte) MyTLS {
	return &myTLS{sharedKey: sharedKey}
}

func NewFromFile(name string) (MyTLS, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("error reading secret file: %w", err)
	}
	return New(b), nil
}

func (m *myTLS) UpgradeConn(c net.Conn) net.Conn {
	return UpgradeConn(c, m.sharedKey)
}

func (m *myTLS) UpgradeListener(l net.Listener) net.Listener {
	return &listener{
		Listener:    l,
		upgradeConn: m.UpgradeConn,
	}
}

func (m *myTLS) Transport() http.RoundTripper {
	dt, _ := http.DefaultTransport.(*http.Transport)
	t := *dt
	dial := t.DialContext
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dial(ctx, network, addr)
		if err != nil {
			return c, err
		}
		return m.UpgradeConn(c), nil
	}
	return &t
}

func GenerateKey(keyFile string) error {
	f, err := os.Create(keyFile)
	if err != nil {
		return fmt.Errorf("error creating key file: %w", err)
	}
	defer f.Close()
	if _, err := io.CopyN(f, rand.Reader, 32); err != nil {
		return fmt.Errorf("error generating secure key: %w", err)
	}
	return nil
}
