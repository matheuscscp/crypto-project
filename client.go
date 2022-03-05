package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/matheuscscp/crypto-project/pkg/mytls"
)

func clientMain(trustedCertFiles []string) {
	u, err := mytls.NewConnUpgrader(
		trustedCertFiles,
		"",          // certFile
		"",          // keyFile
		time.Second, // handshakeReadTimeout
	)
	if err != nil {
		panic(err)
	}

	dt, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		panic("somebody changed http.DefaultTransport")
	}
	dialCtx := dt.DialContext
	t := *dt
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dialCtx(ctx, network, addr)
		if err != nil {
			return c, err
		}
		return u.Upgrade(c), nil
	}
	c := &http.Client{
		Transport: &t,
	}

	resp, err := c.Get("http://localhost:8080")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(b))
}
