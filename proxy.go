package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/matheuscscp/crypto-project/pkg/mytls"
)

type (
	pureWriter struct {
		io.Writer
	}

	pureReader struct {
		io.Reader
	}
)

func proxyMain(useTLSWithBackend bool, trustedCertFiles []string) {
	var u *mytls.ConnUpgrader
	var err error
	if useTLSWithBackend {
		u, err = mytls.NewConnUpgrader(
			trustedCertFiles,
			"",          // certFile
			"",          // keyFile
			time.Second, // handshakeReadTimeout
		)
		if err != nil {
			panic(err)
		}
	}

	l, err := net.Listen("tcp", "localhost:8081")
	if err != nil {
		panic(err)
	}
	defer l.Close()

	osSignal := make(chan os.Signal, 1)
	signal.Notify(osSignal, os.Interrupt, syscall.SIGTERM)
	go func() {
		defer l.Close()
		<-osSignal
	}()

	for {
		c, err := l.Accept()
		if err != nil {
			if isUseOfClosedConn(err) {
				return
			}
			panic(err)
		}

		go proxy(u, c)
	}
}

func proxy(u *mytls.ConnUpgrader, c net.Conn) {
	defer c.Close()

	const addr = "localhost:8080"
	s, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("error dialing to server: %v", err)
		return
	}
	defer s.Close()

	if u != nil {
		s = u.Upgrade(s, addr)
	}

	errCh := make(chan error, 2)

	go func() {
		defer s.Close()

		err := copyConn(s, c)
		if err != nil {
			err = fmt.Errorf("error copying from client to server: %w", err)
		}

		errCh <- err
	}()

	go func() {
		defer c.Close()

		err := copyConn(c, s)
		if err != nil {
			err = fmt.Errorf("error copying from server to client: %w", err)
		}

		errCh <- err
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			log.Printf("%v", err)
		}
	}
}

var proxyTapMtx sync.Mutex

func copyConn(dst, src net.Conn) error {
	var buf bytes.Buffer
	tap := io.TeeReader(&pureReader{Reader: src}, &buf)
	defer func() {
		proxyTapMtx.Lock()
		defer proxyTapMtx.Unlock()

		f, err := os.OpenFile("proxy-capture.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		defer f.Close()

		s := fmt.Sprintf("from %s to %s:\n\n", src.RemoteAddr().String(), dst.RemoteAddr().String())
		s += fmt.Sprintf("=====\n%s\n=====\n\n", string(buf.Bytes()))
		f.Write([]byte(s))
	}()

	_, err := io.Copy(&pureWriter{Writer: dst}, &pureReader{Reader: tap})
	if err != nil && !isUseOfClosedConn(err) {
		return err
	}
	return nil
}

func isUseOfClosedConn(err error) bool {
	return strings.Contains(err.Error(), "use of closed network connection")
}
