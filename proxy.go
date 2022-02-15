package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

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

func proxyMain(keyFile string) {
	m, err := mytls.NewFromFile(keyFile)
	if err != nil {
		panic(err)
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

		go proxy(m, c)
	}
}

func proxy(m mytls.MyTLS, c net.Conn) {
	defer c.Close()

	s, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		log.Printf("error dialing to server: %v", err)
		return
	}
	defer s.Close()

	s = m.UpgradeConn(s)

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

func copyConn(dst io.Writer, src io.Reader) error {
	_, err := io.Copy(&pureWriter{Writer: dst}, &pureReader{Reader: src})
	if err != nil && !isUseOfClosedConn(err) {
		return err
	}
	return nil
}

func isUseOfClosedConn(err error) bool {
	return strings.Contains(err.Error(), "use of closed network connection")
}
