package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/matheuscscp/crypto-project/pkg/mytls"
)

func serverMain(certFile, keyFile string) {
	u, err := mytls.NewConnUpgrader(
		nil, // trustedCertFiles
		certFile, keyFile,
		time.Second, // handshakeReadTimeout
	)
	if err != nil {
		panic(err)
	}

	s := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("WORKING"))
		}),
	}

	osSignal := make(chan os.Signal, 1)
	signal.Notify(osSignal, os.Interrupt, syscall.SIGTERM)
	shutdownErr := make(chan error, 1)
	go func() {
		<-osSignal
		shutdownErr <- s.Shutdown(context.Background())
	}()

	l, err := net.Listen("tcp", "localhost:8080")
	if err != nil {
		panic(err)
	}

	err = s.Serve(mytls.UpgradeListener(l, u))
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("Serve() returned error: %v\n", err)
	}
	signal.Stop(osSignal)
	close(osSignal)

	if err := <-shutdownErr; err != nil {
		fmt.Printf("Shutdown() returned error: %v\n", err)
	}
}
