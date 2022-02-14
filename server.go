package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/matheuscscp/crypto-project/pkg/mytls"
)

func serverMain(keyFile string) {
	m, err := mytls.NewFromFile(keyFile)
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
	defer close(shutdownErr)
	go func() {
		<-osSignal
		shutdownErr <- s.Shutdown(context.Background())
	}()

	l, err := net.Listen("tcp", "localhost:8080")
	if err != nil {
		panic(err)
	}

	if err := s.Serve(m.UpgradeListener(l)); err != nil {
		fmt.Printf("Serve() returned error: %v\n", err)
	}
	signal.Stop(osSignal)
	close(osSignal)

	if err := <-shutdownErr; err != nil {
		fmt.Printf("Shutdown() returned error: %v\n", err)
	}
}
