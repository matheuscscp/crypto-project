package main

import (
	"fmt"
	"io"
	"net/http"

	"github.com/matheuscscp/crypto-project/pkg/mytls"
)

func clientMain(keyFile string) {
	m, err := mytls.NewFromFile(keyFile)
	if err != nil {
		panic(err)
	}

	c := &http.Client{
		Transport: m.Transport(),
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
