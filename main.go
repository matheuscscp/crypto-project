package main

import (
	"os"

	"github.com/matheuscscp/crypto-project/pkg/mytls"
)

func main() {
	if len(os.Args) < 2 {
		panic("arg missing")
	}

	const keyFile = "key.bin"
	switch os.Args[1] {
	case "server":
		serverMain(keyFile)
	case "client":
		clientMain(keyFile)
	case "proxy":
		proxyMain(keyFile)
	case "genkey":
		if err := mytls.GenerateKey(keyFile); err != nil {
			panic(err)
		}
	default:
		panic("invalid arg")
	}
}
