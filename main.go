package main

import (
	"fmt"
	"os"
	"time"

	"github.com/matheuscscp/crypto-project/pkg/mytls"
)

const usage = `usage: %s <command> [args]

commands:

gen <duration> <cert_file> <key_file>
	Generate unsigned certificate with random key pair.
	If <duration> <= 0, then <duration> is assigned
	365 days. Use go duration syntax.

sign <cert_file> <parent_cert_file> <parent_key_file>
	Sign <cert_file> with <parent_key_file>.
	The <parent_key_file> private key must match the
	public key of <parent_cert_file>.

self <cert_file> <key_file>
	Self-sign <cert_file>.
	The <key_file> private key must match the public
	key of <cert_file>.

server <cert_file> <key_file>
	Start hello world HTTPS server on localhost:8080.

proxy <trusted_cert_file>...
	Start TCP proxy server on localhost:8081 proxying
	connections to localhost:8080 over TLS.

client <trusted_cert_file>...
	Send GET / HTTPS request to localhost:8080.
`

func printUsage() {
	fmt.Printf(usage, os.Args[0])
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	err := func() error {
		switch os.Args[1] {
		case "gen":
			if len(os.Args) < 5 {
				printUsage()
				return nil
			}
			d, err := time.ParseDuration(os.Args[2])
			if err != nil {
				return fmt.Errorf("error parsing certificate duration: %w", err)
			}
			return mytls.GenerateCertificate(d, os.Args[3], os.Args[4])
		case "sign":
			if len(os.Args) < 5 {
				printUsage()
				return nil
			}
			return mytls.SignCertificate(os.Args[2], os.Args[3], os.Args[4])
		case "self":
			if len(os.Args) < 4 {
				printUsage()
				return nil
			}
			return mytls.SignCertificate(os.Args[2], "", os.Args[3])
		case "server":
			if len(os.Args) < 4 {
				printUsage()
				return nil
			}
			serverMain(os.Args[2], os.Args[3])
		case "proxy":
			proxyMain(os.Args[2:])
		case "client":
			clientMain(os.Args[2:])
		default:
			printUsage()
		}
		return nil
	}()

	if err != nil {
		fmt.Println(err.Error())
	}
}
