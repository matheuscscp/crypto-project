package main

import (
	"fmt"
	"os"
	"time"

	"github.com/matheuscscp/crypto-project/pkg/mytls"
)

const usage = `usage: %s <command> [args]

commands:

gen <go_duration> <cert_file> <key_file>
	Generate unsigned certificate with random key pair.
	If <go_duration> <= 0, then <go_duration> is assigned
	365 days.

sign <cert_file> <parent_cert_file> <parent_key_file>
	Sign <cert_file> with <parent_key_file>.
	The <parent_key_file> private key must match the
	public key of <parent_cert_file>.

self <cert_file> <key_file>
	Self-sign <cert_file>.
	The <key_file> private key must match the public
	key of <cert_file>.
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
		default:
			printUsage()
		}
		return nil
	}()

	if err != nil {
		fmt.Println(err.Error())
	}
}
