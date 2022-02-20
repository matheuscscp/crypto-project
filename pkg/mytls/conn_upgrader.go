package mytls

import (
	"crypto/ed25519"
	"fmt"
	"net"
	"time"
)

type (
	// ConnUpgrader provides an interface for upgrading insecure
	// connections into secure ones.
	ConnUpgrader struct {
		certReg              *certificateRegistry
		cert                 []byte
		key                  ed25519.PrivateKey
		handshakeReadTimeout time.Duration
	}
)

// NewConnUpgrader loads the trusted root certificates for authenticating peers
// and a (cert, key) pair of files for self-authentication and returns a factory
// for upgrading insecure connections into secure ones.
//
// If an empty set of trusted root certificates is passed, any certificate will
// be trusted.
//
// Zero for handshakeReadTimeout indicates no timeout for reading handshake
// messages.
func NewConnUpgrader(
	trustedCerts []string,
	certFile, keyFile string,
	handshakeReadTimeout time.Duration,
) (*ConnUpgrader, error) {
	certReg, err := newCertificateRegistry(trustedCerts)
	if err != nil {
		return nil, fmt.Errorf("error creating certificate registry: %w", err)
	}

	cert, key, err := newListenerCertificate(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("error creating listener certificate: %w", err)
	}

	return &ConnUpgrader{
		cert:                 cert,
		key:                  key,
		certReg:              certReg,
		handshakeReadTimeout: handshakeReadTimeout,
	}, nil
}

// Upgrade upgrades a connection by performing the handshake.
func (u *ConnUpgrader) Upgrade(c net.Conn) net.Conn {
	h := &handshake{
		c:           c,
		cert:        u.cert,
		key:         u.cert,
		certReg:     u.certReg,
		readTimeout: u.handshakeReadTimeout,
	}

	aead, err := h.doHandshake()
	return &conn{
		Conn: c,

		aead:         aead,
		handshakeErr: err,
	}
}