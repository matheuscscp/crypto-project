package mytls

import (
	"fmt"
	"net"
	"time"
)

type (
	// ConnUpgrader provides an interface for upgrading insecure
	// connections into secure ones.
	ConnUpgrader struct {
		certReg              certificateRegistry
		cert                 certificateWireFormat
		key                  certificatePrivateKey
		handshakeReadTimeout time.Duration
	}
)

// NewConnUpgrader loads the trusted root certificates for authenticating peers
// and a (cert, key) pair of files for self-authentication and returns a factory
// for upgrading insecure connections into secure ones.
//
// If an empty set of trusted root certificates is passed, any certificate chain
// with all signatures valid will be trusted.
//
// If handshakeReadTimeout <= 0, then reading handshake messages will not timeout.
func NewConnUpgrader(
	trustedCertFiles []string,
	certFile, keyFile string,
	handshakeReadTimeout time.Duration,
) (*ConnUpgrader, error) {
	certReg, err := newCertificateRegistry(trustedCertFiles)
	if err != nil {
		return nil, fmt.Errorf("error creating certificate registry: %w", err)
	}

	cert, key, err := newWireAuthentication(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("error creating wire authentication: %w", err)
	}

	return &ConnUpgrader{
		cert:                 cert,
		key:                  key,
		certReg:              certReg,
		handshakeReadTimeout: handshakeReadTimeout,
	}, nil
}

// Upgrade upgrades a connection by performing the handshake.
func (u *ConnUpgrader) Upgrade(c net.Conn, remoteAddr string) net.Conn {
	h := &handshake{
		c:           c,
		remoteAddr:  remoteAddr,
		cert:        u.cert,
		key:         u.key,
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
