package mytls

import (
	"crypto/cipher"
	"crypto/ed25519" // ECDSA
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/chacha20poly1305" // AEAD
	"golang.org/x/crypto/curve25519"       // ECDHE
)

type (
	handshake struct {
		c           net.Conn
		remoteAddr  string
		cert        certificateWireFormat
		key         certificatePrivateKey
		certReg     certificateRegistry
		readTimeout time.Duration
	}

	ecdhePrivateKey []byte
	ecdhePublicKey  []byte
)

func (h *handshake) doHandshake() (cipher.AEAD, error) {
	closeOnReturn := true
	defer func() {
		if closeOnReturn {
			h.c.Close()
		}
	}()

	pri, pub, err := generateECDHEKeyPair()
	if err != nil {
		return nil, err
	}

	peerPub, err := h.doExchange(pub)
	if err != nil {
		return nil, err
	}

	aead, err := aeadFromECDHEKeyPair(pri, peerPub)
	if err != nil {
		return nil, err
	}

	closeOnReturn = false
	return aead, nil
}

func (h *handshake) doExchange(mine ecdhePublicKey) (ecdhePublicKey, error) {
	if err := writeLV(h.c, h.cert); err != nil {
		return nil, fmt.Errorf("error writing certificate: %w", err)
	}
	peerCert, err := readLVWithTimeout(h.c, h.readTimeout)
	if err != nil {
		return nil, fmt.Errorf("error reading peer certificate: %w", err)
	}

	peerECDSA, err := h.certReg.validate(peerCert, h.remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("error validating peer certificate: %w", err)
	}

	if err := h.writeWithSignature(mine); err != nil {
		return nil, err
	}
	peer, err := h.readAndVerify(peerECDSA)
	if err != nil {
		return nil, err
	}

	return peer, nil
}

func (h *handshake) writeWithSignature(b []byte) error {
	var sig []byte
	if len(h.key) > 0 {
		sig = ed25519.Sign(ed25519.PrivateKey(h.key), b)
	}

	if err := writeLV(h.c, b); err != nil {
		return err
	}
	if len(sig) > 0 {
		if err := writeLV(h.c, sig); err != nil {
			return err
		}
	}

	return nil
}

func (h *handshake) readAndVerify(peerECDSA certificatePublicKey) ([]byte, error) {
	b, err := readLVWithTimeout(h.c, h.readTimeout)
	if err != nil {
		return nil, err
	}

	if len(peerECDSA) > 0 {
		sig, err := readLVWithTimeout(h.c, h.readTimeout)
		if err != nil {
			return nil, err
		}
		if !ed25519.Verify(ed25519.PublicKey(peerECDSA), b, sig) {
			return nil, errors.New("invalid signature for message")
		}
	}

	return b, nil
}

func generateECDHEKeyPair() (private ecdhePrivateKey, public ecdhePublicKey, err error) {
	pri := make([]byte, curve25519.ScalarSize)
	if _, err := cryptorand.Read(pri); err != nil {
		return nil, nil, fmt.Errorf("error generating private key: %w", err)
	}
	pub, err := curve25519.X25519(pri, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating public key: %w", err)
	}
	private = pri
	public = pub
	return
}

func aeadFromECDHEKeyPair(private ecdhePrivateKey, public ecdhePublicKey) (cipher.AEAD, error) {
	sharedKey, err := curve25519.X25519(private, public)
	if err != nil {
		return nil, fmt.Errorf("error combining keys: %w", err)
	}
	aead, err := chacha20poly1305.NewX(sharedKey)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher: %w", err)
	}
	return aead, nil
}
