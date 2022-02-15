package mytls

import (
	"crypto/cipher"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

type (
	conn struct {
		net.Conn

		aead         cipher.AEAD
		handshakeErr error

		readBuf []byte
	}

	handshake struct {
		c    net.Conn
		hash hash.Hash
	}
)

func UpgradeConn(c net.Conn, sharedKey []byte) net.Conn {
	u := &conn{Conn: c}

	h := &handshake{
		c:    c,
		hash: hmac.New(sha256.New, sharedKey),
	}
	u.aead, u.handshakeErr = h.doHandshake()
	if u.handshakeErr != nil {
		u.handshakeErr = fmt.Errorf("error on handshake: %w", u.handshakeErr)
	}

	return u
}

func (c *conn) Write(b []byte) (int, error) {
	if c.handshakeErr != nil {
		return 0, c.handshakeErr
	}

	if len(b) == 0 {
		return 0, nil
	}

	msg, err := c.encrypt(b)
	if err != nil {
		return 0, err
	}

	if err := writeLV(c.Conn, msg); err != nil {
		return 0, err
	}

	return len(b), nil
}

func (c *conn) Read(b []byte) (int, error) {
	if c.handshakeErr != nil {
		return 0, c.handshakeErr
	}

	if len(b) == 0 {
		return 0, nil
	}

	if len(c.readBuf) == 0 {
		msg, err := readLV(c.Conn)
		if err != nil {
			return 0, err
		}

		msg, err = c.decrypt(msg)
		if err != nil {
			return 0, err
		}

		c.readBuf = msg
	}

	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]

	return n, nil
}

func (c *conn) encrypt(b []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize(), c.aead.NonceSize()+len(b)+c.aead.Overhead())
	if _, err := cryptorand.Read(nonce); err != nil {
		return nil, fmt.Errorf("error generating nonce: %w", err)
	}
	return c.aead.Seal(nonce, nonce, b, nil), nil
}

func (c *conn) decrypt(b []byte) ([]byte, error) {
	if len(b) < c.aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := b[:c.aead.NonceSize()], b[c.aead.NonceSize():]
	b, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening ciphertext: %w", err)
	}
	return b, nil
}

func (h *handshake) doHandshake() (cipher.AEAD, error) {
	pri, pub, err := generateKeyPair()
	if err != nil {
		return nil, err
	}
	pubPeer, err := h.doExchange(pub)
	if err != nil {
		return nil, err
	}
	return aeadFromECDHE(pri, pubPeer)
}

func (h *handshake) doExchange(publicKey []byte) ([]byte, error) {
	if err := h.writeWithSignature(publicKey); err != nil {
		return nil, err
	}
	pubPeer, err := h.readAndVerify()
	if err != nil {
		return nil, err
	}
	return pubPeer, nil
}

func (h *handshake) writeWithSignature(b []byte) error {
	h.hash.Reset()
	if _, err := h.hash.Write(b); err != nil {
		return fmt.Errorf("error writing handshake payload to hash: %w", err)
	}
	sig := h.hash.Sum(nil)

	if err := writeLV(h.c, b); err != nil {
		return fmt.Errorf("error writing handshake payload: %w", err)
	}
	if err := writeLV(h.c, sig); err != nil {
		return fmt.Errorf("error writing handshake signature: %w", err)
	}

	return nil
}

func (h *handshake) readAndVerify() ([]byte, error) {
	b, err := readLV(h.c)
	if err != nil {
		return nil, fmt.Errorf("error reading handshake payload: %w", err)
	}
	sig, err := readLV(h.c)
	if err != nil {
		return nil, fmt.Errorf("error reading handshake signature: %w", err)
	}

	h.hash.Reset()
	if _, err := h.hash.Write(b); err != nil {
		return nil, fmt.Errorf("error writing peer handshake payload to hash: %w", err)
	}
	if !hmac.Equal(sig, h.hash.Sum(nil)) {
		return nil, errors.New("handshake payload signatures differ")
	}

	return b, nil
}

func generateKeyPair() (private, public []byte, err error) {
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

func aeadFromECDHE(private, public []byte) (cipher.AEAD, error) {
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

func writeLV(c net.Conn, b []byte) error {
	size := int32(len(b))
	if err := binary.Write(c, binary.LittleEndian, size); err != nil {
		return fmt.Errorf("error writing message size: %w", err)
	}
	if _, err := c.Write(b); err != nil {
		return fmt.Errorf("error writing message: %w", err)
	}
	return nil
}

func readLV(c net.Conn) ([]byte, error) {
	var size int32
	if err := binary.Read(c, binary.LittleEndian, &size); err != nil {
		return nil, fmt.Errorf("error reading message size: %w", err)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, fmt.Errorf("error reading message: %w", err)
	}
	return buf, nil
}
