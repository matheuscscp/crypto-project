package mytls

import (
	"crypto/cipher"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

type (
	conn struct {
		net.Conn

		aead         cipher.AEAD
		handshakeErr error

		readBuf []byte
	}
)

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

func writeLV(c net.Conn, b []byte) error {
	size := int32(len(b))
	if err := binary.Write(c, binary.LittleEndian, size); err != nil {
		return fmt.Errorf("error writing message size: %w", err)
	}
	if size == 0 {
		return nil
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
	if size == 0 {
		return nil, nil
	}

	buf := make([]byte, size)
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, fmt.Errorf("error reading message: %w", err)
	}
	return buf, nil
}

func readLVWithTimeout(c net.Conn, timeout time.Duration) ([]byte, error) {
	if timeout > 0 {
		c.SetReadDeadline(time.Now().Add(timeout))
		defer c.SetReadDeadline(time.Time{})
	}

	return readLV(c)
}
