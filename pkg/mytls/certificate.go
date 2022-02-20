package mytls

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"time"

	yaml "gopkg.in/yaml.v3"
)

type (
	certificateRegistry struct {
		r map[publicKey]*certificate
	}

	publicKey [ed25519.PublicKeySize]byte
	signature [ed25519.SignatureSize]byte

	certificate struct {
		Data      certifiedData `yaml:"certifiedData"`
		Signature signature     `yaml:"certifiedDataSignature"`
		Parent    *certificate  `yaml:"parentCertificate"`
	}

	certifiedData struct {
		PublicKey    publicKey `yaml:"publicKey"`
		ExpiresAt    time.Time `yaml:"expiresAt"`
		Organization string    `yaml:"organization"`
		Records      []string  `yaml:"records"`
	}
)

func newCertificateRegistry(certFiles []string) (*certificateRegistry, error) {
	cr := &certificateRegistry{
		r: make(map[publicKey]*certificate),
	}

	for _, f := range certFiles {
		cert, err := newCertificate(f)
		if err != nil {
			return nil, err
		}
		cr.r[cert.Data.PublicKey] = cert
	}

	return cr, nil
}

func (cr *certificateRegistry) validate(b []byte) (ed25519.PublicKey, error) {
	if len(cr.r) == 0 {
		return nil, nil
	}

	if len(b) == 0 {
		return nil, errors.New("want certificate but got empty")
	}

	c, err := parseWireCertificate(b)
	if err != nil {
		return nil, err
	}

	rootPubKey, err := c.validate()
	if err != nil {
		return nil, err
	}

	if _, ok := cr.r[*rootPubKey]; !ok {
		return nil, errors.New("self signed certificate")
	}

	return c.Data.PublicKey[:], nil
}

func newCertificate(certFile string) (*certificate, error) {
	cert, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("error reading certificate file at '%s': %w", certFile, err)
	}
	var c certificate
	if err := yaml.Unmarshal(cert, &c); err != nil {
		return nil, fmt.Errorf("error unmarshaling certificate: %w", err)
	}
	return &c, nil
}

func newListenerCertificate(certFile, keyFile string) ([]byte, ed25519.PrivateKey, error) {
	if certFile == "" {
		return nil, nil, nil
	}

	c, err := newCertificate(certFile)
	if err != nil {
		return nil, nil, err
	}
	cert, err := c.wireFormat()
	if err != nil {
		return nil, nil, err
	}

	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading certificate private key file at '%s': %w", keyFile, err)
	}

	return cert, ed25519.NewKeyFromSeed(key), nil
}

func parseWireCertificate(b []byte) (*certificate, error) {
	var c certificate
	if err := gob.NewDecoder(bytes.NewBuffer(b)).Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *certificate) wireFormat() ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(c); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (c *certificate) validate() (*publicKey, error) {
	if c.Parent == nil {
		p := &c.Data.PublicKey
		if err := c.validateWithPublicKey(p); err != nil {
			return nil, err
		}
		return p, nil
	}

	if err := c.validateWithPublicKey(&c.Parent.Data.PublicKey); err != nil {
		return nil, err
	}

	return c.Parent.validate()
}

func (c *certificate) validateWithPublicKey(p *publicKey) error {
	if !ed25519.Verify(p[:], c.deterministicallySerializeCertifiedData(), c.Signature[:]) {
		return errors.New("signature cannot be verified")
	}
	if c.Data.ExpiresAt.Before(time.Now()) {
		return fmt.Errorf("certificate expired at %v", c.Data.ExpiresAt)
	}
	return nil
}

func (c *certificate) deterministicallySerializeCertifiedData() []byte {
	var buf bytes.Buffer
	buf.Write(c.Data.PublicKey[:])
	buf.Write([]byte(c.Data.ExpiresAt.Format(time.RFC3339)))
	buf.Write([]byte(c.Data.Organization))
	for _, r := range c.Data.Records {
		buf.Write([]byte(r))
	}
	return buf.Bytes()
}

func (p publicKey) MarshalYAML() (interface{}, error) {
	return base64.StdEncoding.EncodeToString(p[:]), nil
}

func (p *publicKey) UnmarshalYAML(value *yaml.Node) error {
	var buf string
	if err := value.Decode(&buf); err != nil {
		return err
	}
	n, err := base64.StdEncoding.Decode(p[:], []byte(buf))
	if err != nil {
		return err
	}
	expectedSize := len(p[:])
	if n != expectedSize {
		return fmt.Errorf("public key has length %d but should have length %d", n, expectedSize)
	}
	return nil
}

func (s signature) MarshalYAML() (interface{}, error) {
	return base64.StdEncoding.EncodeToString(s[:]), nil
}

func (s *signature) UnmarshalYAML(value *yaml.Node) error {
	var buf string
	if err := value.Decode(&buf); err != nil {
		return err
	}
	n, err := base64.StdEncoding.Decode(s[:], []byte(buf))
	if err != nil {
		return err
	}
	expectedSize := len(s[:])
	if n != expectedSize {
		return fmt.Errorf("signature has length %d but should have length %d", n, expectedSize)
	}
	return nil
}
