package mytls

import (
	"bytes"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"time"

	yaml "gopkg.in/yaml.v3"
)

type (
	certificateRegistry map[publicKeyArray]struct{}
	publicKeyArray      [ed25519.PublicKeySize]byte

	certificate struct {
		Data      certifiedData `yaml:"certifiedData"`
		Signature signature     `yaml:"certifiedDataSignature,omitempty"`
		Parent    *certificate  `yaml:"parentCertificate,omitempty"`
	}

	certifiedData struct {
		PublicKey    publicKey `yaml:"publicKey"`
		ExpiresAt    time.Time `yaml:"expiresAt"`
		Organization string    `yaml:"organization"`
		Records      []string  `yaml:"records"`
	}

	publicKey []byte
	signature []byte
)

// GenerateCertificate generates an unsigned certificate with a random
// key pair.
func GenerateCertificate(d time.Duration, certFile, keyFile string) error {
	pub, pri, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		return fmt.Errorf("error generating random key pair for certificate: %w", err)
	}

	var c certificate
	c.Data.PublicKey = publicKey(pub)
	if d <= 0 {
		d = time.Hour * 24 * 365
	}
	c.Data.ExpiresAt = time.Now().Add(d)

	if err := c.marshalAndWrite(certFile); err != nil {
		return err
	}

	if err := os.WriteFile(keyFile, pri.Seed(), 0644); err != nil {
		return fmt.Errorf("error writing private key file: %w", err)
	}

	return nil
}

// SignCertificate uses a parent certificate to sign the given certificate.
//
// If parentCertFile == "", then the parentKeyFile should be the private
// key of the given certificate and the certificate will be self-signed.
func SignCertificate(certFile, parentCertFile, parentKeyFile string) error {
	c, err := newCertificate(certFile)
	if err != nil {
		return err
	}

	c.Parent = nil
	if parentCertFile != "" {
		c.Parent, err = newCertificate(parentCertFile)
		if err != nil {
			return err
		}
		if _, err := c.Parent.validate(); err != nil {
			return fmt.Errorf("parent certificate is invalid: %w", err)
		}
	}

	key, err := readPrivateKey(parentKeyFile)
	if err != nil {
		return err
	}

	signingCert := c.Parent
	if signingCert == nil {
		signingCert = c
	}
	if !ed25519.PublicKey(signingCert.Data.PublicKey).Equal(key.Public()) {
		return errors.New("private key and signing certificate do not match")
	}
	c.Signature = ed25519.Sign(key, c.deterministicallySerializeCertifiedData())

	return c.marshalAndWrite(certFile)
}

func newCertificateRegistry(certFiles []string) (certificateRegistry, error) {
	cr := make(certificateRegistry)

	for _, f := range certFiles {
		cert, err := newCertificate(f)
		if err != nil {
			return nil, err
		}
		cr[*cert.Data.PublicKey.asArray()] = struct{}{}
	}

	return cr, nil
}

func (cr certificateRegistry) validate(b []byte) (ed25519.PublicKey, error) {
	if len(cr) == 0 {
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

	if _, ok := cr[*rootPubKey]; !ok {
		if rootPubKey == c.Data.PublicKey.asArray() {
			return nil, errors.New("self signed certificate")
		}
		return nil, errors.New("untrusted root certificate")
	}

	return ed25519.PublicKey(c.Data.PublicKey), nil
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

	key, err := readPrivateKey(keyFile)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
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

func (c *certificate) validate() (*publicKeyArray, error) {
	if c.Parent == nil {
		p := c.Data.PublicKey.asArray()
		if err := c.validateWithPublicKey(p); err != nil {
			return nil, err
		}
		return p, nil
	}

	if err := c.validateWithPublicKey(c.Parent.Data.PublicKey.asArray()); err != nil {
		return nil, err
	}

	return c.Parent.validate()
}

func (c *certificate) validateWithPublicKey(p *publicKeyArray) error {
	if !ed25519.Verify(p[:], c.deterministicallySerializeCertifiedData(), c.Signature) {
		return errors.New("signature cannot be verified")
	}
	if c.Data.ExpiresAt.Before(time.Now()) {
		return fmt.Errorf("certificate expired at %v", c.Data.ExpiresAt)
	}
	return nil
}

func (c *certificate) deterministicallySerializeCertifiedData() []byte {
	var buf bytes.Buffer
	buf.Write(c.Data.PublicKey)
	buf.Write([]byte(c.Data.ExpiresAt.Format(time.RFC3339)))
	buf.Write([]byte(c.Data.Organization))
	for _, r := range c.Data.Records {
		buf.Write([]byte(r))
	}
	return buf.Bytes()
}

func (c *certificate) marshalAndWrite(certFile string) error {
	b, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("error marshaling certificate: %w", err)
	}
	if err := os.WriteFile(certFile, b, 0644); err != nil {
		return fmt.Errorf("error writing certificate file: %w", err)
	}
	return nil
}

func (p publicKey) asArray() *publicKeyArray {
	return (*publicKeyArray)(p)
}

func (p publicKey) MarshalYAML() (interface{}, error) {
	return marshalYAMLCertificateByteSlice(p)
}

func (p *publicKey) UnmarshalYAML(value *yaml.Node) error {
	return unmarshalYAMLCertificateByteSlice(
		value,
		(*[]byte)(p),
		"public key", // sliceType
		ed25519.PublicKeySize,
	)
}

func (s signature) MarshalYAML() (interface{}, error) {
	return marshalYAMLCertificateByteSlice(s)
}

func (s *signature) UnmarshalYAML(value *yaml.Node) error {
	return unmarshalYAMLCertificateByteSlice(
		value,
		(*[]byte)(s),
		"signature", // sliceType
		ed25519.SignatureSize,
	)
}

func marshalYAMLCertificateByteSlice(b []byte) (interface{}, error) {
	return base64.StdEncoding.EncodeToString(b), nil
}

func unmarshalYAMLCertificateByteSlice(
	value *yaml.Node,
	buf *[]byte,
	sliceType string,
	expectedLen int,
) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	if s == "" {
		*buf = nil
		return nil
	}
	v, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	if l := len(v); l != expectedLen {
		return fmt.Errorf("%s has length %d but should have length %d", sliceType, expectedLen, l)
	}
	*buf = v
	return nil
}

func readPrivateKey(keyFile string) (ed25519.PrivateKey, error) {
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("error reading certificate private key file at '%s': %w", keyFile, err)
	}
	return ed25519.NewKeyFromSeed(key), nil
}
