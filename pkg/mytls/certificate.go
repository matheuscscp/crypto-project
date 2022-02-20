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
	certificateRegistry       map[certificatePublicKeyArray]struct{}
	certificatePublicKeyArray [ed25519.PublicKeySize]byte

	certificate struct {
		Data      certifiedData        `yaml:"certifiedData"`
		Signature certificateSignature `yaml:"certifiedDataSignature,omitempty"`
		Parent    *certificate         `yaml:"parentCertificate,omitempty"`
	}

	certifiedData struct {
		PublicKey    certificatePublicKey `yaml:"publicKey"`
		ExpiresAt    time.Time            `yaml:"expiresAt"`
		Organization string               `yaml:"organization"`
		Records      []string             `yaml:"records"`
	}

	certificatePublicKey  []byte
	certificateSignature  []byte
	certificateWireFormat []byte
	certificatePrivateKey []byte
)

var (
	untrustedRootCertificateErr       = errors.New("untrusted root certificate")
	untrustedSelfSignedCertificateErr = errors.New("untrusted self-signed certificate")
)

// GenerateCertificate generates an unsigned certificate with a random
// key pair.
//
// If duration <= 0, then duration is assigned 365 days.
func GenerateCertificate(duration time.Duration, certFile, keyFile string) error {
	pub, pri, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		return fmt.Errorf("error generating random key pair for certificate: %w", err)
	}

	var c certificate
	c.Data.PublicKey = certificatePublicKey(pub)
	if duration <= 0 {
		duration = time.Hour * 24 * 365
	}
	c.Data.ExpiresAt = time.Now().Add(duration)

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
// To self-sign a certificate pass parentCertFile == "". The behavior is
// undefined if certFile and parentCertFile point to the same file in the
// file system.
func SignCertificate(certFile, parentCertFile, parentKeyFile string) error {
	c, err := readCertificate(certFile)
	if err != nil {
		return err
	}

	c.Parent = nil
	if parentCertFile != "" {
		c.Parent, err = newCertificate(parentCertFile)
		if err != nil {
			return fmt.Errorf("error creating parent certificate: %w", err)
		}
	}

	key, err := newCertificatePrivateKey(parentKeyFile)
	if err != nil {
		return err
	}

	signingCert := c.Parent
	if signingCert == nil {
		signingCert = c
	}
	signingKey := ed25519.PrivateKey(key)
	if !ed25519.PublicKey(signingCert.Data.PublicKey).Equal(signingKey.Public()) {
		return errors.New("private key and signing certificate do not match")
	}

	c.Signature = ed25519.Sign(signingKey, c.deterministicallySerializeCertifiedData())
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

func (cr certificateRegistry) validate(b certificateWireFormat) (certificatePublicKey, error) {
	if len(b) == 0 {
		if len(cr) > 0 {
			return nil, errors.New("want certificate but got empty")
		}
		return nil, nil
	}

	c, err := parseWireCertificate(b)
	if err != nil {
		return nil, err
	}

	if err := c.validate(cr); err != nil {
		if errors.Is(err, untrustedRootCertificateErr) && c.Parent == nil {
			return nil, untrustedSelfSignedCertificateErr
		}
		return nil, err
	}

	return c.Data.PublicKey, nil
}

func newCertificate(certFile string) (*certificate, error) {
	c, err := readCertificate(certFile)
	if err != nil {
		return nil, err
	}
	if err := c.validate(nil /* certificateRegistry */); err != nil {
		return nil, fmt.Errorf("certificate is invalid: %w", err)
	}
	return c, nil
}

func readCertificate(certFile string) (*certificate, error) {
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

func newWireAuthentication(certFile, keyFile string) (certificateWireFormat, certificatePrivateKey, error) {
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

	key, err := newCertificatePrivateKey(keyFile)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

func parseWireCertificate(b certificateWireFormat) (*certificate, error) {
	var c certificate
	if err := gob.NewDecoder(bytes.NewBuffer(b)).Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *certificate) wireFormat() (certificateWireFormat, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(c); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (c *certificate) validate(cr certificateRegistry) error {
	if c.Parent == nil { // root
		key := c.Data.PublicKey.asArray()
		if err := c.validateWithPublicKey(key); err != nil {
			return err
		}

		if _, rootIsTrusted := cr[*key]; !rootIsTrusted && len(cr) > 0 {
			return untrustedRootCertificateErr
		}

		return nil
	}

	key := c.Parent.Data.PublicKey.asArray()
	if err := c.validateWithPublicKey(key); err != nil {
		return err
	}
	if _, parentIsTrusted := cr[*key]; parentIsTrusted {
		return nil
	}

	return c.Parent.validate(cr)
}

func (c *certificate) validateWithPublicKey(key *certificatePublicKeyArray) error {
	if !ed25519.Verify(key[:], c.deterministicallySerializeCertifiedData(), c.Signature) {
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

func (k certificatePublicKey) asArray() *certificatePublicKeyArray {
	return (*certificatePublicKeyArray)(k)
}

func (k certificatePublicKey) MarshalYAML() (interface{}, error) {
	return marshalYAMLCertificateByteSlice(k)
}

func (k *certificatePublicKey) UnmarshalYAML(value *yaml.Node) error {
	return unmarshalYAMLCertificateByteSlice(
		value,
		(*[]byte)(k),          // buf
		"public key",          // sliceType
		ed25519.PublicKeySize, // expectedLen
	)
}

func (s certificateSignature) MarshalYAML() (interface{}, error) {
	return marshalYAMLCertificateByteSlice(s)
}

func (s *certificateSignature) UnmarshalYAML(value *yaml.Node) error {
	return unmarshalYAMLCertificateByteSlice(
		value,
		(*[]byte)(s),          // buf
		"signature",           // sliceType
		ed25519.SignatureSize, // expectedLen
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

func newCertificatePrivateKey(keyFile string) (certificatePrivateKey, error) {
	seed, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("error reading certificate private key file at '%s': %w", keyFile, err)
	}

	var key certificatePrivateKey
	func() {
		defer func() {
			if p := recover(); p != nil {
				key = nil
				err = fmt.Errorf("error initializing certificate private key: %v", p)
			}
		}()
		key = certificatePrivateKey(ed25519.NewKeyFromSeed(seed))
	}()
	return key, err
}
