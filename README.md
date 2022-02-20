crypto-project
==============

Personal project for the purpose of learning.

My personal attempt to implement the recommended cipher suite (as of 2022/Q1) [TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256](https://ciphersuite.info/cs/TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256/) using the Go standard library (as much as possible, as of 2022/Q1).

The code here does not implement the TLS protocol on every minimal detail, i.e. it is not actually compatible. The handshake and message transmission schemes are as simple as possible, only to accomplish the purpose of providing a proof-of-concept, secure, stream-oriented connection over an insecure channel. In other words, the code here only uses the specific set of cryptographic primitives of the TLS cipher suite above to implement Go's `net.Conn` interface on top of itself and does not provide a TLS-compatible implementation.

The public key infrastructure for the handshake authentication is also a custom construction for the purpose of learning, i.e. it is also not compatible with actual TLS.

## Cryptographic Primitives

### ECDHE Parameters
Curve25519.

### ECDSA Parameters
Ed25519.

Ed25519 is EdDSA using SHA-512 and Curve25519. EdDSA is ECDSA using Edwards curves.

### AEAD Parameters
XChaCha20-Poly1305.

XChaCha20-Poly1305 is the 24-byte nonce variant of the ChaCha20-Poly1305 AEAD, which is stronger for randomly generated nonces.

## References
- [Security StackExchange: ECDSA vs ECDH vs Ed25519 vs Curve25519](https://security.stackexchange.com/a/211484)
- [Wikipedia: Edwards Curves](https://en.wikipedia.org/wiki/Edwards_curve)
- [RFC7748: Elliptic Curves for Security](https://datatracker.ietf.org/doc/html/rfc7748)
- [RFC7905: ChaCha20-Poly1305 Cipher Suites for TLS](https://datatracker.ietf.org/doc/html/rfc7905)
- [RFC8032: EdDSA](https://datatracker.ietf.org/doc/html/rfc8032)
- [RFC8422: ECC Cipher Suites for TLS 1.2+](https://datatracker.ietf.org/doc/html/rfc8422)
- [RFC8439: ChaCha20 and Poly1305 for IETF Protocols](https://datatracker.ietf.org/doc/html/rfc8439)
