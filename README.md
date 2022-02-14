crypto-project
==============

My personal attempt to implement [this cipher](https://ciphersuite.info/cs/TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256/) using the Go libraries for learning purposes.

First version uses shared secret key for HMAC+SHA256 authentication (mutual TLS only).

Next version should add support for ECDSA with a custom public key infrastructure (learning purposes!).
