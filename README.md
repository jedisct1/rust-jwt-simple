# JWT-Simple (WIP)

A new JWT implementation for Rust that focuses on simplicity.

JWT-Simple is unopinionated and supports all commonly deployed authentication and signature algorithms:

* HMAC-SHA2
  * `HS256`
  * `HS384`
  * `HS512`
* RSA
  * `RS256`
  * `RS384`
  * `RS512`
  * `PS256`
  * `PS384`
  * `PS512`
* p256
  * `ES256`
* secp256k1
  * `ES256K`
* Ed25519
  * `EdDSA`

JWT-Simple uses only pure Rust implementations, and compiled out of the box to WebAssembly/WASI. It is fully compatible with Fastly's Compute@Edge service.
