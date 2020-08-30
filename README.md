[![GitHub CI](https://github.com/jedisct1/rust-jwt-simple/workflows/Rust/badge.svg)](https://github.com/jedisct1/rust-jwt-simple/actions)
[![Docs.rs](https://docs.rs/jwt-simple/badge.svg)](https://docs.rs/jwt-simple/)
[![crates.io](https://img.shields.io/crates/v/jwt-simple.svg)](https://crates.io/crates/jwt-simple)

# JWT-Simple

A new JWT implementation for Rust that focuses on simplicity, while avoid common JWT security pitfalls.

`jwt-simple` is unopinionated and supports all commonly deployed authentication and signature algorithms:

* HMAC-SHA2:
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

`jwt-simple` uses only pure Rust implementations, and can be compiled out of the box to WebAssembly/WASI. It is fully compatible with Fastly's _Compute@Edge_ service.

## Usage

## `cargo.toml`

```toml
[dependencies]
jwt-simple = "0.1"
```

## Authentication (symmetric, `HS*` JWT algorithms) example

Authentication schemes uses the same key for creating and verifying tokens. In other words, both parties need to be ultimately trusting each other, or else the verifier could also create arbitrary tokens.

### Keys and tokens creation

Key creation:

```rust
use jwt_simple::prelude::*;

// create a new key for the `HS256` JWT algorithm
let key = HS256Key::generate();
```

A key can be exported as bytes with `key.to_bytes()`, and restored with `HS256Key::from_bytes()`.

Token creation:

```rust
/// create claims valid for 2 hours
let claims = Claims::create(Duration::from_hours(2));
let token = key.authenticate(claims)?;
```

Done!

### Token verification

```rust
let claims = key.verify_token::<NoCustomClaims>(&token, None)?;
```

No additional steps required.

Key expiration, start time, authentication tag, etc. are automatically performed. The function call fails with `JWTError::InvalidAuthenticationTag` if the authentication tag is invalid for the given key.

The full set of claims can be inspected in the `claims` object if necessary. `NoCustomClaims` means that only the standard set of claims is used by the application, but application-defined claims are also supported.

Extra verification steps can optionally be enabled via the `ValidationOptions` structure:

```rust
let mut options = VerificationOptions::default();
// Accept tokens that will only be valid in the future
options.accept_future = true;
// accept tokens even if they have expired up to 15 minutes after the deadline
options.time_tolerance = Some(Duration::from_mins(15));
// reject tokens if they were issued more than 1 hour ago
options.max_validity = Some(Duration::from_hours(1));
// reject tokens if they don't come from a specific issuer
options.required_issuer = Some("example app".to_string());
// see the documentation for the full list of available options

let claims = key.verify_token::<NoCustomClaims>(&token, Some(options))?;
```

## Signatures (asymmetric, `RS*`, `PS*`, `ES*` and `EdDSA` algorithms) example

A signature requires a key pair: a secret key used to create tokens, and a public key, that can only verify them.

Always use a signature scheme if both parties do not ultimately trust each other, such as tokens exchanged between clients and API providers.

### Key pairs and tokens creation

Key creation:

```rust
use jwt_simple::prelude::*;

// create a new key pair for the `ES256` JWT algorithm
let key_pair = ES256KeyPair::generate();

// a public key can be extracted from a key pair:
let public_key = key_pair.public_key();
```

Keys can be exported as bytes for later reuse, and imported from bytes or, for RSA, from individual parameters, DER-encoded data or PEM-encoded data.

RSA key pair creation, using OpenSSL and PEM importation:

```sh
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

```rust
let key_pair = RS384KeyPair::from_pem(private_pem_file_content)?;
let public_key = RS384PublicKey::from_pem(public_pem_file_content)?;
```

Token creation and verification work the same way as with `HS*` algorithms, except that tokens are created with a key pair, and verified using the corresponding public key.

Token creation:

```rust
/// create claims valid for 2 hours
let claims = Claims::create(Duration::from_hours(2));
let token = key_pair.sign(claims)?;
```

Token verification:

```rust
let claims = public_key.verify_token::<NoCustomClaims>(&token, None)?;
```

Available verification options are identical to the ones used with symmetric algorithms.

## Advanced usage

### Custom claims

Claim objects support all the standard claims by default, and they can be set directly or via convenient helpers:

```rust
let claims = Claims::create(Duration::from_hours(2)).
    with_issuer("Example issuer").with_subject("Example subject");
```

But application-defined claims can also be defined. These simply have to be present in a serializable type (this requires the `serde` crate):

```rust
#[derive(Serialize, Deserialize)]
struct MyAdditionalData {
   user_is_admin: bool,
   user_country: String,
}
let my_additional_data = MyAdditionalData {
   user_is_admin: false,
   user_country: "FR".to_string(),
};
```

Claim creation with custom data:

```rust
let mut claims = Claims::with_custom_claims(my_additional_data, Duration::from_secs(30));
```

Claim verification wit custom data. Note the presence of the custom data type:

```rust
let claims = public_key.verify_token::<MyAdditionalData>(&token, None)?;
let user_is_admin = claims.custom.user_is_admin;
```

### Peeking at metadata before verification

Properties such as the key identifier can be useful prior to tag or signature verification in order to pick the right key out of a set.

```rust
let metadata = Token::decode_metadata(&token)?;
let key_id = metadata.key_id();
let algorithm = metadata.algorithm();
// all other standard properties are also accessible
```

### Creating and attaching key identifiers

Key identifiers indicate to verifiers what public key (or shared key) should be used for verification.
They can be attached at any time to existing shared keys, key pairs and public keys:

```rust
let public_key_with_id = public_key.with_key_id(&"unique key identifier");
```

Instead of delegating this to applications, `jwt-simple` can also create such an identifier for an existing key:

```rust
let key_id = public_key.create_key_id();
```

This creates an text-encoded identifier for the key, attaches it, and returns it.

If an identifier has been attached to a shared key or a key pair, tokens created with them will include it.

## Why yet another JWT crate

This crate is not an endorsement of JWT. JWT is an awful design, and one of the many examples that "but this is a standard" doesn't necessarily mean that it is good.

I would highly recommend [PASETO](https://github.com/paragonie/paseto) instead if you control both token creation and verification.

However, JWT is still widely used in the industry, and remains absolutely mandatory to communicate with popular APIs.

This crate was designed to:

* Be simple to use, even to people who are new to Rust
* Avoid common JWT API pitfalls
* Support features widely in use. I'd love to limit the algorithm choices to Ed25519, but other methods are required to connect to existing APIs, so just provide them (with the exception of the `None` signature method for obvious reasons).
* Minimize code complexity and external dependencies
* Automatically perform common tasks to prevent misuse. Signature verification and claims validation happen automatically instead of relying on applications.
* Still allow power users to access everything JWT tokens include if they really need to
* Be as portable as possible by using only Rust implementations of cryptographic primitives
* Work out of the box in a WebAssembly environment, so that it can be used in function-as-a-service platforms.
