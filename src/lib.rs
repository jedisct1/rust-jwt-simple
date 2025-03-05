//! [![GitHub CI](https://github.com/jedisct1/rust-jwt-simple/workflows/Rust/badge.svg)](https://github.com/jedisct1/rust-jwt-simple/actions)
//! [![Docs.rs](https://docs.rs/jwt-simple/badge.svg)](https://docs.rs/jwt-simple/)
//! [![crates.io](https://img.shields.io/crates/v/jwt-simple.svg)](https://crates.io/crates/jwt-simple)
//!
//! <!-- @import "[TOC]" {cmd="toc" depthFrom=1 depthTo=6 orderedList=false} -->
//!
//! <!-- code_chunk_output -->
//!
//! - [JWT-Simple](#jwt-simple)
//! - [Usage](#usage)
//! - [Authentication (symmetric, `HS*` JWT algorithms) example](#authentication-symmetric-hs-jwt-algorithms-example)
//! - [Keys and tokens creation](#keys-and-tokens-creation)
//! - [Token verification](#token-verification)
//! - [Signatures (asymmetric, `RS*`, `PS*`, `ES*` and `EdDSA` algorithms) example](#signatures-asymmetric-rs-ps-es-and-eddsa-algorithms-example)
//! - [Key pairs and tokens creation](#key-pairs-and-tokens-creation)
//! - [ES256](#es256)
//! - [ES384](#es384)
//! - [Advanced usage](#advanced-usage)
//! - [Custom claims](#custom-claims)
//! - [Peeking at metadata before verification](#peeking-at-metadata-before-verification)
//! - [Creating and attaching key identifiers](#creating-and-attaching-key-identifiers)
//! - [Mitigations against replay attacks](#mitigations-against-replay-attacks)
//! - [CWT (CBOR) support](#cwt-cbor-support)
//! - [Working around compilation issues with the `boring` crate](#working-around-compilation-issues-with-the-boring-crate)
//! - [Usage in Web browsers](#usage-in-web-browsers)
//! - [Why yet another JWT crate](#why-yet-another-jwt-crate)
//!
//! <!-- /code_chunk_output -->
//!
//! # JWT-Simple
//!
//! A new JWT (JSON Web Tokens) implementation for Rust that focuses on simplicity, while avoiding common JWT security pitfalls.
//!
//! `jwt-simple` is unopinionated and supports all commonly deployed authentication and signature algorithms:
//!
//! | JWT algorithm name | Description                           |
//! | ------------------ | ------------------------------------- |
//! | `HS256`            | HMAC-SHA-256                          |
//! | `HS384`            | HMAC-SHA-384                          |
//! | `HS512`            | HMAC-SHA-512                          |
//! | `BLAKE2B`          | BLAKE2B-256                           |
//! | `RS256`            | RSA with PKCS#1v1.5 padding / SHA-256 |
//! | `RS384`            | RSA with PKCS#1v1.5 padding / SHA-384 |
//! | `RS512`            | RSA with PKCS#1v1.5 padding / SHA-512 |
//! | `PS256`            | RSA with PSS padding / SHA-256        |
//! | `PS384`            | RSA with PSS padding / SHA-384        |
//! | `PS512`            | RSA with PSS padding / SHA-512        |
//! | `ES256`            | ECDSA over p256 / SHA-256             |
//! | `ES384`            | ECDSA over p384 / SHA-384             |
//! | `ES256K`           | ECDSA over secp256k1 / SHA-256        |
//! | `EdDSA`            | Ed25519                               |
//!
//! `jwt-simple` can be compiled out of the box to WebAssembly/WASI. It is fully compatible with Fastly _Compute_ service.
//!
//! Important: JWT's purpose is to verify that data has been created by a party knowing a secret key. It does not provide any kind of confidentiality: JWT data is simply encoded as BASE64, and is not encrypted.
//!
//! ## Usage
//!
//! `cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! jwt-simple = "0.12"
//! ```
//!
//! Rust:
//!
//! ```rust
//! use jwt_simple::prelude::*;
//! ```
//!
//! Errors are returned as `jwt_simple::Error` values (alias for the `Error` type of the `thiserror` crate).
//!
//! ## Authentication (symmetric, `HS*` JWT algorithms) example
//!
//! Authentication schemes use the same key for creating and verifying tokens. In other words, both parties need to ultimately trust each other, or else the verifier could also create arbitrary tokens.
//!
//! ### Keys and tokens creation
//!
//! Key creation:
//!
//! ```rust
//! use jwt_simple::prelude::*;
//!
//! // create a new key for the `HS256` JWT algorithm
//! let key = HS256Key::generate();
//! ```
//!
//! A key can be exported as bytes with `key.to_bytes()`, and restored with `HS256Key::from_bytes()`.
//!
//! Token creation:
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # fn main() -> Result<(), jwt_simple::Error> {
//! # let key = HS256Key::generate();
//! /// create claims valid for 2 hours
//! let claims = Claims::create(Duration::from_hours(2));
//! let token = key.authenticate(claims)?;
//! # Ok(())
//! # }
//! ```
//!
//! -> Done!
//!
//! ### Token verification
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # fn main() -> Result<(), jwt_simple::Error> {
//! # let key = HS256Key::generate();
//! # let claims = Claims::create(Duration::from_hours(2));
//! # let token = key.authenticate(claims)?;
//! let claims = key.verify_token::<NoCustomClaims>(&token, None)?;
//! # Ok(())
//! # }
//! ```
//!
//! -> Done! No additional steps required.
//!
//! Key expiration, start time, authentication tags, etc. are automatically verified. The function fails with `JWTError::InvalidAuthenticationTag` if the authentication tag is invalid for the given key.
//!
//! The full set of claims can be inspected in the `claims` object if necessary. `NoCustomClaims` means that only the standard set of claims is used by the application, but application-defined claims can also be supported.
//!
//! Extra verification steps can optionally be enabled via the `ValidationOptions` structure:
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # fn xmain() -> Result<(), jwt_simple::Error> {
//! # let key = HS256Key::generate();
//! # let claims = Claims::create(Duration::from_hours(2));
//! # let token = key.authenticate(claims)?;
//! let mut options = VerificationOptions::default();
//! // Accept tokens that will only be valid in the future
//! options.accept_future = true;
//! // Accept tokens even if they have expired up to 15 minutes after the deadline,
//! // and/or they will be valid within 15 minutes.
//! // Note that 15 minutes is the default, since it is very common for clocks to be slightly off.
//! options.time_tolerance = Some(Duration::from_mins(15));
//! // Reject tokens if they were issued more than 1 hour ago
//! options.max_validity = Some(Duration::from_hours(1));
//! // Reject tokens if they don't include an issuer from that set
//! options.allowed_issuers = Some(HashSet::from_strings(&["example app"]));
//!
//! // see the documentation for the full list of available options
//!
//! let claims = key.verify_token::<NoCustomClaims>(&token, Some(options))?;
//! # Ok(())
//! # }
//! # fn main() { xmain().ok(); }
//! ```
//!
//! Note that `allowed_issuers` and `allowed_audiences` are not strings, but sets of strings (using the `HashSet` type from the Rust standard library), as the application can allow multiple return values.
//!
//! ## Signatures (asymmetric, `RS*`, `PS*`, `ES*` and `EdDSA` algorithms) example
//!
//! A signature requires a key pair: a secret key used to create tokens, and a public key, that can only verify them.
//!
//! Always use a signature scheme if both parties do not ultimately trust each other, such as tokens exchanged between clients and API providers.
//!
//! ### Key pairs and tokens creation
//!
//! Key creation:
//!
//! #### ES256
//!
//! ```rust
//! use jwt_simple::prelude::*;
//!
//! // create a new key pair for the `ES256` JWT algorithm
//! let key_pair = ES256KeyPair::generate();
//!
//! // a public key can be extracted from a key pair:
//! let public_key = key_pair.public_key();
//! ```
//!
//! #### ES384
//!
//! ```rust
//! use jwt_simple::prelude::*;
//!
//! // create a new key pair for the `ES384` JWT algorithm
//! let key_pair = ES384KeyPair::generate();
//!
//! // a public key can be extracted from a key pair:
//! let public_key = key_pair.public_key();
//! ```
//!
//! Keys can be exported as bytes for later reuse, and imported from bytes or, for RSA, from individual parameters, DER-encoded data or PEM-encoded data.
//!
//! RSA key pair creation, using OpenSSL and PEM importation of the secret key:
//!
//! ```sh
//! openssl genrsa -out private.pem 2048
//! openssl rsa -in private.pem -outform PEM -pubout -out public.pem
//! ```
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # fn xmain() -> Result<(), jwt_simple::Error> {
//! # let private_pem_file_content = "test";
//! # let public_pem_file_content = "test";
//! let key_pair = RS384KeyPair::from_pem(private_pem_file_content)?;
//! let public_key = RS384PublicKey::from_pem(public_pem_file_content)?;
//! # Ok(())
//! # }
//! # fn main() { xmain().ok(); }
//! ```
//!
//! Token creation and verification work the same way as with `HS*` algorithms, except that tokens are created with a key pair, and verified using the corresponding public key.
//!
//! Token creation:
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # fn xmain() -> Result<(), jwt_simple::Error> {
//! # let private_pem_file_content = "test";
//! # let key_pair = RS384KeyPair::from_pem(private_pem_file_content)?;
//! /// create claims valid for 2 hours
//! let claims = Claims::create(Duration::from_hours(2));
//! let token = key_pair.sign(claims)?;
//! # Ok(())
//! # }
//! # fn main() { xmain().ok(); }
//! ```
//!
//! Token verification:
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # fn xmain() -> Result<(), jwt_simple::Error> {
//! # let private_pem_file_content = "test";
//! # let public_pem_file_content = "test";
//! # let key_pair = RS384KeyPair::from_pem(private_pem_file_content)?;
//! # let public_key = RS384PublicKey::from_pem(public_pem_file_content)?;
//! # let claims = Claims::create(Duration::from_hours(2));
//! # let token = key_pair.sign(claims)?;
//! let claims = public_key.verify_token::<NoCustomClaims>(&token, None)?;
//! # Ok(())
//! # }
//! # fn main() { xmain().ok(); }
//! ```
//!
//! Available verification options are identical to the ones used with symmetric algorithms.
//!
//! ## Advanced usage
//!
//! ### Custom claims
//!
//! Claim objects support all the standard claims by default, and they can be set directly or via convenient helpers:
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! let claims = Claims::create(Duration::from_hours(2)).
//! with_issuer("Example issuer").with_subject("Example subject");
//! ```
//!
//! But application-defined claims can also be defined. These simply have to be present in a serializable type (this requires the `serde` crate):
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # use serde::{de::DeserializeOwned, Serialize};
//! #[derive(Serialize, Deserialize)]
//! struct MyAdditionalData {
//! user_is_admin: bool,
//! user_country: String,
//! }
//! let my_additional_data = MyAdditionalData {
//! user_is_admin: false,
//! user_country: "FR".to_string(),
//! };
//! ```
//!
//! Claim creation with custom data:
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # use serde::{de::DeserializeOwned, Serialize};
//! # #[derive(Serialize, Deserialize)]
//! # struct MyAdditionalData {user_is_admin: bool}
//! # fn main() -> Result<(), jwt_simple::Error> {
//! # let my_additional_data = MyAdditionalData {user_is_admin: false};
//! let claims = Claims::with_custom_claims(my_additional_data, Duration::from_secs(30));
//! # Ok(())
//! # }
//! ```
//!
//! Claim verification with custom data. Note the presence of the custom data type:
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # use serde::{de::DeserializeOwned, Serialize};
//! # #[derive(Serialize, Deserialize)]
//! # struct MyAdditionalData {user_is_admin: bool}
//! # fn xmain() -> Result<(), jwt_simple::Error> {
//! # let kp = Ed25519KeyPair::generate();
//! # let claims = Claims::create(Duration::from_secs(86400));
//! # let token = kp.sign(claims)?;
//! # let public_key = kp.public_key();
//! let claims = public_key.verify_token::<MyAdditionalData>(&token, None)?;
//! let user_is_admin = claims.custom.user_is_admin;
//! # Ok(())
//! # }
//! # fn main() { xmain().ok(); }
//! ```
//!
//! ### Peeking at metadata before verification
//!
//! Properties such as the key identifier can be useful prior to tag or signature verification in order to pick the right key out of a set.
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # fn main() -> Result<(), jwt_simple::Error> {
//! # let key = RS384KeyPair::generate(3072)?;
//! # let claims = Claims::create(Duration::from_secs(86400));
//! # let token = key.sign(claims)?;
//! let metadata = Token::decode_metadata(&token)?;
//! let key_id = metadata.key_id();
//! let algorithm = metadata.algorithm();
//! // all other standard properties are also accessible
//! # Ok(())
//! # }
//! ```
//!
//! **IMPORTANT:** neither the key ID nor the algorithm can be trusted. This is an unfixable design flaw of the JWT standard.
//!
//! As a result, `algorithm` should be used only for debugging purposes, and never to select a key type.
//! Similarly, `key_id` should be used only to select a key in a set of keys made for the same algorithm.
//!
//! At the bare minimum, verification using `HS*` must be prohibited if a signature scheme was originally used to create the token.
//!
//! ### Creating and attaching key identifiers
//!
//! Key identifiers indicate to verifiers what public key (or shared key) should be used for verification.
//! They can be attached at any time to existing shared keys, key pairs and public keys:
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # let public_key = Ed25519KeyPair::generate().public_key();
//! let public_key_with_id = public_key.with_key_id(&"unique key identifier");
//! ```
//!
//! Instead of delegating this to applications, `jwt-simple` can also create such an identifier for an existing key:
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # let mut public_key = Ed25519KeyPair::generate().public_key();
//! let key_id = public_key.create_key_id();
//! ```
//!
//! This creates an text-encoded identifier for the key, attaches it, and returns it.
//!
//! If an identifier has been attached to a shared key or a key pair, tokens created with them will include it.
//!
//! ### Mitigations against replay attacks
//!
//! `jwt-simple` includes mechanisms to mitigate replay attacks:
//!
//! - Nonces can be created and attached to new tokens using the `create_nonce()` claim function. The verification procedure can later reject any token that doesn't include the expected nonce (`required_nonce` verification option).
//! - The verification procedure can reject tokens created too long ago, no matter what their expiration date is. This prevents tokens from malicious (or compromised) signers from being used for too long.
//! - The verification procedure can reject tokens created before a date. For a given user, the date of the last successful authentication can be stored in a database, and used later along with this option to reject older (replayed) tokens.
//!
//! ### Salted keys
//!
//! Symmetric keys, such as the ones use with the `HS256`, `HS384`, `HS512` and `BLAKE2B` algorithms, are simple and fast, but have a major downside: signature and verification use the exact same key. Therefore, an adversary having access to the verifier key can forge arbitrary, valid tokens.
//!
//! Salted keys mitigate this issue the following way:
//!
//! - A random signer salt is created, and attached to the shared key. This salt is meant to be only known by the signer.
//! - Another salt is computed from the signer salt, and is meant to be used for verification.
//! - The verifier salt is used to verify the signer salt, which is included in tokens, in the `salt` JWT header.
//!
//! If the verifier has access to tokens, it can forge arbitrary tokens. But given only the verification code and keys, this is impossible. This greatly improve the security of symmetric keys used for verification on 3rd party servers, such as CDNs.
//!
//! A salt binds to a key, and can be of any length. The `generate_with_salt()` function generates both a random symmetric key, and a 32-byte salt.
//!
//! Example usage:
//!
//! ```rust
//! /// Create a random key and a signer salt
//! # use jwt_simple::prelude::*;
//! # fn main() -> Result<(), jwt_simple::Error> {
//! let key = HS256Key::generate_with_salt();
//! let claims = Claims::create(Duration::from_secs(86400));
//! let token = key.authenticate(claims).unwrap();
//! # Ok(())
//! # }
//! ```
//!
//! A salt is a `Salt` enum, because it can be either a salt for signing, or a salt for verification.
//! It can be saved and restored:
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # fn main() -> Result<(), jwt_simple::Error> {
//! let mut key = HS256Key::generate_with_salt();
//! /// Get the salt
//! let salt = key.salt();
//! /// Attach an existing salt to a key
//! key.attach_salt(salt)?;
//! # Ok(())
//! # }
//! ```
//!
//! Given a signer salt, the corresponding verifier salt can be computed:
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # fn main() -> Result<(), jwt_simple::Error> {
//! # let key = HS256Key::generate_with_salt();
//! /// Compute the verifier salt, given a signer salt
//! let verifier_salt = key.verifier_salt()?;
//! # Ok(())
//! # }
//! ```
//!
//! The verifier salt doesn't have to be secret, and can even be hard-coded in the verification code.
//!
//! Verification:
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # fn xmain() -> Result<(), jwt_simple::Error> {
//! # let verifier_salt_bytes = b"verifier salt".to_vec();
//! # let mut key = HS256Key::generate_with_salt();
//! # let claims = Claims::create(Duration::from_secs(86400));
//! # let token = key.authenticate(claims)?;
//! let verifier_salt = Salt::Verifier(verifier_salt_bytes);
//! key.attach_salt(verifier_salt)?;
//! let claims = key.verify_token::<NoCustomClaims>(&token, None)?;
//! # Ok(())
//! # }
//! # fn main() { xmain().ok(); }
//! ```
//!
//! ### CWT (CBOR) support
//!
//! The development code includes a `cwt` cargo feature that enables experimental parsing and validation of CWT tokens.
//!
//! Please note that CWT doesn't support custom claims. The required identifiers [haven't been standardized yet](https://www.iana.org/assignments/cwt/cwt.xhtml).
//!
//! Also, the existing Rust crates for JSON and CBOR deserialization are not safe. An untrusted party can send a serialized object that requires a lot of memory and CPU to deserialize. Band-aids have been added for JSON, but with the current Rust tooling, it would be tricky to do for CBOR.
//!
//! As a mitigation, we highly recommend rejecting tokens that would be too large in the context of your application. That can be done by with the `max_token_length` verification option.
//!
//!
//! ### Specifying Content Type
//!
//! Sometimes, it is necessary to set the `content_type` (`cty`) header field that will be associated with a JWT signed with a given key, typically in cases involving nested JWTs. By default, `jwt_simple` omits this field. However, it is possible to set a custom content type by associating it with the key before signing the claims:
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # let mut key_pair = Ed25519KeyPair::generate();
//! key_pair.for_content_type(Some("JWT".into())).unwrap();
//! ```
//!
//! ### Specifying Signature Type
//!
//! The `signature_type` (`typ`) field in the JWT header is sometimes used to differentiate JWTs. This can be set for a key similarly to how content_type can be set:
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # let mut key_pair = Ed25519KeyPair::generate();
//! key_pair.for_signature_type(Some("type+jwt".into())).unwrap();
//! ```
//!
//! If unset, the field will contain the string "JWT" in the serialized token.
//!
//! ### Validating content and signature types
//!
//! By default, `jwt_simple` ignores the `content_type` field when doing validation, and checks `signature_type` to ensure it is either exactly `JWT` or ends in `+JWT`, case insensitive, if it is present. Both fields may instead be case-insensitively compared against an expected string:
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # let mut options = VerificationOptions::default();
//! options.required_signature_type = Some("JWT".into());
//! options.required_content_type = Some("foo+jwt".into());
//! ```
//!
//! When validating CWTs, note that CWTs do not have a `content_type` field in their header, and therefore attempting to match a specific one by setting `required_content_type`during validation will **always result in an error**.
//!
//! ## Working around compilation issues with the `boring` crate
//!
//! As a temporary workaround for portability issues with one of the dependencies (the `boring` crate), this library can be compiled to use only Rust implementations.
//!
//! In order to do so, import the crate with `default-features=false, features=["pure-rust"]` in your Cargo configuration.
//!
//! Do not do it unconditionally. This is only required for very specific setups and targets, and only until issues with the `boring` crate have been solved. The way to configure this in Cargo may also change in future versions.
//!
//! Static builds targeting the `musl` library don't require that workaround. Just use [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild) to build your project.
//!
//! ## Usage in Web browsers
//!
//! The `wasm32-freestanding` target (still sometimes called `wasm32-unknown-unknown` in Rust) is supported (as in "it compiles").
//!
//! However, using a native JavaScript implementation is highly recommended instead. There are high-quality JWT implementations in JavaScript, leveraging the WebCrypto API, that provide better performance and security guarantees than a WebAssembly module.
//!
//! ## Why yet another JWT crate
//!
//! This crate is not an endorsement of JWT. JWT is [an awful design](https://tools.ietf.org/html/rfc8725), and one of the many examples that "but this is a standard" doesn't necessarily mean that it is good.
//!
//! I would highly recommend [PASETO](https://github.com/paragonie/paseto) or [Biscuit](https://github.com/CleverCloud/biscuit) instead if you control both token creation and verification.
//!
//! However, JWT is still widely used in the industry, and remains absolutely mandatory to communicate with popular APIs.
//!
//! This crate was designed to:
//!
//! - Be simple to use, even to people who are new to Rust
//! - Avoid common JWT API pitfalls
//! - Support features widely in use. I'd love to limit the algorithm choices to Ed25519, but other methods are required to connect to existing APIs, so just provide them (with the exception of the `None` signature method for obvious reasons).
//! - Minimize code complexity and external dependencies
//! - Automatically perform common tasks to prevent misuse. Signature verification and claims validation happen automatically instead of relying on applications.
//! - Still allow power users to access everything JWT tokens include if they really need to
//! - Work out of the box in a WebAssembly environment, so that it can be used in function-as-a-service platforms.

#![forbid(unsafe_code)]

#[cfg(all(feature = "pure-rust", feature = "optimal"))]
compile_error!("jwt-simple: the `optimal` feature is only available when the `pure-rust` feature is disabled - Consider disabling default Cargo features.");

#[cfg(all(not(feature = "pure-rust"), not(feature = "optimal")))]
compile_error!("jwt-simple: the `optimal` feature is required when the `pure-rust` feature is disabled - Consider enabling default Cargo features.");

pub mod algorithms;
pub mod claims;
pub mod common;
#[cfg(feature = "cwt")]
pub mod cwt_token;
pub mod token;

mod jwt_header;
mod serde_additions;

pub mod reexports {
    pub use anyhow;
    pub use coarsetime;
    pub use ct_codecs;
    pub use rand;
    pub use serde;
    pub use serde_json;
    pub use thiserror;
    pub use zeroize;
}

mod error;
pub use error::{Error, JWTError};

pub mod prelude {
    pub use std::collections::HashSet;

    pub use coarsetime::{self, Clock, Duration, UnixTimeStamp};
    pub use ct_codecs::{
        Base64, Base64NoPadding, Base64UrlSafe, Base64UrlSafeNoPadding, Decoder as _, Encoder as _,
    };
    pub use serde::{Deserialize, Serialize};

    pub use crate::algorithms::*;
    pub use crate::claims::*;
    pub use crate::common::*;
    #[cfg(feature = "cwt")]
    pub use crate::cwt_token::*;
    pub use crate::token::*;

    mod hashset_from_strings {
        use std::collections::HashSet;

        pub trait HashSetFromStringsT {
            /// Create a set from a list of strings
            fn from_strings(strings: &[impl ToString]) -> HashSet<String> {
                strings.iter().map(|x| x.to_string()).collect()
            }
        }

        impl HashSetFromStringsT for HashSet<String> {}
    }

    pub use hashset_from_strings::HashSetFromStringsT as _;
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    const RSA_KP_PEM: &str = r"
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyqq0N5u8Jvl+BLH2VMP/NAv/zY9T8mSq0V2Gk5Ql5H1a+4qi
3viorUXG3AvIEEccpLsW85ps5+I9itp74jllRjA5HG5smbb+Oym0m2Hovfj6qP/1
m1drQg8oth6tNmupNqVzlGGWZLsSCBLuMa3pFaPhoxl9lGU3XJIQ1/evMkOb98I3
hHb4ELn3WGtNlAVkbP20R8sSii/zFjPqrG/NbSPLyAl1ctbG2d8RllQF1uRIqYQj
85yx73hqQCMpYWU3d9QzpkLf/C35/79qNnSKa3t0cyDKinOY7JGIwh8DWAa4pfEz
gg56yLcilYSSohXeaQV0nR8+rm9J8GUYXjPK7wIDAQABAoIBAQCpeRPYyHcPFGTH
4lU9zuQSjtIq/+bP9FRPXWkS8bi6GAVEAUtvLvpGYuoGyidTTVPrgLORo5ncUnjq
KwebRimlBuBLIR/Zboery5VGthoc+h4JwniMnQ6JIAoIOSDZODA5DSPYeb58n15V
uBbNHkOiH/eoHsG/nOAtnctN/cXYPenkCfeLXa3se9EzkcmpNGhqCBL/awtLU17P
Iw7XxsJsRMBOst4Aqiri1GQI8wqjtXWLyfjMpPR8Sqb4UpTDmU1wHhE/w/+2lahC
Tu0/+sCWj7TlafYkT28+4pAMyMqUT6MjqdmGw8lD7/vXv8TF15NU1cUv3QSKpVGe
50vlB1QpAoGBAO1BU1evrNvA91q1bliFjxrH3MzkTQAJRMn9PBX29XwxVG7/HlhX
0tZRSR92ZimT2bAu7tH0Tcl3Bc3NwEQrmqKlIMqiW+1AVYtNjuipIuB7INb/TUM3
smEh+fn3yhMoVxbbh/klR1FapPUFXlpNv3DJHYM+STqLMhl9tEc/I7bLAoGBANqt
zR6Kovf2rh7VK/Qyb2w0rLJE7Zh/WI+r9ubCba46sorqkJclE5cocxWuTy8HWyQp
spxzLP1FQlsI+MESgRLueoH3HtB9lu/pv6/8JlNjU6SzovfUZ0KztVUyUeB4vAcH
pGcf2CkUtoYc8YL22Ybck3s8ThIdnY5zphCF55PtAoGAf46Go3c05XVKx78R05AD
D2/y+0mnSGSzUjHPMzPyadIPxhltlCurlERhnwPGC4aNHFcvWTwS8kUGns6HF1+m
JNnI1okSCW10UI/jTJ1avfwU/OKIBKKWSfi9cDJTt5cRs51V7pKnVEr6sy0uvDhe
u+G091HuhwY9ak0WNtPwfJ8CgYEAuRdoyZQQso7x/Bj0tiHGW7EOB2n+LRiErj6g
odspmNIH8zrtHXF9bnEHT++VCDpSs34ztuZpywnHS2SBoHH4HD0MJlszksbqbbDM
1bk3+1bUIlEF/Hyk1jljn3QTB0tJ4y1dwweaH9NvVn7DENW9cr/aePGnJwA4Lq3G
fq/IPlUCgYAuqgJQ4ztOq0EaB75xgqtErBM57A/+lMWS9eD/euzCEO5UzWVaiIJ+
nNDmx/jvSrxA1Ih8TEHjzv4ezLFYpaJrTst4Mjhtx+csXRJU9a2W6HMXJ4Kdn8rk
PBziuVURslNyLdlFsFlm/kfvX+4Cxrbb+pAGETtRTgmAoCDbvuDGRQ==
-----END RSA PRIVATE KEY-----
    ";

    const RSA_PK_PEM: &str = r"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyqq0N5u8Jvl+BLH2VMP/
NAv/zY9T8mSq0V2Gk5Ql5H1a+4qi3viorUXG3AvIEEccpLsW85ps5+I9itp74jll
RjA5HG5smbb+Oym0m2Hovfj6qP/1m1drQg8oth6tNmupNqVzlGGWZLsSCBLuMa3p
FaPhoxl9lGU3XJIQ1/evMkOb98I3hHb4ELn3WGtNlAVkbP20R8sSii/zFjPqrG/N
bSPLyAl1ctbG2d8RllQF1uRIqYQj85yx73hqQCMpYWU3d9QzpkLf/C35/79qNnSK
a3t0cyDKinOY7JGIwh8DWAa4pfEzgg56yLcilYSSohXeaQV0nR8+rm9J8GUYXjPK
7wIDAQAB
-----END PUBLIC KEY-----
    ";

    #[test]
    fn hs384() {
        let key = HS384Key::from_bytes(b"your-256-bit-secret").with_key_id("my-key-id");
        let claims = Claims::create(Duration::from_secs(86400)).with_issuer("test issuer");
        let token = key.authenticate(claims).unwrap();
        let options = VerificationOptions {
            allowed_issuers: Some(HashSet::from_strings(&["test issuer"])),
            ..Default::default()
        };
        let _claims = key
            .verify_token::<NoCustomClaims>(&token, Some(options))
            .unwrap();
    }

    #[test]
    fn blake2b() {
        let key = Blake2bKey::from_bytes(b"your-256-bit-secret").with_key_id("my-key-id");
        let claims = Claims::create(Duration::from_secs(86400)).with_issuer("test issuer");
        let token = key.authenticate(claims).unwrap();
        let options = VerificationOptions {
            allowed_issuers: Some(HashSet::from_strings(&["test issuer"])),
            ..Default::default()
        };
        let _claims = key
            .verify_token::<NoCustomClaims>(&token, Some(options))
            .unwrap();
    }

    #[test]
    fn rs256() {
        let key_pair = RS256KeyPair::from_pem(RSA_KP_PEM).unwrap();
        let claims = Claims::create(Duration::from_secs(86400));
        let token = key_pair.sign(claims).unwrap();
        let pk = RS256PublicKey::from_pem(RSA_PK_PEM).unwrap();
        let _claims = pk.verify_token::<NoCustomClaims>(&token, None).unwrap();
        let components = pk.to_components();
        let hex_e = Base64::encode_to_string(components.e).unwrap();
        let _e = Base64::decode_to_vec(hex_e, None).unwrap();
    }

    #[test]
    fn ps384() {
        let key_pair = PS384KeyPair::generate(2048).unwrap();
        let claims = Claims::create(Duration::from_secs(86400));
        let token = key_pair.sign(claims).unwrap();
        let _claims = key_pair
            .public_key()
            .verify_token::<NoCustomClaims>(&token, None)
            .unwrap();
    }

    #[test]
    fn es256() {
        let key_pair = ES256KeyPair::generate();
        let claims = Claims::create(Duration::from_secs(86400));
        let token = key_pair.sign(claims).unwrap();
        let _claims = key_pair
            .public_key()
            .verify_token::<NoCustomClaims>(&token, None)
            .unwrap();
    }

    #[test]
    fn es384() {
        let key_pair = ES384KeyPair::generate();
        let claims = Claims::create(Duration::from_secs(86400));
        let token = key_pair.sign(claims).unwrap();
        let _claims = key_pair
            .public_key()
            .verify_token::<NoCustomClaims>(&token, None)
            .unwrap();
    }

    #[test]
    fn es256k() {
        let key_pair = ES256kKeyPair::generate();
        let claims = Claims::create(Duration::from_secs(86400));
        let token = key_pair.sign(claims).unwrap();
        let _claims = key_pair
            .public_key()
            .verify_token::<NoCustomClaims>(&token, None)
            .unwrap();
    }

    #[test]
    fn ed25519() {
        #[derive(Serialize, Deserialize)]
        struct CustomClaims {
            is_custom: bool,
        }

        let key_pair = Ed25519KeyPair::generate();
        let mut pk = key_pair.public_key();
        let key_id = pk.create_key_id();
        let key_pair = key_pair.with_key_id(key_id);
        let custom_claims = CustomClaims { is_custom: true };
        let claims = Claims::with_custom_claims(custom_claims, Duration::from_secs(86400));
        let token = key_pair.sign(claims).unwrap();
        let options = VerificationOptions {
            required_key_id: Some(key_id.to_string()),
            ..Default::default()
        };
        let claims: JWTClaims<CustomClaims> = key_pair
            .public_key()
            .verify_token::<CustomClaims>(&token, Some(options))
            .unwrap();
        assert!(claims.custom.is_custom);
    }

    #[test]
    fn ed25519_der() {
        let key_pair = Ed25519KeyPair::generate();
        let der = key_pair.to_der();
        let key_pair2 = Ed25519KeyPair::from_der(&der).unwrap();
        assert_eq!(key_pair.to_bytes(), key_pair2.to_bytes());
    }

    #[test]
    fn require_nonce() {
        let key = HS256Key::generate();
        let mut claims = Claims::create(Duration::from_hours(1));
        let nonce = claims.create_nonce();
        let token = key.authenticate(claims).unwrap();

        let options = VerificationOptions {
            required_nonce: Some(nonce),
            ..Default::default()
        };
        key.verify_token::<NoCustomClaims>(&token, Some(options))
            .unwrap();
    }

    #[test]
    fn eddsa_pem() {
        let sk_pem = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMXY1NUbUe/3dW2YUoKW5evsnCJPMfj60/q0RzGne3gg
-----END PRIVATE KEY-----\n";
        let pk_pem = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAyrRjJfTnhMcW5igzYvPirFW5eUgMdKeClGzQhd4qw+Y=
-----END PUBLIC KEY-----\n";
        let kp = Ed25519KeyPair::from_pem(sk_pem).unwrap();
        assert_eq!(kp.public_key().to_pem(), pk_pem);
    }

    #[test]
    fn key_metadata() {
        let mut key_pair = Ed25519KeyPair::generate();
        let thumbprint = key_pair.public_key().sha1_thumbprint();
        let key_metadata = KeyMetadata::default()
            .with_certificate_sha1_thumbprint(&thumbprint)
            .unwrap();
        key_pair.attach_metadata(key_metadata).unwrap();

        let claims = Claims::create(Duration::from_secs(86400));
        let token = key_pair.sign(claims).unwrap();

        let decoded_metadata = Token::decode_metadata(&token).unwrap();
        assert_eq!(
            decoded_metadata.certificate_sha1_thumbprint(),
            Some(thumbprint.as_ref())
        );
        let _ = key_pair
            .public_key()
            .verify_token::<NoCustomClaims>(&token, None)
            .unwrap();
    }

    #[test]
    fn set_header_content_type() {
        let mut key_pair = Ed25519KeyPair::generate();
        key_pair.for_content_type(Some("foo".into())).unwrap();
        let claims = Claims::create(Duration::from_secs(86400));
        let token = key_pair.sign(claims).unwrap();
        let decoded_metadata = Token::decode_metadata(&token).unwrap();
        assert_eq!(
            decoded_metadata.jwt_header.content_type.as_deref(),
            Some("foo")
        );
        let _ = key_pair
            .public_key()
            .verify_token::<NoCustomClaims>(&token, None)
            .unwrap();
    }

    #[test]
    fn set_header_signature_type() {
        let mut key_pair = Ed25519KeyPair::generate();
        key_pair.for_signature_type(Some("etc+jwt".into())).unwrap();
        let claims = Claims::create(Duration::from_secs(86400));
        let token = key_pair.sign(claims).unwrap();
        let decoded_metadata = Token::decode_metadata(&token).unwrap();
        assert_eq!(
            decoded_metadata.jwt_header.signature_type.as_deref(),
            Some("etc+jwt")
        );
        let _ = key_pair
            .public_key()
            .verify_token::<NoCustomClaims>(&token, None)
            .unwrap();
    }

    #[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
    #[test]
    fn expired_token() {
        let key = HS256Key::generate();
        let claims = Claims::create(Duration::from_secs(1));
        let token = key.authenticate(claims).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(2));
        let options = VerificationOptions {
            time_tolerance: None,
            ..Default::default()
        };
        let claims = key.verify_token::<NoCustomClaims>(&token, None);
        assert!(claims.is_ok());
        let claims = key.verify_token::<NoCustomClaims>(&token, Some(options));
        assert!(claims.is_err());
    }

    #[test]
    fn salt() {
        let mut key = HS256Key::generate_with_salt();
        let claims = Claims::create(Duration::from_secs(86400));
        let token = key.authenticate(claims).unwrap();

        let res = key.verify_token::<NoCustomClaims>(&token, None);
        assert!(res.is_err());

        let verifier_salt = key.verifier_salt().unwrap();
        key.attach_salt(verifier_salt).unwrap();
        key.verify_token::<NoCustomClaims>(&token, None).unwrap();
    }

    #[test]
    fn salt2() {
        let mut key = HS256Key::generate();
        let claims = Claims::create(Duration::from_secs(86400));
        let token = key.authenticate(claims).unwrap();

        key.verify_token::<NoCustomClaims>(&token, None).unwrap();

        let verifier_salt = Salt::Verifier(b"salt".to_vec());
        key.attach_salt(verifier_salt).unwrap();
        let res = key.verify_token::<NoCustomClaims>(&token, None);
        assert!(res.is_err());
    }
}
