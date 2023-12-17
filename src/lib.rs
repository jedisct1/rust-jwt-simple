//! ![GitHub CI](https://github.com/jedisct1/rust-jwt-simple/workflows/Rust/badge.svg)
//! [![Docs.rs](https://docs.rs/jwt-simple/badge.svg)](https://docs.rs/jwt-simple/)
//! [![crates.io](https://img.shields.io/crates/v/jwt-simple.svg)](https://crates.io/crates/jwt-simple)
//!
//! # JWT-Simple
//!
//! A new JWT implementation for Rust that focuses on simplicity, while avoiding
//! common JWT security pitfalls.
//!
//! `jwt-simple` is unopinionated and supports all commonly deployed
//! authentication and signature algorithms:
//!
//! * HMAC-SHA2:
//!   * `HS256`
//!   * `HS384`
//!   * `HS512`
//! * `BLAKE2B`
//! * RSA
//!   * `RS256`
//!   * `RS384`
//!   * `RS512`
//!   * `PS256`
//!   * `PS384`
//!   * `PS512`
//! * p256
//!   * `ES256`
//! * p384
//!   * `ES384`
//! * secp256k1
//!   * `ES256K`
//! * Ed25519
//!   * `EdDSA`
//!
//! `jwt-simple` can be compiled out of the box to WebAssembly/WASI.
//! It is fully compatible with Fastly _Compute_ service.
//!
//! Important: JWT's purpose is to verify that data has been created by a party
//! knowing a secret key. It does not provide any kind of confidentiality: JWT
//! data is simply encoded as BASE64, and is not encrypted.
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
//! ## Authentication (symmetric, `HS*` JWT algorithms) example
//!
//! Authentication schemes use the same key for creating and verifying tokens.
//! In other words, both parties need to ultimately trust each other, or else
//! the verifier could also create arbitrary tokens.
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
//! A key can be exported as bytes with `key.to_bytes()`, and restored with
//! `HS256Key::from_bytes()`.
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
//! # Ok(()) }
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
//! # let token = key.authenticate(Claims::create(Duration::from_secs(10)))?;
//! let claims = key.verify_token::<NoCustomClaims>(&token, None)?;
//! # Ok(()) }
//! ```
//!
//! -> Done! No additional steps required.
//!
//! Key expiration, start time, authentication tags, etc. are automatically
//! verified. The function fails with `JWTError::InvalidAuthenticationTag` if
//! the authentication tag is invalid for the given key.
//!
//! The full set of claims can be inspected in the `claims` object if necessary.
//! `NoCustomClaims` means that only the standard set of claims is used by the
//! application, but application-defined claims can also be supported.
//!
//! Extra verification steps can optionally be enabled via the
//! `ValidationOptions` structure:
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # fn main() -> Result<(), jwt_simple::Error> {
//! # let key = HS256Key::generate();
//! # let token = key.authenticate(Claims::create(Duration::from_secs(10)).with_issuer("example app"))?;
//! let mut options = VerificationOptions::default();
//! // Accept tokens that will only be valid in the future
//! options.accept_future = true;
//! // Accept tokens even if they have expired up to 15 minutes after the deadline
//! // and/or they will be valid within 15 minutes.
//! options.time_tolerance = Some(Duration::from_mins(15));
//! // Reject tokens if they were issued more than 1 hour ago
//! options.max_validity = Some(Duration::from_hours(1));
//! // Reject tokens if they don't include an issuer from that list
//! options.allowed_issuers = Some(HashSet::from_strings(&["example app"]));
//! // See the documentation for the full list of available options
//!
//! let claims = key.verify_token::<NoCustomClaims>(&token, Some(options))?;
//! # Ok(()) }
//! ```
//!
//! Note that `allowed_issuers` and `allowed_audiences` are not strings, but
//! sets of strings (using the `HashSet` type from the Rust standard library),
//! as the application can allow multiple return values.
//!
//! ## Signatures (asymmetric, `RS*`, `PS*`, `ES*` and `EdDSA` algorithms) example
//!
//! A signature requires a key pair: a secret key used to create tokens, and a
//! public key, that can only verify them.
//!
//! Always use a signature scheme if both parties do not ultimately trust each
//! other, such as tokens exchanged between clients and API providers.
//!
//! ### Key pairs and tokens creation
//!
//! Key creation:
//!
//! ```rust
//! use jwt_simple::prelude::*;
//!
//! // create a new key pair for the `ES256` JWT algorithm
//! let key_pair = ES256KeyPair::generate();
//!
//! // Or the `ES384` JWT algorithm
//! let key_pair = ES384KeyPair::generate();
//!
//! // a public key can be extracted from a key pair:
//! let public_key = key_pair.public_key();
//! ```
//!
//! Keys can be exported as bytes for later reuse, and imported from bytes or,
//! for RSA, from individual parameters, DER-encoded data or PEM-encoded data.
//!
//! RSA key pair creation, using OpenSSL and PEM importation of the secret key:
//!
//! ```sh
//! openssl genrsa -out private.pem 2048
//! openssl rsa -in private.pem -outform PEM -pubout -out public.pem
//! ```
//!
//! ```no_run
//! # use jwt_simple::prelude::*;
//! # fn main() -> Result<(), jwt_simple::Error> {
//! # let private_pem_file_content = "";
//! # let public_pem_file_content = "";
//! let key_pair = RS384KeyPair::from_pem(private_pem_file_content)?;
//! let public_key = RS384PublicKey::from_pem(public_pem_file_content)?;
//! # Ok(()) }
//! ```
//!
//! Token creation and verification work the same way as with `HS*` algorithms,
//! except that tokens are created with a key pair, and verified using the
//! corresponding public key.
//!
//! Token creation:
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # fn main() -> Result<(), jwt_simple::Error> {
//! # let key_pair = Ed25519KeyPair::generate();
//! /// create claims valid for 2 hours
//! let claims = Claims::create(Duration::from_hours(2));
//! let token = key_pair.sign(claims)?;
//! # Ok(()) }
//! ```
//!
//! Token verification:
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # fn main() -> Result<(), jwt_simple::Error> {
//! # let key_pair = Ed25519KeyPair::generate();
//! # let public_key = key_pair.public_key();
//! # let token = key_pair.sign(Claims::create(Duration::from_secs(10)))?;
//! let claims = public_key.verify_token::<NoCustomClaims>(&token, None)?;
//! # Ok(()) }
//! ```
//!
//! Available verification options are identical to the ones used with symmetric
//! algorithms.
//!
//! ## Advanced usage
//!
//! ### Custom claims
//!
//! Claim objects support all the standard claims by default, and they can be
//! set directly or via convenient helpers:
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! let claims = Claims::create(Duration::from_hours(2))
//!     .with_issuer("Example issuer")
//!     .with_subject("Example subject");
//! ```
//!
//! But application-defined claims can also be defined. These simply have to be
//! present in a serializable type (this requires the `serde` crate):
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # fn main() -> Result<(), jwt_simple::Error> {
//! #[derive(Serialize, Deserialize)]
//! struct MyAdditionalData {
//!     user_is_admin: bool,
//!     user_country: String,
//! }
//! let my_additional_data = MyAdditionalData {
//!     user_is_admin: false,
//!     user_country: "FR".to_string(),
//! };
//!
//! // Claim creation with custom data:
//!
//! # use jwt_simple::prelude::*;
//! let claims = Claims::with_custom_claims(my_additional_data, Duration::from_secs(30));
//!
//! // Claim verification with custom data. Note the presence of the custom data type:
//!
//! # let key_pair = Ed25519KeyPair::generate();
//! # let public_key = key_pair.public_key();
//! # let token = key_pair.sign(claims)?;
//! let claims = public_key.verify_token::<MyAdditionalData>(&token, None)?;
//! let user_is_admin = claims.custom.user_is_admin;
//! # Ok(()) }
//! ```
//!
//! ### Peeking at metadata before verification
//!
//! Properties such as the key identifier can be useful prior to tag or
//! signature verification in order to pick the right key out of a set.
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # fn main() -> Result<(), jwt_simple::Error> {
//! # let token = Ed25519KeyPair::generate().sign(Claims::create(Duration::from_hours(2)))?;
//! let metadata = Token::decode_metadata(&token)?;
//! let key_id = metadata.key_id();
//! let algorithm = metadata.algorithm();
//! // all other standard properties are also accessible
//! # Ok(()) }
//! ```
//!
//! ### Creating and attaching key identifiers
//!
//! Key identifiers indicate to verifiers what public key (or shared key) should
//! be used for verification. They can be attached at any time to existing
//! shared keys, key pairs and public keys:
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # let public_key = Ed25519KeyPair::generate().public_key();
//! let public_key_with_id = public_key.with_key_id(&"unique key identifier");
//! ```
//!
//! Instead of delegating this to applications, `jwt-simple` can also create
//! such an identifier for an existing key:
//!
//! ```rust
//! # use jwt_simple::prelude::*;
//! # let mut public_key = Ed25519KeyPair::generate().public_key();
//! let key_id = public_key.create_key_id();
//! ```
//!
//! This creates an text-encoded identifier for the key, attaches it, and
//! returns it.
//!
//! If an identifier has been attached to a shared key or a key pair, tokens
//! created with them will include it.

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
}
