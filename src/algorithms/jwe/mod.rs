//! JWE (JSON Web Encryption) key management algorithms.
//!
//! This module provides implementations of various JWE key management algorithms
//! as specified in RFC 7518. Each key type is strongly typed to prevent misuse.
//!
//! # Supported Algorithms
//!
//! ## RSA Key Management
//! - `RSA-OAEP` - RSA with OAEP using SHA-1
//!
//! Note: RSA-OAEP-256 (with SHA-256) is not currently supported because the underlying
//! boring/superboring crates do not expose the API to specify the OAEP hash function.
//!
//! ## Symmetric Key Wrap
//! - `A256KW` - AES-256 Key Wrap (recommended)
//! - `A128KW` - AES-128 Key Wrap
//!
//! ## ECDH Key Agreement
//! - `ECDH-ES+A256KW` - ECDH with AES-256 Key Wrap (recommended)
//! - `ECDH-ES+A128KW` - ECDH with AES-128 Key Wrap
//!
//! # Content Encryption
//!
//! All key management algorithms support these content encryption algorithms:
//! - `A256GCM` - AES-256-GCM (default, recommended)
//! - `A128GCM` - AES-128-GCM
//!
//! # Examples
//!
//! ## RSA-OAEP
//!
//! ```rust
//! use jwt_simple::prelude::*;
//!
//! // Generate a key pair
//! let decryption_key = RsaOaepDecryptionKey::generate(2048).unwrap();
//! let encryption_key = decryption_key.encryption_key();
//!
//! // Encrypt
//! let claims = Claims::create(Duration::from_hours(1))
//!     .with_subject("user@example.com");
//! let token = encryption_key.encrypt(claims).unwrap();
//!
//! // Decrypt
//! let claims = decryption_key.decrypt_token::<NoCustomClaims>(&token, None).unwrap();
//! ```
//!
//! ## AES Key Wrap
//!
//! ```rust
//! use jwt_simple::prelude::*;
//!
//! // Generate a symmetric key
//! let key = A256KWKey::generate();
//!
//! // Encrypt
//! let claims = Claims::create(Duration::from_hours(1));
//! let token = key.encrypt(claims).unwrap();
//!
//! // Decrypt
//! let claims = key.decrypt_token::<NoCustomClaims>(&token, None).unwrap();
//! ```
//!
//! ## ECDH-ES+A256KW
//!
//! ```rust
//! use jwt_simple::prelude::*;
//!
//! // Generate a key pair
//! let decryption_key = EcdhEsA256KWDecryptionKey::generate();
//! let encryption_key = decryption_key.encryption_key();
//!
//! // Encrypt
//! let claims = Claims::create(Duration::from_hours(1));
//! let token = encryption_key.encrypt(claims).unwrap();
//!
//! // Decrypt
//! let claims = decryption_key.decrypt_token::<NoCustomClaims>(&token, None).unwrap();
//! ```

pub mod aes_kw;
pub mod content;
pub mod ecdh_es;
pub mod rsa_oaep;

pub use aes_kw::{A128KWKey, A256KWKey};
pub use content::ContentEncryption;
pub use ecdh_es::{
    EcdhEsA128KWDecryptionKey, EcdhEsA128KWEncryptionKey, EcdhEsA256KWDecryptionKey,
    EcdhEsA256KWEncryptionKey,
};
pub use rsa_oaep::{RsaOaepDecryptionKey, RsaOaepEncryptionKey};
