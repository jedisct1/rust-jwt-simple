//! AES Key Wrap algorithms for JWE.
//!
//! Implements A256KW and A128KW (AES Key Wrap as per RFC 3394).

#[cfg(any(feature = "pure-rust", target_arch = "wasm32", target_arch = "wasm64"))]
use superboring as boring;

use boring::aes::{unwrap_key, wrap_key, AesKey};
use rand::RngCore;
use serde::{de::DeserializeOwned, Serialize};
use zeroize::Zeroize;

use crate::claims::*;
use crate::error::*;
use crate::jwe_header::JWEHeader;
use crate::jwe_token::{DecryptionOptions, EncryptionOptions, JWEToken, JWETokenMetadata};

/// AES-256 Key Wrap key for JWE.
///
/// This is a symmetric key that can both encrypt and decrypt JWE tokens.
#[derive(Clone)]
pub struct A256KWKey {
    key: Vec<u8>,
    key_id: Option<String>,
}

impl std::fmt::Debug for A256KWKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("A256KWKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl Drop for A256KWKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl A256KWKey {
    const KEY_SIZE: usize = 32;
    const ALG_NAME: &'static str = "A256KW";

    /// Create a key from raw bytes.
    ///
    /// The key must be exactly 32 bytes (256 bits).
    pub fn from_bytes(key: &[u8]) -> Result<Self, Error> {
        ensure!(key.len() == Self::KEY_SIZE, JWTError::InvalidEncryptionKey);
        Ok(A256KWKey {
            key: key.to_vec(),
            key_id: None,
        })
    }

    /// Generate a random key.
    pub fn generate() -> Self {
        let mut key = vec![0u8; Self::KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut key);
        A256KWKey { key, key_id: None }
    }

    /// Export the key as raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.clone()
    }

    /// Set the key ID.
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Get the key ID.
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    pub(crate) fn wrap_key(&self, cek: &[u8]) -> Result<Vec<u8>, Error> {
        let aes_key =
            AesKey::new_encrypt(&self.key).map_err(|_| JWTError::InvalidEncryptionKey)?;

        // Output is 8 bytes larger than input (for IV)
        let mut wrapped = vec![0u8; cek.len() + 8];
        wrap_key(&aes_key, None, &mut wrapped, cek).map_err(|_| JWTError::InvalidEncryptionKey)?;

        Ok(wrapped)
    }

    pub(crate) fn unwrap_key(&self, wrapped: &[u8]) -> Result<Vec<u8>, Error> {
        ensure!(wrapped.len() >= 16, JWTError::KeyUnwrapFailed);

        let aes_key =
            AesKey::new_decrypt(&self.key).map_err(|_| JWTError::InvalidEncryptionKey)?;

        // Output is 8 bytes smaller than input
        let mut cek = vec![0u8; wrapped.len() - 8];
        unwrap_key(&aes_key, None, &mut cek, wrapped).map_err(|_| JWTError::KeyUnwrapFailed)?;

        Ok(cek)
    }

    /// Encrypt claims into a JWE token.
    pub fn encrypt<CustomClaims: Serialize>(
        &self,
        claims: JWTClaims<CustomClaims>,
    ) -> Result<String, Error> {
        self.encrypt_with_options(claims, &EncryptionOptions::default())
    }

    /// Encrypt claims into a JWE token with options.
    pub fn encrypt_with_options<CustomClaims: Serialize>(
        &self,
        claims: JWTClaims<CustomClaims>,
        options: &EncryptionOptions,
    ) -> Result<String, Error> {
        let content_encryption = options.content_encryption;
        let mut header = JWEHeader::new(Self::ALG_NAME, content_encryption.alg_name());

        if let Some(key_id) = &self.key_id {
            header.key_id = Some(key_id.clone());
        }
        if let Some(key_id) = &options.key_id {
            header.key_id = Some(key_id.clone());
        }
        if let Some(cty) = &options.content_type {
            header.content_type = Some(cty.clone());
        }

        JWEToken::build_from_claims(&header, &claims, content_encryption, |cek| {
            self.wrap_key(cek)
        })
    }

    /// Decrypt a JWE token and return the claims.
    pub fn decrypt_token<CustomClaims: DeserializeOwned>(
        &self,
        token: &str,
        options: Option<DecryptionOptions>,
    ) -> Result<JWTClaims<CustomClaims>, Error> {
        JWEToken::decrypt(Self::ALG_NAME, token, options, |_header, encrypted_key| {
            self.unwrap_key(encrypted_key)
        })
    }

    /// Decode token metadata without decrypting.
    pub fn decode_metadata(token: &str) -> Result<JWETokenMetadata, Error> {
        JWEToken::decode_metadata(token)
    }
}

/// AES-128 Key Wrap key for JWE.
///
/// This is a symmetric key that can both encrypt and decrypt JWE tokens.
/// Note: A256KW is preferred for new applications.
#[derive(Clone)]
pub struct A128KWKey {
    key: Vec<u8>,
    key_id: Option<String>,
}

impl std::fmt::Debug for A128KWKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("A128KWKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl Drop for A128KWKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl A128KWKey {
    const KEY_SIZE: usize = 16;
    const ALG_NAME: &'static str = "A128KW";

    /// Create a key from raw bytes.
    ///
    /// The key must be exactly 16 bytes (128 bits).
    pub fn from_bytes(key: &[u8]) -> Result<Self, Error> {
        ensure!(key.len() == Self::KEY_SIZE, JWTError::InvalidEncryptionKey);
        Ok(A128KWKey {
            key: key.to_vec(),
            key_id: None,
        })
    }

    /// Generate a random key.
    pub fn generate() -> Self {
        let mut key = vec![0u8; Self::KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut key);
        A128KWKey { key, key_id: None }
    }

    /// Export the key as raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.clone()
    }

    /// Set the key ID.
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Get the key ID.
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    pub(crate) fn wrap_key(&self, cek: &[u8]) -> Result<Vec<u8>, Error> {
        let aes_key =
            AesKey::new_encrypt(&self.key).map_err(|_| JWTError::InvalidEncryptionKey)?;

        // Output is 8 bytes larger than input (for IV)
        let mut wrapped = vec![0u8; cek.len() + 8];
        wrap_key(&aes_key, None, &mut wrapped, cek).map_err(|_| JWTError::InvalidEncryptionKey)?;

        Ok(wrapped)
    }

    pub(crate) fn unwrap_key(&self, wrapped: &[u8]) -> Result<Vec<u8>, Error> {
        ensure!(wrapped.len() >= 16, JWTError::KeyUnwrapFailed);

        let aes_key =
            AesKey::new_decrypt(&self.key).map_err(|_| JWTError::InvalidEncryptionKey)?;

        // Output is 8 bytes smaller than input
        let mut cek = vec![0u8; wrapped.len() - 8];
        unwrap_key(&aes_key, None, &mut cek, wrapped).map_err(|_| JWTError::KeyUnwrapFailed)?;

        Ok(cek)
    }

    /// Encrypt claims into a JWE token.
    pub fn encrypt<CustomClaims: Serialize>(
        &self,
        claims: JWTClaims<CustomClaims>,
    ) -> Result<String, Error> {
        self.encrypt_with_options(claims, &EncryptionOptions::default())
    }

    /// Encrypt claims into a JWE token with options.
    pub fn encrypt_with_options<CustomClaims: Serialize>(
        &self,
        claims: JWTClaims<CustomClaims>,
        options: &EncryptionOptions,
    ) -> Result<String, Error> {
        let content_encryption = options.content_encryption;
        let mut header = JWEHeader::new(Self::ALG_NAME, content_encryption.alg_name());

        if let Some(key_id) = &self.key_id {
            header.key_id = Some(key_id.clone());
        }
        if let Some(key_id) = &options.key_id {
            header.key_id = Some(key_id.clone());
        }
        if let Some(cty) = &options.content_type {
            header.content_type = Some(cty.clone());
        }

        JWEToken::build_from_claims(&header, &claims, content_encryption, |cek| {
            self.wrap_key(cek)
        })
    }

    /// Decrypt a JWE token and return the claims.
    pub fn decrypt_token<CustomClaims: DeserializeOwned>(
        &self,
        token: &str,
        options: Option<DecryptionOptions>,
    ) -> Result<JWTClaims<CustomClaims>, Error> {
        JWEToken::decrypt(Self::ALG_NAME, token, options, |_header, encrypted_key| {
            self.unwrap_key(encrypted_key)
        })
    }

    /// Decode token metadata without decrypting.
    pub fn decode_metadata(token: &str) -> Result<JWETokenMetadata, Error> {
        JWEToken::decode_metadata(token)
    }
}
