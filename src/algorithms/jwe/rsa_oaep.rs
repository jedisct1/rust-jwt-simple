//! RSA-OAEP key management algorithm for JWE.
//!
//! Implements RSA-OAEP (RSA with OAEP using SHA-1).
//!
//! Note: RSA-OAEP-256 (with SHA-256) is not currently supported because the underlying
//! boring/superboring crates do not expose the API to specify the OAEP hash function.

#[cfg(any(feature = "pure-rust", target_arch = "wasm32", target_arch = "wasm64"))]
use superboring as boring;

use boring::pkey::{Private, Public};
use boring::rsa::{Padding, Rsa};
use serde::{de::DeserializeOwned, Serialize};

use crate::claims::*;
use crate::error::*;
use crate::jwe_header::JWEHeader;
use crate::jwe_token::{DecryptionOptions, EncryptionOptions, JWEToken, JWETokenMetadata};

const MIN_RSA_MODULUS_BITS: u32 = 2048;

/// RSA public key for encryption (RSA-OAEP with SHA-1).
#[derive(Debug, Clone)]
pub struct RsaOaepEncryptionKey {
    pk: Rsa<Public>,
    key_id: Option<String>,
}

impl RsaOaepEncryptionKey {
    /// Create an encryption key from a DER-encoded public key.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let pk = Rsa::<Public>::public_key_from_der(der)
            .or_else(|_| Rsa::<Public>::public_key_from_der_pkcs1(der))?;
        Self::validate_key_size(&pk)?;
        Ok(RsaOaepEncryptionKey { pk, key_id: None })
    }

    /// Create an encryption key from a PEM-encoded public key.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let pem = pem.trim();
        let pk = Rsa::<Public>::public_key_from_pem(pem.as_bytes())
            .or_else(|_| Rsa::<Public>::public_key_from_pem_pkcs1(pem.as_bytes()))?;
        Self::validate_key_size(&pk)?;
        Ok(RsaOaepEncryptionKey { pk, key_id: None })
    }

    /// Export the key as DER.
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.pk.public_key_to_der().map_err(Into::into)
    }

    /// Export the key as PEM.
    pub fn to_pem(&self) -> Result<String, Error> {
        let bytes = self.pk.public_key_to_pem()?;
        Ok(String::from_utf8(bytes)?)
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

    fn validate_key_size(pk: &Rsa<Public>) -> Result<(), Error> {
        let bits = pk.size() * 8;
        ensure!(bits >= MIN_RSA_MODULUS_BITS, JWTError::WeakKey);
        Ok(())
    }

    fn wrap_key(&self, cek: &[u8]) -> Result<Vec<u8>, Error> {
        let mut encrypted = vec![0u8; self.pk.size() as usize];
        let encrypted_len = self
            .pk
            .public_encrypt(cek, &mut encrypted, Padding::PKCS1_OAEP)
            .map_err(|_| JWTError::InvalidEncryptionKey)?;
        encrypted.truncate(encrypted_len);

        Ok(encrypted)
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
        let mut header = JWEHeader::new("RSA-OAEP", content_encryption.alg_name());

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
}

/// RSA key pair for decryption (RSA-OAEP with SHA-1).
#[derive(Clone)]
pub struct RsaOaepDecryptionKey {
    sk: Rsa<Private>,
    key_id: Option<String>,
}

impl std::fmt::Debug for RsaOaepDecryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaOaepDecryptionKey")
            .field("key_id", &self.key_id)
            .field("modulus_bits", &(self.sk.size() * 8))
            .finish_non_exhaustive()
    }
}

impl RsaOaepDecryptionKey {
    /// Create a decryption key from a DER-encoded private key.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let sk = Rsa::<Private>::private_key_from_der(der)?;
        if !sk.check_key()? {
            bail!(JWTError::InvalidKeyPair);
        }
        Self::validate_key_size(&sk)?;
        Ok(RsaOaepDecryptionKey { sk, key_id: None })
    }

    /// Create a decryption key from a PEM-encoded private key.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let pem = pem.trim();
        let sk = Rsa::<Private>::private_key_from_pem(pem.as_bytes())?;
        if !sk.check_key()? {
            bail!(JWTError::InvalidKeyPair);
        }
        Self::validate_key_size(&sk)?;
        Ok(RsaOaepDecryptionKey { sk, key_id: None })
    }

    /// Generate a new RSA key pair.
    pub fn generate(modulus_bits: usize) -> Result<Self, Error> {
        match modulus_bits {
            2048 | 3072 | 4096 => {}
            _ => bail!(JWTError::UnsupportedRSAModulus),
        };
        let sk = Rsa::<Private>::generate(modulus_bits as u32)?;
        Ok(RsaOaepDecryptionKey { sk, key_id: None })
    }

    /// Export the private key as DER.
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.sk.private_key_to_der().map_err(Into::into)
    }

    /// Export the private key as PEM.
    pub fn to_pem(&self) -> Result<String, Error> {
        let bytes = self.sk.private_key_to_pem()?;
        Ok(String::from_utf8(bytes)?)
    }

    /// Get the public encryption key.
    pub fn encryption_key(&self) -> RsaOaepEncryptionKey {
        let pk = Rsa::<Public>::from_public_components(
            self.sk.n().to_owned().expect("failed to get modulus"),
            self.sk.e().to_owned().expect("failed to get exponent"),
        )
        .expect("failed to create public key");
        RsaOaepEncryptionKey {
            pk,
            key_id: self.key_id.clone(),
        }
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

    fn validate_key_size(sk: &Rsa<Private>) -> Result<(), Error> {
        let bits = sk.size() * 8;
        ensure!(bits >= MIN_RSA_MODULUS_BITS, JWTError::WeakKey);
        Ok(())
    }

    fn unwrap_key(&self, encrypted_key: &[u8]) -> Result<Vec<u8>, Error> {
        let mut cek = vec![0u8; self.sk.size() as usize];
        let cek_len = self
            .sk
            .private_decrypt(encrypted_key, &mut cek, Padding::PKCS1_OAEP)
            .map_err(|_| JWTError::KeyUnwrapFailed)?;
        cek.truncate(cek_len);

        Ok(cek)
    }

    /// Encrypt claims into a JWE token.
    pub fn encrypt<CustomClaims: Serialize>(
        &self,
        claims: JWTClaims<CustomClaims>,
    ) -> Result<String, Error> {
        self.encryption_key().encrypt(claims)
    }

    /// Encrypt claims into a JWE token with options.
    pub fn encrypt_with_options<CustomClaims: Serialize>(
        &self,
        claims: JWTClaims<CustomClaims>,
        options: &EncryptionOptions,
    ) -> Result<String, Error> {
        self.encryption_key().encrypt_with_options(claims, options)
    }

    /// Decrypt a JWE token and return the claims.
    pub fn decrypt_token<CustomClaims: DeserializeOwned>(
        &self,
        token: &str,
        options: Option<DecryptionOptions>,
    ) -> Result<JWTClaims<CustomClaims>, Error> {
        JWEToken::decrypt("RSA-OAEP", token, options, |_header, encrypted_key| {
            self.unwrap_key(encrypted_key)
        })
    }

    /// Decode token metadata without decrypting.
    pub fn decode_metadata(token: &str) -> Result<JWETokenMetadata, Error> {
        JWEToken::decode_metadata(token)
    }
}
