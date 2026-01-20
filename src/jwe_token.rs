//! JWE token building and parsing.

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use serde::{de::DeserializeOwned, Serialize};

use crate::algorithms::jwe::content::{ContentEncryption, CEK};
use crate::claims::*;
use crate::common::VerificationOptions;
use crate::error::*;
use crate::jwe_header::JWEHeader;

pub const MAX_JWE_HEADER_LENGTH: usize = 8192;

/// Options for JWE encryption.
#[derive(Clone, Debug, Default)]
pub struct EncryptionOptions {
    /// Content encryption algorithm (default: A256GCM)
    pub content_encryption: ContentEncryption,
    /// Content type header
    pub content_type: Option<String>,
    /// Key ID
    pub key_id: Option<String>,
}

/// Options for JWE decryption.
#[derive(Clone, Debug, Default)]
pub struct DecryptionOptions {
    /// Maximum token length to accept
    pub max_token_length: Option<usize>,
    /// Maximum header length to accept
    pub max_header_length: Option<usize>,
    /// Required key ID
    pub required_key_id: Option<String>,
    /// Options for validating claims after decryption
    pub claim_options: Option<VerificationOptions>,
}

/// JWE token metadata extracted from the header (before decryption).
#[derive(Debug, Clone)]
pub struct JWETokenMetadata {
    header: JWEHeader,
}

impl JWETokenMetadata {
    /// The key management algorithm.
    pub fn algorithm(&self) -> &str {
        &self.header.algorithm
    }

    /// The content encryption algorithm.
    pub fn encryption(&self) -> &str {
        &self.header.encryption
    }

    /// The key ID (if present).
    pub fn key_id(&self) -> Option<&str> {
        self.header.key_id.as_deref()
    }

    /// The content type (if present).
    pub fn content_type(&self) -> Option<&str> {
        self.header.content_type.as_deref()
    }

    /// Get the full header.
    pub fn header(&self) -> &JWEHeader {
        &self.header
    }
}

/// Utilities for working with JWE tokens.
pub struct JWEToken;

impl JWEToken {
    /// Build a JWE token.
    ///
    /// This function is called by key management implementations to create
    /// the final JWE compact serialization.
    ///
    /// # Arguments
    /// * `header` - The JWE header
    /// * `encrypted_key` - The encrypted CEK (or empty for direct key agreement)
    /// * `iv` - The initialization vector
    /// * `ciphertext` - The encrypted content
    /// * `tag` - The authentication tag
    pub fn build(
        header: &JWEHeader,
        encrypted_key: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<String, Error> {
        let header_json = serde_json::to_string(header)?;
        let header_b64 = Base64UrlSafeNoPadding::encode_to_string(&header_json)?;
        let encrypted_key_b64 = Base64UrlSafeNoPadding::encode_to_string(encrypted_key)?;
        let iv_b64 = Base64UrlSafeNoPadding::encode_to_string(iv)?;
        let ciphertext_b64 = Base64UrlSafeNoPadding::encode_to_string(ciphertext)?;
        let tag_b64 = Base64UrlSafeNoPadding::encode_to_string(tag)?;

        Ok(format!(
            "{}.{}.{}.{}.{}",
            header_b64, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64
        ))
    }

    /// Build a JWE token from claims.
    ///
    /// This is a helper that serializes claims to JSON before encryption.
    pub fn build_from_claims<KeyWrapFn, CustomClaims: Serialize>(
        header: &JWEHeader,
        claims: &JWTClaims<CustomClaims>,
        content_encryption: ContentEncryption,
        key_wrap_fn: KeyWrapFn,
    ) -> Result<String, Error>
    where
        KeyWrapFn: FnOnce(&[u8]) -> Result<Vec<u8>, Error>,
    {
        // Serialize claims to JSON
        let claims_json = serde_json::to_string(claims)?;
        let plaintext = claims_json.as_bytes();

        // Generate CEK and IV
        let cek = CEK::new(content_encryption.generate_cek());
        let iv = content_encryption.generate_iv();

        // Wrap the CEK
        let encrypted_key = key_wrap_fn(cek.as_bytes())?;

        // Build the AAD (ASCII bytes of the base64url-encoded header)
        let header_json = serde_json::to_string(header)?;
        let header_b64 = Base64UrlSafeNoPadding::encode_to_string(&header_json)?;
        let aad = header_b64.as_bytes();

        // Encrypt the plaintext
        let (ciphertext, tag) = content_encryption.encrypt(cek.as_bytes(), &iv, aad, plaintext)?;
        drop(cek); // Zeroize CEK immediately after use

        // Build the final token
        let encrypted_key_b64 = Base64UrlSafeNoPadding::encode_to_string(&encrypted_key)?;
        let iv_b64 = Base64UrlSafeNoPadding::encode_to_string(&iv)?;
        let ciphertext_b64 = Base64UrlSafeNoPadding::encode_to_string(&ciphertext)?;
        let tag_b64 = Base64UrlSafeNoPadding::encode_to_string(&tag)?;

        Ok(format!(
            "{}.{}.{}.{}.{}",
            header_b64, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64
        ))
    }

    /// Parse and decrypt a JWE token.
    ///
    /// This function is called by key management implementations to decrypt
    /// a JWE token and return the claims.
    pub fn decrypt<KeyUnwrapFn, CustomClaims: DeserializeOwned>(
        expected_alg: &str,
        token: &str,
        options: Option<DecryptionOptions>,
        key_unwrap_fn: KeyUnwrapFn,
    ) -> Result<JWTClaims<CustomClaims>, Error>
    where
        KeyUnwrapFn: FnOnce(&JWEHeader, &[u8]) -> Result<Vec<u8>, Error>,
    {
        let options = options.unwrap_or_default();

        // Check token length
        if let Some(max_len) = options.max_token_length {
            ensure!(token.len() <= max_len, JWTError::TokenTooLong);
        }

        // Split into 5 parts
        let parts: Vec<&str> = token.split('.').collect();
        ensure!(parts.len() == 5, JWTError::InvalidJWEFormat);

        let header_b64 = parts[0];
        let encrypted_key_b64 = parts[1];
        let iv_b64 = parts[2];
        let ciphertext_b64 = parts[3];
        let tag_b64 = parts[4];

        // Check header length
        let max_header_len = options.max_header_length.unwrap_or(MAX_JWE_HEADER_LENGTH);
        ensure!(header_b64.len() <= max_header_len, JWTError::HeaderTooLarge);

        // Decode header
        let header_bytes = Base64UrlSafeNoPadding::decode_to_vec(header_b64, None)?;
        let header: JWEHeader = serde_json::from_slice(&header_bytes)?;

        // Validate critical header - RFC 7516 requires rejecting tokens with
        // unrecognized critical extensions
        if let Some(ref crit) = header.critical {
            if !crit.is_empty() {
                // We don't support any critical extensions
                bail!(JWTError::UnknownCriticalExtension);
            }
        }

        // Validate algorithm
        ensure!(
            header.algorithm == expected_alg,
            JWTError::AlgorithmMismatch
        );

        // Validate key ID if required
        if let Some(required_key_id) = &options.required_key_id {
            if let Some(key_id) = &header.key_id {
                ensure!(key_id == required_key_id, JWTError::KeyIdentifierMismatch);
            } else {
                bail!(JWTError::MissingJWTKeyIdentifier);
            }
        }

        // Decode the encrypted key, IV, ciphertext, and tag
        let encrypted_key = Base64UrlSafeNoPadding::decode_to_vec(encrypted_key_b64, None)?;
        let iv = Base64UrlSafeNoPadding::decode_to_vec(iv_b64, None)?;
        let ciphertext = Base64UrlSafeNoPadding::decode_to_vec(ciphertext_b64, None)?;
        let tag = Base64UrlSafeNoPadding::decode_to_vec(tag_b64, None)?;

        // Get the content encryption algorithm
        let content_encryption = ContentEncryption::from_alg_name(&header.encryption)?;

        // Unwrap the CEK
        let cek = CEK::new(key_unwrap_fn(&header, &encrypted_key)?);

        // The AAD is the ASCII bytes of the base64url-encoded header
        let aad = header_b64.as_bytes();

        // Decrypt the ciphertext
        let plaintext = content_encryption.decrypt(cek.as_bytes(), &iv, aad, &ciphertext, &tag)?;
        drop(cek); // Zeroize CEK immediately after use

        // Parse the claims
        let claims: JWTClaims<CustomClaims> = serde_json::from_slice(&plaintext)?;

        // Validate claims if options provided
        if let Some(claim_options) = &options.claim_options {
            claims.validate(claim_options)?;
        }

        Ok(claims)
    }

    /// Decode JWE token metadata without decrypting.
    ///
    /// This allows inspection of the header to determine which key to use
    /// for decryption.
    pub fn decode_metadata(token: &str) -> Result<JWETokenMetadata, Error> {
        let mut parts = token.split('.');
        let header_b64 = parts.next().ok_or(JWTError::InvalidJWEFormat)?;

        ensure!(
            header_b64.len() <= MAX_JWE_HEADER_LENGTH,
            JWTError::HeaderTooLarge
        );

        let header_bytes = Base64UrlSafeNoPadding::decode_to_vec(header_b64, None)?;
        let header: JWEHeader = serde_json::from_slice(&header_bytes)?;

        Ok(JWETokenMetadata { header })
    }
}
