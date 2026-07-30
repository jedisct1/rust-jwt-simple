//! JWE token building and parsing.

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use serde::{de::DeserializeOwned, Serialize};

use crate::algorithms::jwe::content::{ContentEncryption, CEK};
use crate::claims::*;
use crate::common::{VerificationOptions, DEFAULT_MAX_TOKEN_LENGTH};
use crate::error::*;
use crate::jwe_header::JWEHeader;

pub const MAX_JWE_HEADER_LENGTH: usize = 8192;

/// Largest wrapped key a token may carry: an RSA-OAEP key for a 16384-bit modulus.
/// AES-KW wrapped keys are 40 bytes, and ECDH-ES direct key agreement carries none.
pub const MAX_JWE_ENCRYPTED_KEY_LENGTH: usize = 2048;

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
#[derive(Clone, Debug)]
pub struct DecryptionOptions {
    /// Maximum token length to accept.
    /// Defaults to `DEFAULT_MAX_TOKEN_LENGTH`, as signed tokens do; `None` accepts any size.
    pub max_token_length: Option<usize>,
    /// Maximum header length to accept
    pub max_header_length: Option<usize>,
    /// Required key ID
    pub required_key_id: Option<String>,
    /// Options for validating claims after decryption
    pub claim_options: Option<VerificationOptions>,
}

impl Default for DecryptionOptions {
    fn default() -> Self {
        Self {
            max_token_length: Some(DEFAULT_MAX_TOKEN_LENGTH),
            max_header_length: None,
            required_key_id: None,
            claim_options: None,
        }
    }
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

        if let Some(max_len) = options.max_token_length {
            ensure!(token.len() <= max_len, JWTError::TokenTooLong);
        }

        let mut parts = token.split('.');
        let header_b64 = parts.next().ok_or(JWTError::InvalidJWEFormat)?;
        let encrypted_key_b64 = parts.next().ok_or(JWTError::InvalidJWEFormat)?;
        let iv_b64 = parts.next().ok_or(JWTError::InvalidJWEFormat)?;
        let ciphertext_b64 = parts.next().ok_or(JWTError::InvalidJWEFormat)?;
        let tag_b64 = parts.next().ok_or(JWTError::InvalidJWEFormat)?;
        ensure!(parts.next().is_none(), JWTError::InvalidJWEFormat);

        let max_header_len = options.max_header_length.unwrap_or(MAX_JWE_HEADER_LENGTH);
        ensure!(header_b64.len() <= max_header_len, JWTError::HeaderTooLarge);

        let header_bytes = Base64UrlSafeNoPadding::decode_to_vec(header_b64, None)?;
        let header: JWEHeader = serde_json::from_slice(&header_bytes)?;

        // RFC 7516 requires rejecting unrecognized critical extensions, and we support none.
        if let Some(ref crit) = header.critical {
            if !crit.is_empty() {
                bail!(JWTError::UnknownCriticalExtension);
            }
        }

        ensure!(
            header.algorithm == expected_alg,
            JWTError::AlgorithmMismatch
        );

        if let Some(required_key_id) = &options.required_key_id {
            if let Some(key_id) = &header.key_id {
                ensure!(key_id == required_key_id, JWTError::KeyIdentifierMismatch);
            } else {
                bail!(JWTError::MissingJWTKeyIdentifier);
            }
        }

        let content_encryption = ContentEncryption::from_alg_name(&header.encryption)?;

        // Every segment but the ciphertext has a size these algorithms fix, so an inflated one
        // costs nothing to reject while still encoded.
        ensure!(
            encrypted_key_b64.len()
                <= Base64UrlSafeNoPadding::encoded_len(MAX_JWE_ENCRYPTED_KEY_LENGTH)?,
            JWTError::InvalidJWEFormat
        );
        ensure!(
            iv_b64.len() == Base64UrlSafeNoPadding::encoded_len(content_encryption.iv_size())?,
            JWTError::InvalidIV
        );
        ensure!(
            tag_b64.len() == Base64UrlSafeNoPadding::encoded_len(content_encryption.tag_size())?,
            JWTError::InvalidJWEAuthTag
        );

        // Nothing decodes the ciphertext until a CEK exists.
        let encrypted_key = Base64UrlSafeNoPadding::decode_to_vec(encrypted_key_b64, None)?;
        let cek = CEK::new(key_unwrap_fn(&header, &encrypted_key)?);

        let iv = Base64UrlSafeNoPadding::decode_to_vec(iv_b64, None)?;
        let tag = Base64UrlSafeNoPadding::decode_to_vec(tag_b64, None)?;
        let ciphertext = Base64UrlSafeNoPadding::decode_to_vec(ciphertext_b64, None)?;

        // The AAD is the ASCII bytes of the base64url-encoded header
        let aad = header_b64.as_bytes();

        let plaintext = content_encryption.decrypt(cek.as_bytes(), &iv, aad, &ciphertext, &tag)?;
        drop(cek); // Zeroize CEK immediately after use

        let claims: JWTClaims<CustomClaims> = serde_json::from_slice(&plaintext)?;

        claims.validate(&options.claim_options.unwrap_or_default())?;

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

#[test]
fn decrypt_enforces_size_limits_before_doing_work() {
    use crate::{prelude::*, JWTError};

    const ENCRYPTED_KEY: usize = 1;
    const IV: usize = 2;
    const CIPHERTEXT: usize = 3;
    const TAG: usize = 4;

    let key = A256KWKey::generate();
    let token = key
        .encrypt(Claims::create(Duration::from_hours(1)))
        .unwrap();
    let segments: Vec<&str> = token.split('.').collect();

    let error_for = |patches: &[(usize, &str)]| {
        let mut segments = segments.clone();
        for &(index, segment) in patches {
            segments[index] = segment;
        }
        key.decrypt_token::<NoCustomClaims>(&segments.join("."), None)
            .unwrap_err()
            .downcast::<JWTError>()
            .unwrap()
    };

    let oversized_key =
        "A".repeat(Base64UrlSafeNoPadding::encoded_len(MAX_JWE_ENCRYPTED_KEY_LENGTH).unwrap() + 1);
    assert!(matches!(
        error_for(&[(ENCRYPTED_KEY, &oversized_key)]),
        JWTError::InvalidJWEFormat
    ));
    assert!(matches!(
        error_for(&[(IV, &format!("{}AAAA", segments[IV]))]),
        JWTError::InvalidIV
    ));
    assert!(matches!(
        error_for(&[(TAG, &format!("{}AAAA", segments[TAG]))]),
        JWTError::InvalidJWEAuthTag
    ));

    // The ciphertext here is not even valid base64, so failing at key unwrap is what proves
    // nothing looked at it.
    let bogus_key = Base64UrlSafeNoPadding::encode_to_string([0u8; 40]).unwrap();
    assert!(matches!(
        error_for(&[(ENCRYPTED_KEY, &bogus_key), (CIPHERTEXT, &"!".repeat(1024))]),
        JWTError::KeyUnwrapFailed
    ));

    // The whole token gets the same default ceiling as a signed one, and lifting it keeps large
    // tokens usable.
    let issuer = "i".repeat(1_100_000);
    let large = key
        .encrypt(Claims::create(Duration::from_hours(1)).with_issuer(&issuer))
        .unwrap();
    assert!(large.len() > DEFAULT_MAX_TOKEN_LENGTH);
    assert!(matches!(
        key.decrypt_token::<NoCustomClaims>(&large, None)
            .unwrap_err()
            .downcast::<JWTError>()
            .unwrap(),
        JWTError::TokenTooLong
    ));

    let options = DecryptionOptions {
        max_token_length: None,
        ..Default::default()
    };
    let claims = key
        .decrypt_token::<NoCustomClaims>(&large, Some(options))
        .unwrap();
    assert_eq!(claims.issuer.unwrap(), issuer);
}
