use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use serde::{de::DeserializeOwned, Serialize};

use crate::claims::*;
use crate::common::*;
use crate::error::*;
use crate::jwt_header::*;

pub const MAX_HEADER_LENGTH: usize = 8192;

/// Utilities to get information about a JWT token
pub struct Token;

/// JWT token information useful before signature/tag verification
#[derive(Debug, Clone)]
pub struct TokenMetadata {
    jwt_header: JWTHeader,
}

impl TokenMetadata {
    /// The JWT algorithm for this token
    pub fn algorithm(&self) -> &str {
        &self.jwt_header.algorithm
    }

    /// The content type for this token
    pub fn content_type(&self) -> Option<&str> {
        self.jwt_header.content_type.as_deref()
    }

    /// The key set URL for this token
    pub fn key_set_url(&self) -> Option<&str> {
        self.jwt_header.key_set_url.as_deref()
    }

    /// The public key for this token
    pub fn public_key(&self) -> Option<&str> {
        self.jwt_header.public_key.as_deref()
    }

    /// The key, or public key identifier for this token
    pub fn key_id(&self) -> Option<&str> {
        self.jwt_header.key_id.as_deref()
    }

    /// The certificate URL for this token
    pub fn certificate_url(&self) -> Option<&str> {
        self.jwt_header.certificate_url.as_deref()
    }

    /// The certificate chain for this token
    pub fn certificate_chain(&self) -> Option<&[String]> {
        self.jwt_header.certificate_chain.as_deref()
    }

    /// The SHA-1 certificate fingerprint
    pub fn certificate_sha1_thumbprint(&self) -> Option<&str> {
        self.jwt_header.certificate_sha1_thumbprint.as_deref()
    }

    /// The SHA-256 certificate fingerprint
    pub fn certificate_sha256_thumbprint(&self) -> Option<&str> {
        self.jwt_header.certificate_sha256_thumbprint.as_deref()
    }

    /// The signature type for this token
    pub fn signature_type(&self) -> Option<&str> {
        self.jwt_header.signature_type.as_deref()
    }

    /// The set of critical properties for this token
    pub fn critical(&self) -> Option<&[String]> {
        self.jwt_header.critical.as_deref()
    }
}

impl Token {
    pub(crate) fn build<AuthenticationOrSignatureFn, CustomClaims: Serialize + DeserializeOwned>(
        jwt_header: &JWTHeader,
        claims: JWTClaims<CustomClaims>,
        authentication_or_signature_fn: AuthenticationOrSignatureFn,
    ) -> Result<String, Error>
    where
        AuthenticationOrSignatureFn: FnOnce(&str) -> Result<Vec<u8>, Error>,
    {
        let jwt_header_json = serde_json::to_string(&jwt_header)?;
        let claims_json = serde_json::to_string(&claims)?;
        let authenticated = format!(
            "{}.{}",
            Base64UrlSafeNoPadding::encode_to_string(jwt_header_json)?,
            Base64UrlSafeNoPadding::encode_to_string(claims_json)?
        );
        let authentication_tag_or_signature = authentication_or_signature_fn(&authenticated)?;
        let mut token = authenticated;
        token.push('.');
        token.push_str(&Base64UrlSafeNoPadding::encode_to_string(
            &authentication_tag_or_signature,
        )?);
        Ok(token)
    }

    pub(crate) fn verify<AuthenticationOrSignatureFn, CustomClaims: Serialize + DeserializeOwned>(
        jwt_alg_name: &'static str,
        token: &str,
        options: Option<VerificationOptions>,
        authentication_or_signature_fn: AuthenticationOrSignatureFn,
    ) -> Result<JWTClaims<CustomClaims>, Error>
    where
        AuthenticationOrSignatureFn: FnOnce(&str, &[u8]) -> Result<(), Error>,
    {
        let options = options.unwrap_or_default();
        let mut parts = token.split('.');
        let jwt_header_b64 = parts.next().ok_or(JWTError::CompactEncodingError)?;
        ensure!(
            jwt_header_b64.len() <= MAX_HEADER_LENGTH,
            JWTError::HeaderTooLarge
        );
        let claims_b64 = parts.next().ok_or(JWTError::CompactEncodingError)?;
        let authentication_tag_b64 = parts.next().ok_or(JWTError::CompactEncodingError)?;
        ensure!(parts.next().is_none(), JWTError::CompactEncodingError);
        let jwt_header: JWTHeader = serde_json::from_slice(
            &Base64UrlSafeNoPadding::decode_to_vec(jwt_header_b64, None)?,
        )?;
        ensure!(
            jwt_header.algorithm == jwt_alg_name,
            JWTError::AlgorithmMismatch
        );
        if let Some(required_key_id) = &options.required_key_id {
            if let Some(key_id) = &jwt_header.key_id {
                ensure!(key_id == required_key_id, JWTError::KeyIdentifierMismatch);
            } else {
                bail!(JWTError::MissingJWTKeyIdentifier)
            }
        }
        let authentication_tag =
            Base64UrlSafeNoPadding::decode_to_vec(&authentication_tag_b64, None)?;
        let authenticated = &token[..jwt_header_b64.len() + 1 + claims_b64.len()];
        authentication_or_signature_fn(authenticated, &authentication_tag)?;
        let claims: JWTClaims<CustomClaims> =
            serde_json::from_slice(&Base64UrlSafeNoPadding::decode_to_vec(&claims_b64, None)?)?;
        claims.validate(&options)?;
        Ok(claims)
    }

    /// Decode token information that can be usedful prior to signature/tag verification
    pub fn decode_metadata(token: &str) -> Result<TokenMetadata, Error> {
        let mut parts = token.split('.');
        let jwt_header_b64 = parts.next().ok_or(JWTError::CompactEncodingError)?;
        ensure!(
            jwt_header_b64.len() <= MAX_HEADER_LENGTH,
            JWTError::HeaderTooLarge
        );
        let jwt_header: JWTHeader = serde_json::from_slice(
            &Base64UrlSafeNoPadding::decode_to_vec(jwt_header_b64, None)?,
        )?;
        Ok(TokenMetadata { jwt_header })
    }
}

#[test]
fn should_verify_token() {
    use crate::prelude::*;

    let key = HS256Key::generate();

    let issuer = "issuer";
    let audience = "recipient";
    let mut claims = Claims::create(Duration::from_mins(10))
        .with_issuer(issuer)
        .with_audience(audience);
    let nonce = claims.create_nonce();
    let token = key.authenticate(claims).unwrap();

    let options = VerificationOptions {
        required_nonce: Some(nonce),
        allowed_issuers: Some(HashSet::from_strings(&[issuer])),
        allowed_audiences: Some(HashSet::from_strings(&[audience])),
        ..Default::default()
    };
    key.verify_token::<NoCustomClaims>(&token, Some(options))
        .unwrap();
}

#[test]
fn multiple_audiences() {
    use crate::prelude::*;
    use std::collections::HashSet;

    let key = HS256Key::generate();

    let mut audiences = HashSet::new();
    audiences.insert("audience 1");
    audiences.insert("audience 2");
    audiences.insert("audience 3");
    let claims = Claims::create(Duration::from_mins(10)).with_audiences(audiences);
    let token = key.authenticate(claims).unwrap();

    let options = VerificationOptions {
        allowed_audiences: Some(HashSet::from_strings(&["audience 1"])),
        ..Default::default()
    };
    key.verify_token::<NoCustomClaims>(&token, Some(options))
        .unwrap();
}

#[test]
fn explicitly_empty_audiences() {
    use crate::prelude::*;
    use std::collections::HashSet;

    let key = HS256Key::generate();

    let audiences: HashSet<&str> = HashSet::new();
    let claims = Claims::create(Duration::from_mins(10)).with_audiences(audiences);
    let token = key.authenticate(claims).unwrap();
    let decoded = key.verify_token::<NoCustomClaims>(&token, None).unwrap();
    assert!(decoded.audiences.is_some());

    let claims = Claims::create(Duration::from_mins(10)).with_audience("");
    let token = key.authenticate(claims).unwrap();
    let decoded = key.verify_token::<NoCustomClaims>(&token, None).unwrap();
    assert!(decoded.audiences.is_some());

    let claims = Claims::create(Duration::from_mins(10));
    let token = key.authenticate(claims).unwrap();
    let decoded = key.verify_token::<NoCustomClaims>(&token, None).unwrap();
    assert!(decoded.audiences.is_none());
}
