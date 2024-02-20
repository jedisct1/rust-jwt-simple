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
#[derive(Debug, Clone, Default)]
pub struct TokenMetadata {
    pub(crate) jwt_header: JWTHeader,
}

impl TokenMetadata {
    /// The JWT algorithm for this token ("alg")
    /// This information should not be trusted: it is unprotected and can be
    /// freely modified by a third party. Clients should ignore it and use
    /// the correct type of key directly.
    pub fn algorithm(&self) -> &str {
        &self.jwt_header.algorithm
    }

    /// The content type for this token ("cty")
    pub fn content_type(&self) -> Option<&str> {
        self.jwt_header.content_type.as_deref()
    }

    /// The key, or public key identifier for this token ("kid")
    pub fn key_id(&self) -> Option<&str> {
        self.jwt_header.key_id.as_deref()
    }

    /// The signature type for this token ("typ")
    pub fn signature_type(&self) -> Option<&str> {
        self.jwt_header.signature_type.as_deref()
    }

    /// The set of raw critical properties for this token ("crit")
    pub fn critical(&self) -> Option<&[String]> {
        self.jwt_header.critical.as_deref()
    }

    /// The certificate chain for this token ("x5c")
    /// This information should not be trusted: it is unprotected and can be
    /// freely modified by a third party.
    pub fn certificate_chain(&self) -> Option<&[String]> {
        self.jwt_header.certificate_chain.as_deref()
    }

    /// The key set URL for this token ("jku")
    /// This information should not be trusted: it is unprotected and can be
    /// freely modified by a third party. At the bare minimum, you should
    /// check that the URL belongs to the domain you expect.
    pub fn key_set_url(&self) -> Option<&str> {
        self.jwt_header.key_set_url.as_deref()
    }

    /// The public key for this token ("jwk")
    /// This information should not be trusted: it is unprotected and can be
    /// freely modified by a third party. At the bare minimum, you should
    /// check that it's in a set of public keys you already trust.
    pub fn public_key(&self) -> Option<&str> {
        self.jwt_header.public_key.as_deref()
    }

    /// The certificate URL for this token ("x5u")
    /// This information should not be trusted: it is unprotected and can be
    /// freely modified by a third party. At the bare minimum, you should
    /// check that the URL belongs to the domain you expect.
    pub fn certificate_url(&self) -> Option<&str> {
        self.jwt_header.certificate_url.as_deref()
    }

    /// URLsafe-base64-encoded SHA1 hash of the X.509 certificate for this token
    /// ("x5t") In practice, it can also be any string representing the
    /// public key. This information should not be trusted: it is
    /// unprotected and can be freely modified by a third party.
    pub fn certificate_sha1_thumbprint(&self) -> Option<&str> {
        self.jwt_header.certificate_sha1_thumbprint.as_deref()
    }

    /// URLsafe-base64-encoded SHA256 hash of the X.509 certificate for this
    /// token ("x5t#256") In practice, it can also be any string
    /// representing the public key. This information should not be trusted:
    /// it is unprotected and can be freely modified by a third party.
    pub fn certificate_sha256_thumbprint(&self) -> Option<&str> {
        self.jwt_header.certificate_sha256_thumbprint.as_deref()
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
            authentication_tag_or_signature,
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

        if let Some(max_token_length) = options.max_token_length {
            ensure!(token.len() <= max_token_length, JWTError::TokenTooLong);
        }

        let mut parts = token.split('.');
        let jwt_header_b64 = parts.next().ok_or(JWTError::CompactEncodingError)?;
        ensure!(
            jwt_header_b64.len() <= options.max_header_length.unwrap_or(MAX_HEADER_LENGTH),
            JWTError::HeaderTooLarge
        );
        let claims_b64 = parts.next().ok_or(JWTError::CompactEncodingError)?;
        let authentication_tag_b64 = parts.next().ok_or(JWTError::CompactEncodingError)?;
        ensure!(parts.next().is_none(), JWTError::CompactEncodingError);
        let jwt_header: JWTHeader = serde_json::from_slice(
            &Base64UrlSafeNoPadding::decode_to_vec(jwt_header_b64, None)?,
        )?;
        if let Some(signature_type) = &jwt_header.signature_type {
            let signature_type_uc = signature_type.to_uppercase();
            ensure!(
                signature_type_uc == "JWT" || signature_type_uc.ends_with("+JWT"),
                JWTError::NotJWT
            );
        }
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
            Base64UrlSafeNoPadding::decode_to_vec(authentication_tag_b64, None)?;
        let authenticated = &token[..jwt_header_b64.len() + 1 + claims_b64.len()];
        authentication_or_signature_fn(authenticated, &authentication_tag)?;
        let claims: JWTClaims<CustomClaims> =
            serde_json::from_slice(&Base64UrlSafeNoPadding::decode_to_vec(claims_b64, None)?)?;
        claims.validate(&options)?;
        Ok(claims)
    }

    /// Decode token information that can be usedful prior to signature/tag
    /// verification
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
    use std::collections::HashSet;

    use crate::prelude::*;

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
    use std::collections::HashSet;

    use crate::prelude::*;

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

#[test]
fn very_old_artificial_time() {
    use crate::prelude::*;
    let key = RS256PublicKey::from_pem(
        r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt5N44H1mpb5Wlx/0e7Cd
oKTY8xt+3yMby8BgNdagVNkeCkZ4pRbmQXRWNC7qn//Zaxx9dnzHbzGCul5W0RLf
d3oB3PESwsrQh+oiXVEPTYhvUPQkX0vBfCXJtg/zY2mY1DxKOIiXnZ8PaK/7Sx0a
MmvR//0Yy2a5dIAWCmjPsxn+PcGZOkVUm+D5bH1+ZStcA/68r4ZSPix7Szhgl1Ro
Hb9Q6JSekyZqM0Qfwhgb7srZVXC/9/m5PEx9wMVNYpYJBrXhD5IQm9RzE9oJS8T+
Ai+4/5mNTNXI8f1rrYgffWS4wf9cvsEihrvEg9867B2f98L7ux9Llle7jsHCtwgV
1wIDAQAB
-----END PUBLIC KEY-----"#,
    )
    .unwrap();
    let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiQWRhIExvdmVsYWNlIiwiaXNzIjoiaHR0cHM6Ly9jaHJvbm9nZWFycy5jb20vdGVzdCIsImF1ZCI6InRlc3QiLCJhdXRoX3RpbWUiOjEwMCwidXNlcl9pZCI6InVpZDEyMyIsInN1YiI6InNidTEyMyIsImlhdCI6MjAwLCJleHAiOjUwMCwibmJmIjozMDAsImVtYWlsIjoiYWxvdmVsYWNlQGNocm9ub2dlYXJzLmNvbSJ9.eTQnwXrri_uY55fS4IygseBzzbosDM1hP153EZXzNlLH5s29kdlGt2mL_KIjYmQa8hmptt9RwKJHBtw6l4KFHvIcuif86Ix-iI2fCpqNnKyGZfgERV51NXk1THkgWj0GQB6X5cvOoFIdHa9XvgPl_rVmzXSUYDgkhd2t01FOjQeeT6OL2d9KdlQHJqAsvvKVc3wnaYYoSqv2z0IluvK93Tk1dUBU2yWXH34nX3GAVGvIoFoNRiiFfZwFlnz78G0b2fQV7B5g5F8XlNRdD1xmVZXU8X2-xh9LqRpnEakdhecciFHg0u6AyC4c00rlo_HBb69wlXajQ3R4y26Kpxn7HA";

    let mut options = VerificationOptions::default();
    options.artificial_time = Some(UnixTimeStamp::from_secs(400));
    let res = key.verify_token::<NoCustomClaims>(jwt, Some(options.clone()));
    assert!(res.is_err());

    options.time_tolerance = Some(Duration::from_secs(100));
    key.verify_token::<NoCustomClaims>(jwt, Some(options))
        .unwrap();
}
