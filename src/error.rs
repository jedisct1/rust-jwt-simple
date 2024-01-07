#[allow(unused)]
pub use anyhow::{anyhow, bail, ensure, Error};

#[derive(Debug, thiserror::Error)]
pub enum JWTError {
    #[error("Internal error: [{0}]")]
    InternalError(String),
    #[error("JWT compact encoding error")]
    CompactEncodingError,
    #[error("CWT decoding error")]
    CWTDecodingError,
    #[error("JWT header too large")]
    HeaderTooLarge,
    #[error("JWT algorithm mismatch")]
    AlgorithmMismatch,
    #[error("JWT key identifier mismatch")]
    KeyIdentifierMismatch,
    #[error("Missing JWT key identifier")]
    MissingJWTKeyIdentifier,
    #[error("Authentication tag didn't verify")]
    InvalidAuthenticationTag,
    #[error("Signature tag didn't verify")]
    InvalidSignature,
    #[error("Old token reused")]
    OldTokenReused,
    #[error("Clock drift detected")]
    ClockDrift,
    #[error("Token is too old")]
    TokenIsTooOld,
    #[error("Token not valid yet")]
    TokenNotValidYet,
    #[error("Token has expired")]
    TokenHasExpired,
    #[error("Required nonce missing")]
    RequiredNonceMissing,
    #[error("Required nonce mismatch")]
    RequiredNonceMismatch,
    #[error("Required issuer mismatch")]
    RequiredIssuerMismatch,
    #[error("Required issuer missing")]
    RequiredIssuerMissing,
    #[error("Required subject mismatch")]
    RequiredSubjectMismatch,
    #[error("Required subject missing")]
    RequiredSubjectMissing,
    #[error("Required audience missing")]
    RequiredAudienceMissing,
    #[error("Required audience mismatch")]
    RequiredAudienceMismatch,
    #[error("Unsupported RSA modulus")]
    UnsupportedRSAModulus,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid key pair")]
    InvalidKeyPair,
    #[error("At most one audience can be represented as a string instead of a set")]
    TooManyAudiences,
    #[error("Too many issuers to be represented as a string")]
    TooManyIssuers,
    #[error("Invalid certificate thumbprint")]
    InvalidCertThumprint,
    #[error("Not a JWT token")]
    NotJWT,
    #[error("Token is too long")]
    TokenTooLong,
}

impl From<&str> for JWTError {
    fn from(e: &str) -> JWTError {
        JWTError::InternalError(e.into())
    }
}
