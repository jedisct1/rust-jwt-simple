pub use anyhow::{anyhow, bail, ensure, Error};

#[derive(Debug, thiserror::Error)]
pub enum JWTError {
    #[error("Internal error: [{0}]")]
    InternalError(String),
    #[error("JWT compact encoding error")]
    CompactEncodingError,
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
    #[error("Required audiences missing")]
    RequiredAudiencesMissing,
    #[error("Required audiences mismatch")]
    RequiredAudiencesMismatch,
    #[error("Unsupported RSA modulus")]
    UnsupportedRSAModulus,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid key pair")]
    InvalidKeyPair,
    #[error("A single audience can be represented as a string instead of a set")]
    TooManyAudiences,
}

impl From<&str> for JWTError {
    fn from(e: &str) -> JWTError {
        JWTError::InternalError(e.into())
    }
}
