use std::collections::HashSet;

use coarsetime::{Duration, UnixTimeStamp};
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder, Hex};

use crate::{claims::DEFAULT_TIME_TOLERANCE_SECS, error::*};

pub const DEFAULT_MAX_TOKEN_LENGTH: usize = 1_000_000;

/// Additional features to enable during verification.
/// Signatures and token expiration are already automatically verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationOptions {
    /// Reject tokens created before the given date
    ///
    /// For a given user, the time of the last successful authentication can be
    /// kept in a database, and `reject_before` can then be used to reject
    /// older (replayed) tokens.
    pub reject_before: Option<UnixTimeStamp>,

    /// Accept tokens created with a date in the future
    pub accept_future: bool,

    /// Require a specific subject to be present
    pub required_subject: Option<String>,

    /// Require a specific key identifier to be present
    pub required_key_id: Option<String>,

    /// Require a specific public key to be present
    pub required_public_key: Option<String>,

    /// Require a specific nonce to be present
    pub required_nonce: Option<String>,

    /// Require the issuer to be present in the set
    pub allowed_issuers: Option<HashSet<String>>,

    /// Require the audience to be present in the set
    pub allowed_audiences: Option<HashSet<String>>,

    /// How much clock drift to tolerate when verifying token timestamps
    /// Default is 15 minutes, to work around common issues with clocks that are not perfectly accurate
    pub time_tolerance: Option<Duration>,

    /// Reject tokens created more than `max_validity` ago
    pub max_validity: Option<Duration>,

    /// Maximum token length to accept
    pub max_token_length: Option<usize>,

    /// Maximum unsafe, untrusted, unverified JWT header length to accept
    pub max_header_length: Option<usize>,

    /// Change the current time. Only used for testing.
    pub artificial_time: Option<UnixTimeStamp>,
}

impl Default for VerificationOptions {
    fn default() -> Self {
        Self {
            reject_before: None,
            accept_future: false,
            required_subject: None,
            required_key_id: None,
            required_public_key: None,
            required_nonce: None,
            allowed_issuers: None,
            allowed_audiences: None,
            time_tolerance: Some(Duration::from_secs(DEFAULT_TIME_TOLERANCE_SECS)),
            max_validity: None,
            max_token_length: Some(DEFAULT_MAX_TOKEN_LENGTH),
            max_header_length: None,
            artificial_time: None,
        }
    }
}

/// Unsigned metadata about a key to be attached to tokens.
/// This information can be freely tampered with by an intermediate party.
/// Most applications should not need to use this.
#[derive(Debug, Clone, Default)]
pub struct KeyMetadata {
    pub(crate) key_set_url: Option<String>,
    pub(crate) public_key: Option<String>,
    pub(crate) certificate_url: Option<String>,
    pub(crate) certificate_sha1_thumbprint: Option<String>,
    pub(crate) certificate_sha256_thumbprint: Option<String>,
}

impl KeyMetadata {
    /// Add a key set URL to the metadata ("jku")
    pub fn with_key_set_url(mut self, key_set_url: impl ToString) -> Self {
        self.key_set_url = Some(key_set_url.to_string());
        self
    }

    /// Add a public key to the metadata ("jwk")
    pub fn with_public_key(mut self, public_key: impl ToString) -> Self {
        self.public_key = Some(public_key.to_string());
        self
    }

    /// Add a certificate URL to the metadata ("x5u")
    pub fn with_certificate_url(mut self, certificate_url: impl ToString) -> Self {
        self.certificate_url = Some(certificate_url.to_string());
        self
    }

    /// Add a certificate SHA-1 thumbprint to the metadata ("x5t")
    pub fn with_certificate_sha1_thumbprint(
        mut self,
        certificate_sha1_thumbprint: impl ToString,
    ) -> Result<Self, Error> {
        let thumbprint = certificate_sha1_thumbprint.to_string();
        let mut bin = [0u8; 20];
        if thumbprint.len() == 40 {
            ensure!(
                Hex::decode(&mut bin, &thumbprint, None)?.len() == bin.len(),
                JWTError::InvalidCertThumprint
            );
            let thumbprint = Base64UrlSafeNoPadding::encode_to_string(bin)?;
            self.certificate_sha1_thumbprint = Some(thumbprint);
            return Ok(self);
        }
        ensure!(
            Base64UrlSafeNoPadding::decode(&mut bin, &thumbprint, None)?.len() == bin.len(),
            JWTError::InvalidCertThumprint
        );
        self.certificate_sha1_thumbprint = Some(thumbprint);
        Ok(self)
    }

    /// Add a certificate SHA-256 thumbprint to the metadata ("x5t#256")
    pub fn with_certificate_sha256_thumbprint(
        mut self,
        certificate_sha256_thumbprint: impl ToString,
    ) -> Result<Self, Error> {
        let thumbprint = certificate_sha256_thumbprint.to_string();
        let mut bin = [0u8; 32];
        if thumbprint.len() == 64 {
            ensure!(
                Hex::decode(&mut bin, &thumbprint, None)?.len() == bin.len(),
                JWTError::InvalidCertThumprint
            );
            let thumbprint = Base64UrlSafeNoPadding::encode_to_string(bin)?;
            self.certificate_sha256_thumbprint = Some(thumbprint);
            return Ok(self);
        }
        ensure!(
            Base64UrlSafeNoPadding::decode(&mut bin, &thumbprint, None)?.len() == bin.len(),
            JWTError::InvalidCertThumprint
        );
        self.certificate_sha256_thumbprint = Some(thumbprint);
        Ok(self)
    }
}

#[inline(never)]
pub(crate) fn timingsafe_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0, |c, (x, y)| c | (x ^ y)) == 0
}
