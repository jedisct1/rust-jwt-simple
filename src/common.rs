use coarsetime::{Duration, UnixTimeStamp};
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder, Hex};
use std::collections::HashSet;

use crate::error::*;

/// Additional features to enable during verification.
/// Signatures and token expiration are already automatically verified.
#[derive(Clone, Debug, Default)]
pub struct VerificationOptions {
    /// Reject tokens created before the given date
    ///
    /// For a given user, the time of the last successful authentication can be kept in a database,
    /// and `reject_before` can then be used to reject older (replayed) tokens.
    pub reject_before: Option<UnixTimeStamp>,

    /// Accept tokens created with a date in the future
    pub accept_future: bool,

    /// Require a specific subject to be present
    pub required_subject: Option<String>,

    /// Require a specific key identifierto be present
    pub required_key_id: Option<String>,

    /// Require a specific public key to be present
    pub required_public_key: Option<String>,

    /// Require a specific nonce to be present
    pub required_nonce: Option<String>,

    /// Require the issuer to be present in the set
    pub allowed_issuers: Option<HashSet<String>>,

    /// Require the audience to be present in the set
    pub allowed_audiences: Option<HashSet<String>>,

    /// Time tolerance for validating expiration dates
    pub time_tolerance: Option<Duration>,

    /// Reject tokens created more than `max_validity` ago
    pub max_validity: Option<Duration>,
}

/// Unsigned metadata about a key to be attached to tokens
#[derive(Debug, Clone, Default)]
pub struct KeyMetadata {
    pub(crate) key_set_url: Option<String>,
    pub(crate) public_key: Option<String>,
    pub(crate) certificate_url: Option<String>,
    pub(crate) certificate_sha1_thumbprint: Option<String>,
    pub(crate) certificate_sha256_thumbprint: Option<String>,
}

impl KeyMetadata {
    pub fn with_key_set_url(mut self, key_set_url: impl ToString) -> Self {
        self.key_set_url = Some(key_set_url.to_string());
        self
    }

    pub fn with_public_key(mut self, public_key: impl ToString) -> Self {
        self.public_key = Some(public_key.to_string());
        self
    }

    pub fn with_certificate_url(mut self, certificate_url: impl ToString) -> Self {
        self.certificate_url = Some(certificate_url.to_string());
        self
    }

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
            let thumbprint = Base64UrlSafeNoPadding::encode_to_string(&bin)?;
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
            let thumbprint = Base64UrlSafeNoPadding::encode_to_string(&bin)?;
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
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).fold(0, |c, (x, y)| c | (x ^ y)) == 0
}
