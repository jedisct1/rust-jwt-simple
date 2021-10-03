use std::collections::HashSet;

use coarsetime::{Duration, UnixTimeStamp};

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

impl VerificationOptions {
    /// Reject tokens created before the given date
    ///
    /// For a given user, the time of the last successful authentication can be kept in a database,
    /// and `reject_before` can then be used to reject older (replayed) tokens.
    pub fn with_reject_before(mut self, reject_before: UnixTimeStamp) -> Self {
        self.reject_before = Some(reject_before);
        self
    }

    /// Accept tokens created with a date in the future
    pub fn with_accept_future(mut self, accept_future: bool) -> Self {
        self.accept_future = accept_future;
        self
    }

    /// Require a specific subject to be present
    pub fn with_required_subject(mut self, required_subject: impl ToString) -> Self {
        self.required_subject = Some(required_subject.to_string());
        self
    }

    /// Require a specific key identifierto be present
    pub fn with_required_key_id(mut self, required_key_id: impl ToString) -> Self {
        self.required_key_id = Some(required_key_id.to_string());
        self
    }

    /// Require a specific public key to be present
    pub fn with_required_public_key(mut self, required_public_key: impl ToString) -> Self {
        self.required_public_key = Some(required_public_key.to_string());
        self
    }

    /// Require a specific nonce to be present
    pub fn with_required_nonce(mut self, required_nonce: impl ToString) -> Self {
        self.required_nonce = Some(required_nonce.to_string());
        self
    }

    /// Require the issuer to be present in the set
    pub fn with_allowed_issuers(mut self, allowed_issuers: HashSet<impl ToString>) -> Self {
        self.allowed_issuers = Some(allowed_issuers.iter().map(|x| x.to_string()).collect());
        self
    }

    /// Require the audience to be present in the set
    pub fn with_allowed_audiences(mut self, allowed_audiences: HashSet<impl ToString>) -> Self {
        self.allowed_audiences = Some(allowed_audiences.iter().map(|x| x.to_string()).collect());
        self
    }

    /// Time tolerance for validating expiration dates
    pub fn with_time_tolerance(mut self, time_tolerance: Duration) -> Self {
        self.time_tolerance = Some(time_tolerance);
        self
    }

    /// Reject tokens created more than `max_validity` ago
    pub fn with_max_validity(mut self, max_validity: Duration) -> Self {
        self.max_validity = Some(max_validity);
        self
    }
}

#[inline(never)]
pub(crate) fn timingsafe_eq(a: &[u8], b: &[u8]) -> bool {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).fold(0, |c, (x, y)| c | (x ^ y)) == 0
}
