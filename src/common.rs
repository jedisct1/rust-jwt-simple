use coarsetime::{Duration, UnixTimeStamp};

/// Additional features to enable during verification
#[derive(Clone, Debug, Default)]
pub struct VerificationOptions {
    /// Reject tokens created before the given date
    pub reject_before: Option<UnixTimeStamp>,

    /// Accept tokens created with a date in the future
    pub accept_future: bool,

    /// Require a specific issuer to be present
    pub required_issuer: Option<String>,

    /// Require a specific subject to be present
    pub required_subject: Option<String>,

    /// Require a specific key identifierto be present
    pub required_key_id: Option<String>,

    /// Require a specific public key to be present
    pub required_public_key: Option<String>,

    /// Require a specific nonce to be present
    pub required_nonce: Option<String>,

    /// Time tolerance for validating expiration dates
    pub time_tolerance: Option<Duration>,

    /// Reject tokens created more than `max_validity` ago
    pub max_validity: Option<Duration>,
}

#[inline(never)]
pub(crate) fn timingsafe_eq(a: &[u8], b: &[u8]) -> bool {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).fold(0, |c, (x, y)| c | (x ^ y)) == 0
}
