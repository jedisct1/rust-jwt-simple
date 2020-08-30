use coarsetime::{Duration, UnixTimeStamp};

#[derive(Clone, Debug, Default)]
pub struct VerificationOptions {
    pub reject_before: Option<UnixTimeStamp>,
    pub accept_future: bool,
    pub required_issuer: Option<String>,
    pub required_subject: Option<String>,
    pub required_key_id: Option<String>,
    pub required_public_key: Option<String>,
    pub time_tolerance: Option<Duration>,
    pub max_validity: Option<Duration>,
}

#[inline(never)]
pub(crate) fn timingsafe_eq(a: &[u8], b: &[u8]) -> bool {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).fold(0, |c, (x, y)| c | (x ^ y)) == 0
}
