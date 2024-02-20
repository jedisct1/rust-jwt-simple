use std::collections::HashSet;
use std::convert::TryInto;

use coarsetime::{Clock, Duration, UnixTimeStamp};
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::common::VerificationOptions;
use crate::error::*;
use crate::serde_additions;

pub const DEFAULT_TIME_TOLERANCE_SECS: u64 = 900;

/// Type representing the fact that no application-defined claims is necessary.
#[derive(Copy, Clone, Default, Debug, Serialize, Deserialize)]
pub struct NoCustomClaims {}

/// Depending on applications, the `audiences` property may be either a set or a
/// string. We support both.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Audiences {
    AsSet(HashSet<String>),
    AsString(String),
}

impl Audiences {
    /// Return `true` if the audiences are represented as a set.
    pub fn is_set(&self) -> bool {
        matches!(self, Audiences::AsSet(_))
    }

    /// Return `true` if the audiences are represented as a string.
    pub fn is_string(&self) -> bool {
        matches!(self, Audiences::AsString(_))
    }

    /// Return `true` if the audiences include any of the `allowed_audiences`
    /// entries
    pub fn contains(&self, allowed_audiences: &HashSet<String>) -> bool {
        match self {
            Audiences::AsString(audience) => allowed_audiences.contains(audience),
            Audiences::AsSet(audiences) => {
                audiences.intersection(allowed_audiences).next().is_some()
            }
        }
    }

    /// Get the audiences as a set
    pub fn into_set(self) -> HashSet<String> {
        match self {
            Audiences::AsSet(audiences_set) => audiences_set,
            Audiences::AsString(audiences) => {
                let mut audiences_set = HashSet::new();
                if !audiences.is_empty() {
                    audiences_set.insert(audiences);
                }
                audiences_set
            }
        }
    }

    /// Get the audiences as a string.
    /// If it was originally serialized as a set, it can be only converted to a
    /// string if it contains at most one element.
    pub fn into_string(self) -> Result<String, Error> {
        match self {
            Audiences::AsString(audiences_str) => Ok(audiences_str),
            Audiences::AsSet(audiences) => {
                if audiences.len() > 1 {
                    bail!(JWTError::TooManyAudiences);
                }
                Ok(audiences
                    .iter()
                    .next()
                    .map(|x| x.to_string())
                    .unwrap_or_default())
            }
        }
    }
}

impl TryInto<String> for Audiences {
    type Error = Error;

    fn try_into(self) -> Result<String, Error> {
        self.into_string()
    }
}

impl From<Audiences> for HashSet<String> {
    fn from(audiences: Audiences) -> HashSet<String> {
        audiences.into_set()
    }
}

impl<T: ToString> From<T> for Audiences {
    fn from(audience: T) -> Self {
        Audiences::AsString(audience.to_string())
    }
}

/// A set of JWT claims.
///
/// The `CustomClaims` parameter can be set to `NoCustomClaims` if only standard
/// claims are used, or to a user-defined type that must be `serde`-serializable
/// if custom claims are required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWTClaims<CustomClaims> {
    /// Time the claims were created at
    #[serde(
        rename = "iat",
        default,
        skip_serializing_if = "Option::is_none",
        with = "self::serde_additions::unix_timestamp"
    )]
    pub issued_at: Option<UnixTimeStamp>,

    /// Time the claims expire at
    #[serde(
        rename = "exp",
        default,
        skip_serializing_if = "Option::is_none",
        with = "self::serde_additions::unix_timestamp"
    )]
    pub expires_at: Option<UnixTimeStamp>,

    /// Time the claims will be invalid until
    #[serde(
        rename = "nbf",
        default,
        skip_serializing_if = "Option::is_none",
        with = "self::serde_additions::unix_timestamp"
    )]
    pub invalid_before: Option<UnixTimeStamp>,

    /// Issuer - This can be set to anything application-specific
    #[serde(rename = "iss", default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    /// Subject - This can be set to anything application-specific
    #[serde(rename = "sub", default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    /// Audience
    #[serde(
        rename = "aud",
        default,
        skip_serializing_if = "Option::is_none",
        with = "self::serde_additions::audiences"
    )]
    pub audiences: Option<Audiences>,

    /// JWT identifier
    ///
    /// That property was originally designed to avoid replay attacks, but
    /// keeping all previously sent JWT token IDs is unrealistic.
    ///
    /// Replay attacks are better addressed by keeping only the timestamp of the
    /// last valid token for a user, and rejecting anything older in future
    /// tokens.
    #[serde(rename = "jti", default, skip_serializing_if = "Option::is_none")]
    pub jwt_id: Option<String>,

    /// Nonce
    #[serde(rename = "nonce", default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Custom (application-defined) claims
    #[serde(flatten)]
    pub custom: CustomClaims,
}

impl<CustomClaims> JWTClaims<CustomClaims> {
    pub(crate) fn validate(&self, options: &VerificationOptions) -> Result<(), Error> {
        let now = options
            .artificial_time
            .unwrap_or_else(Clock::now_since_epoch);
        let time_tolerance = options.time_tolerance.unwrap_or_default();

        if let Some(reject_before) = options.reject_before {
            ensure!(now >= reject_before, JWTError::OldTokenReused);
        }
        if let Some(time_issued) = self.issued_at {
            ensure!(time_issued <= now + time_tolerance, JWTError::ClockDrift);
            if let Some(max_validity) = options.max_validity {
                ensure!(
                    now <= time_issued || now - time_issued <= max_validity,
                    JWTError::TokenIsTooOld
                );
            }
        }
        if !options.accept_future {
            if let Some(invalid_before) = self.invalid_before {
                ensure!(
                    now + time_tolerance >= invalid_before,
                    JWTError::TokenNotValidYet
                );
            }
        }
        if let Some(expires_at) = self.expires_at {
            ensure!(
                now >= time_tolerance && now - time_tolerance <= expires_at,
                JWTError::TokenHasExpired
            );
        }
        if let Some(allowed_issuers) = &options.allowed_issuers {
            if let Some(issuer) = &self.issuer {
                ensure!(
                    allowed_issuers.contains(issuer),
                    JWTError::RequiredIssuerMismatch
                );
            } else {
                bail!(JWTError::RequiredIssuerMissing);
            }
        }
        if let Some(required_subject) = &options.required_subject {
            if let Some(subject) = &self.subject {
                ensure!(
                    subject == required_subject,
                    JWTError::RequiredSubjectMismatch
                );
            } else {
                bail!(JWTError::RequiredSubjectMissing);
            }
        }
        if let Some(required_nonce) = &options.required_nonce {
            if let Some(nonce) = &self.nonce {
                ensure!(nonce == required_nonce, JWTError::RequiredNonceMismatch);
            } else {
                bail!(JWTError::RequiredNonceMissing);
            }
        }
        if let Some(allowed_audiences) = &options.allowed_audiences {
            if let Some(audiences) = &self.audiences {
                ensure!(
                    audiences.contains(allowed_audiences),
                    JWTError::RequiredAudienceMismatch
                );
            } else {
                bail!(JWTError::RequiredAudienceMissing);
            }
        }
        Ok(())
    }

    /// Set the token as not being valid until `unix_timestamp`
    pub fn invalid_before(mut self, unix_timestamp: UnixTimeStamp) -> Self {
        self.invalid_before = Some(unix_timestamp);
        self
    }

    /// Set the issuer
    pub fn with_issuer(mut self, issuer: impl ToString) -> Self {
        self.issuer = Some(issuer.to_string());
        self
    }

    /// Set the subject
    pub fn with_subject(mut self, subject: impl ToString) -> Self {
        self.subject = Some(subject.to_string());
        self
    }

    /// Register one or more audiences (optional recipient identifiers), as a
    /// set
    pub fn with_audiences(mut self, audiences: HashSet<impl ToString>) -> Self {
        self.audiences = Some(Audiences::AsSet(
            audiences.iter().map(|x| x.to_string()).collect(),
        ));
        self
    }

    /// Set a unique audience (an optional recipient identifier), as a string
    pub fn with_audience(mut self, audience: impl ToString) -> Self {
        self.audiences = Some(Audiences::AsString(audience.to_string()));
        self
    }

    /// Set the JWT identifier
    pub fn with_jwt_id(mut self, jwt_id: impl ToString) -> Self {
        self.jwt_id = Some(jwt_id.to_string());
        self
    }

    /// Set the nonce
    pub fn with_nonce(mut self, nonce: impl ToString) -> Self {
        self.nonce = Some(nonce.to_string());
        self
    }

    /// Create a nonce, attach it and return it
    pub fn create_nonce(&mut self) -> String {
        let mut raw_nonce = [0u8; 24];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut raw_nonce);
        let nonce = Base64UrlSafeNoPadding::encode_to_string(raw_nonce).unwrap();
        self.nonce = Some(nonce);
        self.nonce.as_deref().unwrap().to_string()
    }
}

pub struct Claims;

impl Claims {
    /// Create a new set of claims, without custom data, expiring in
    /// `valid_for`.
    pub fn create(valid_for: Duration) -> JWTClaims<NoCustomClaims> {
        let now = Some(Clock::now_since_epoch());
        JWTClaims {
            issued_at: now,
            expires_at: Some(now.unwrap() + valid_for),
            invalid_before: now,
            audiences: None,
            issuer: None,
            jwt_id: None,
            subject: None,
            nonce: None,
            custom: NoCustomClaims {},
        }
    }

    /// Create a new set of claims, with custom data, expiring in `valid_for`.
    pub fn with_custom_claims<CustomClaims: Serialize + DeserializeOwned>(
        custom_claims: CustomClaims,
        valid_for: Duration,
    ) -> JWTClaims<CustomClaims> {
        let now = Some(Clock::now_since_epoch());
        JWTClaims {
            issued_at: now,
            expires_at: Some(now.unwrap() + valid_for),
            invalid_before: now,
            audiences: None,
            issuer: None,
            jwt_id: None,
            subject: None,
            nonce: None,
            custom: custom_claims,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_set_standard_claims() {
        let exp = Duration::from_mins(10);
        let mut audiences = HashSet::new();
        audiences.insert("audience1".to_string());
        audiences.insert("audience2".to_string());
        let claims = Claims::create(exp)
            .with_audiences(audiences.clone())
            .with_issuer("issuer")
            .with_jwt_id("jwt_id")
            .with_nonce("nonce")
            .with_subject("subject");

        assert_eq!(claims.audiences, Some(Audiences::AsSet(audiences)));
        assert_eq!(claims.issuer, Some("issuer".to_owned()));
        assert_eq!(claims.jwt_id, Some("jwt_id".to_owned()));
        assert_eq!(claims.nonce, Some("nonce".to_owned()));
        assert_eq!(claims.subject, Some("subject".to_owned()));
    }

    #[test]
    fn parse_floating_point_unix_time() {
        let claims: JWTClaims<()> = serde_json::from_str(r#"{"exp":1617757825.8}"#).unwrap();
        assert_eq!(
            claims.expires_at,
            Some(UnixTimeStamp::from_secs(1617757825))
        );
    }

    #[test]
    fn should_tolerate_clock_drift() {
        let exp = Duration::from_mins(1);
        let claims = Claims::create(exp);
        let mut options = VerificationOptions::default();

        // Verifier clock is 2 minutes ahead of the token clock.
        // The token is valid for 1 minute, with an extra tolerance of 1 minute.
        // Verification should pass.
        let drift = Duration::from_mins(2);
        options.artificial_time = Some(claims.issued_at.unwrap() + drift);
        options.time_tolerance = Some(Duration::from_mins(1));
        claims.validate(&options).unwrap();

        // Verifier clock is 2 minutes ahead of the token clock.
        // The token is valid for 1 minute, with an extra tolerance of 1 minute.
        // Verification must not pass.
        let drift = Duration::from_mins(3);
        options.artificial_time = Some(claims.issued_at.unwrap() + drift);
        options.time_tolerance = Some(Duration::from_mins(1));
        assert!(claims.validate(&options).is_err());

        // Verifier clock is 2 minutes ahead of the token clock.
        // The token is valid for 30 seconds, with an extra tolerance of 1 minute.
        // Verification must not pass.
        let drift = Duration::from_secs(30);
        options.artificial_time = Some(claims.issued_at.unwrap() + drift);
        options.time_tolerance = Some(Duration::from_mins(1));
        claims.validate(&options).unwrap();

        // Verifier clock is 2 minutes behind the token clock.
        // The token is valid for 1 minute, so it is already expired.
        // We have a tolerance of 1 minute.
        // Verification must not pass.
        let drift = Duration::from_mins(2);
        options.artificial_time = Some(claims.issued_at.unwrap() - drift);
        options.time_tolerance = Some(Duration::from_mins(1));
        assert!(claims.validate(&options).is_err());

        // Verifier clock is 2 minutes behind the token clock.
        // The token is valid for 1 minute, so it is already expired.
        // We have a tolerance of 2 minute.
        // Verification should pass.
        let drift = Duration::from_mins(2);
        options.artificial_time = Some(claims.issued_at.unwrap() - drift);
        options.time_tolerance = Some(Duration::from_mins(2));
        claims.validate(&options).unwrap();
    }
}
