use coarsetime::{Clock, Duration, UnixTimeStamp};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::common::VerificationOptions;
use crate::error::*;
use crate::serde_additions;

pub const DEFAULT_TIME_TOLERANCE_SECS: u64 = 900;

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct NoCustomClaims {}

#[derive(Serialize, Deserialize)]
pub struct JWTClaims<CustomClaims> {
    #[serde(
        rename = "iat",
        default,
        skip_serializing_if = "Option::is_none",
        with = "self::serde_additions::unix_timestamp"
    )]
    pub issued_at: Option<UnixTimeStamp>,

    #[serde(
        rename = "exp",
        default,
        skip_serializing_if = "Option::is_none",
        with = "self::serde_additions::unix_timestamp"
    )]
    pub expires_at: Option<UnixTimeStamp>,

    #[serde(
        rename = "nbf",
        default,
        skip_serializing_if = "Option::is_none",
        with = "self::serde_additions::unix_timestamp"
    )]
    pub invalid_before: Option<UnixTimeStamp>,

    #[serde(rename = "iss", default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    #[serde(rename = "sub", default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    #[serde(rename = "aud", default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,

    #[serde(rename = "jti", default, skip_serializing_if = "Option::is_none")]
    pub jwt_id: Option<String>,

    #[serde(flatten)]
    pub custom: CustomClaims,
}

impl<CustomClaims> JWTClaims<CustomClaims> {
    pub(crate) fn validate(&self, options: &VerificationOptions) -> Result<(), Error> {
        let now = Clock::now_since_epoch();
        let time_tolerance = options
            .time_toleratnce
            .unwrap_or_else(|| Duration::from_secs(DEFAULT_TIME_TOLERANCE_SECS));

        if let Some(reject_before) = options.reject_before {
            ensure!(now <= reject_before, JWTError::OldTokenReused);
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
                ensure!(now >= invalid_before, JWTError::TokenNotValidYet);
            }
        }
        if let Some(expires_at) = self.expires_at {
            ensure!(
                now - time_tolerance <= expires_at,
                JWTError::TokenHasExpired
            );
        }
        if let Some(required_issuer) = &options.required_issuer {
            if let Some(issuer) = &self.issuer {
                ensure!(issuer == required_issuer, JWTError::RequiredIssuerMismatch);
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
        Ok(())
    }

    pub fn invalid_before(mut self, unix_timestamp: UnixTimeStamp) -> Self {
        self.invalid_before = Some(unix_timestamp);
        self
    }

    pub fn with_issuer(mut self, issuer: String) -> Self {
        self.issuer = Some(issuer);
        self
    }

    pub fn with_subject(mut self, subject: String) -> Self {
        self.issuer = Some(subject);
        self
    }

    pub fn with_audience(mut self, audience: String) -> Self {
        self.issuer = Some(audience);
        self
    }

    pub fn with_jwt_id(mut self, jwt_id: String) -> Self {
        self.issuer = Some(jwt_id);
        self
    }
}

pub struct Claims;

impl Claims {
    pub fn create(valid_for: Duration) -> JWTClaims<NoCustomClaims> {
        let now = Some(Clock::now_since_epoch());
        JWTClaims {
            issued_at: now,
            expires_at: Some(now.unwrap() + valid_for),
            invalid_before: now,
            audience: None,
            issuer: None,
            jwt_id: None,
            subject: None,
            custom: NoCustomClaims {},
        }
    }

    pub fn with_custom_claims<CustomClaims: Serialize + DeserializeOwned>(
        custom_claims: CustomClaims,
        valid_for: Duration,
    ) -> JWTClaims<CustomClaims> {
        let now = Some(Clock::now_since_epoch());
        JWTClaims {
            issued_at: now,
            expires_at: Some(now.unwrap() + valid_for),
            invalid_before: now,
            audience: None,
            issuer: None,
            jwt_id: None,
            subject: None,
            custom: custom_claims,
        }
    }
}
