use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use hmac_sha512::sha384 as hmac_sha384;
use rand::RngCore;
use serde::{de::DeserializeOwned, Serialize};
use zeroize::Zeroize;

use crate::claims::*;
use crate::common::*;
use crate::error::*;
use crate::jwt_header::*;
use crate::token::*;

#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct HMACKey(Vec<u8>);

impl Drop for HMACKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl HMACKey {
    pub fn from_bytes(raw_key: &[u8]) -> Self {
        HMACKey(raw_key.to_vec())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn generate() -> Self {
        let mut raw_key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw_key);
        HMACKey(raw_key)
    }
}

impl AsRef<[u8]> for HMACKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub trait MACLike {
    fn jwt_alg_name() -> &'static str;
    fn key(&self) -> &HMACKey;
    fn key_id(&self) -> &Option<String>;
    fn set_key_id(&mut self, key_id: String);
    fn authentication_tag(&self, authenticated: &str) -> Vec<u8>;

    fn authenticate<CustomClaims: Serialize + DeserializeOwned>(
        &self,
        claims: JWTClaims<CustomClaims>,
    ) -> Result<String, Error> {
        let jwt_header = JWTHeader {
            algorithm: Self::jwt_alg_name().to_string(),
            key_id: self.key_id().clone(),
            ..Default::default()
        };
        Token::build(&jwt_header, claims, |authenticated| {
            Ok(self.authentication_tag(authenticated))
        })
    }

    fn verify_token<CustomClaims: Serialize + DeserializeOwned>(
        &self,
        token: &str,
        options: Option<VerificationOptions>,
    ) -> Result<JWTClaims<CustomClaims>, Error> {
        Token::verify(
            Self::jwt_alg_name(),
            token,
            options,
            |authenticated, authentication_tag| {
                ensure!(
                    timingsafe_eq(&self.authentication_tag(authenticated), authentication_tag),
                    JWTError::InvalidAuthenticationTag
                );
                Ok(())
            },
        )
    }

    fn create_key_id(&mut self) -> &str {
        self.set_key_id(
            Base64UrlSafeNoPadding::encode_to_string(hmac_sha256::Hash::hash(
                &self.key().to_bytes(),
            ))
            .unwrap(),
        );
        &self.key_id().as_ref().map(|x| x.as_str()).unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct HS256Key {
    key: HMACKey,
    key_id: Option<String>,
}

impl MACLike for HS256Key {
    fn jwt_alg_name() -> &'static str {
        "HS256"
    }

    fn key(&self) -> &HMACKey {
        &self.key
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn set_key_id(&mut self, key_id: String) {
        self.key_id = Some(key_id);
    }

    fn authentication_tag(&self, authenticated: &str) -> Vec<u8> {
        hmac_sha256::HMAC::mac(authenticated.as_bytes(), self.key().as_ref()).to_vec()
    }
}

impl HS256Key {
    pub fn from_bytes(raw_key: &[u8]) -> Self {
        HS256Key {
            key: HMACKey::from_bytes(raw_key),
            key_id: None,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.to_bytes()
    }

    pub fn generate() -> Self {
        HS256Key {
            key: HMACKey::generate(),
            key_id: None,
        }
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}

#[derive(Debug, Clone)]
pub struct HS512Key {
    key: HMACKey,
    key_id: Option<String>,
}

impl MACLike for HS512Key {
    fn jwt_alg_name() -> &'static str {
        "HS512"
    }

    fn key(&self) -> &HMACKey {
        &self.key
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn set_key_id(&mut self, key_id: String) {
        self.key_id = Some(key_id);
    }

    fn authentication_tag(&self, authenticated: &str) -> Vec<u8> {
        hmac_sha512::HMAC::mac(authenticated.as_bytes(), self.key().as_ref()).to_vec()
    }
}

impl HS512Key {
    pub fn from_bytes(raw_key: &[u8]) -> Self {
        HS512Key {
            key: HMACKey::from_bytes(raw_key),
            key_id: None,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.to_bytes()
    }

    pub fn generate() -> Self {
        HS512Key {
            key: HMACKey::generate(),
            key_id: None,
        }
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}

#[derive(Debug, Clone)]
pub struct HS384Key {
    key: HMACKey,
    key_id: Option<String>,
}

impl MACLike for HS384Key {
    fn jwt_alg_name() -> &'static str {
        "HS384"
    }

    fn key(&self) -> &HMACKey {
        &self.key
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn set_key_id(&mut self, key_id: String) {
        self.key_id = Some(key_id);
    }

    fn authentication_tag(&self, authenticated: &str) -> Vec<u8> {
        hmac_sha384::HMAC::mac(authenticated.as_bytes(), self.key().as_ref()).to_vec()
    }
}

impl HS384Key {
    pub fn from_bytes(raw_key: &[u8]) -> Self {
        HS384Key {
            key: HMACKey::from_bytes(raw_key),
            key_id: None,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.to_bytes()
    }

    pub fn generate() -> Self {
        HS384Key {
            key: HMACKey::generate(),
            key_id: None,
        }
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}
