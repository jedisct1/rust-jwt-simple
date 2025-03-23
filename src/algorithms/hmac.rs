use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use hmac_sha512::sha384 as hmac_sha384;
use rand::RngCore;
use serde::{de::DeserializeOwned, Serialize};
use zeroize::Zeroize;

use crate::claims::*;
use crate::common::*;
#[cfg(feature = "cwt")]
use crate::cwt_token::*;
use crate::error::*;
use crate::jwt_header::*;
use crate::token::*;

#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct HMACKey {
    raw_key: Vec<u8>,
    metadata: Option<KeyMetadata>,
}

impl Drop for HMACKey {
    fn drop(&mut self) {
        self.raw_key.zeroize();
    }
}

impl HMACKey {
    /// Create a HMAC key from a byte slice.
    pub fn from_bytes(raw_key: &[u8]) -> Self {
        HMACKey {
            raw_key: raw_key.to_vec(),
            metadata: None,
        }
    }

    /// Convert the HMAC key to a byte slice.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.raw_key.clone()
    }

    /// Get the salt associated with the key.
    pub fn salt(&self) -> Option<Salt> {
        self.metadata.as_ref().map(|metadata| metadata.salt.clone())
    }

    /// Set the salt associated with the key.
    pub fn with_salt(mut self, salt: Salt) -> Self {
        if let Some(metadata) = self.metadata.as_mut() {
            metadata.salt = salt;
        } else {
            self.metadata = Some(KeyMetadata {
                salt,
                ..Default::default()
            });
        }
        self
    }

    /// Generate a random HMAC key.
    pub fn generate() -> Self {
        let mut raw_key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw_key);
        HMACKey {
            raw_key,
            metadata: None,
        }
    }

    /// Generate a random HMAC key with a random salt.
    pub fn generate_with_salt() -> Self {
        HMACKey::generate().with_salt(Salt::generate())
    }
}

impl AsRef<[u8]> for HMACKey {
    /// Get the raw key, as a byte slice
    fn as_ref(&self) -> &[u8] {
        &self.raw_key
    }
}

pub trait MACLike {
    fn jwt_alg_name() -> &'static str;
    fn key(&self) -> &HMACKey;
    fn key_id(&self) -> &Option<String>;
    fn set_key_id(&mut self, key_id: String);
    fn metadata(&self) -> &Option<KeyMetadata>;
    fn attach_metadata(&mut self, metadata: KeyMetadata) -> Result<(), Error>;
    fn authentication_tag(&self, authenticated: &[u8]) -> Vec<u8>;

    /// Get the salt associated with the key.
    fn salt(&self) -> Salt {
        self.metadata()
            .as_ref()
            .map(|metadata| metadata.salt.clone())
            .unwrap_or(Salt::None)
    }

    /// Compute the salt to be used for verification, given a signer salt.
    fn verifier_salt(&self) -> Result<Salt, Error> {
        match self.metadata().as_ref().map(|metadata| &metadata.salt) {
            None => bail!(JWTError::MissingSalt),
            Some(Salt::Signer(salt)) => {
                let authenticated_salt = self.authentication_tag(salt);
                Ok(Salt::Verifier(authenticated_salt))
            }
            Some(x @ Salt::Verifier(_)) => Ok(x.clone()),
            Some(Salt::None) => bail!(JWTError::MissingSalt),
        }
    }

    /// Attach a salt to the key.
    fn attach_salt(&mut self, salt: Salt) -> Result<(), Error> {
        let metadata = KeyMetadata {
            salt,
            ..Default::default()
        };
        self.attach_metadata(metadata).unwrap();
        Ok(())
    }

    /// Authenticate a token.
    fn authenticate<CustomClaims: Serialize + DeserializeOwned>(
        &self,
        claims: JWTClaims<CustomClaims>,
    ) -> Result<String, Error> {
        self.authenticate_with_options(claims, &Default::default())
    }

    fn authenticate_with_options<CustomClaims: Serialize + DeserializeOwned>(
        &self,
        claims: JWTClaims<CustomClaims>,
        options: &HeaderOptions,
    ) -> Result<String, Error> {
        let jwt_header = JWTHeader::new(Self::jwt_alg_name().to_string(), self.key_id().clone())
            .with_key_metadata(self.metadata())
            .with_options(options);
        Token::build(&jwt_header, claims, |authenticated| {
            Ok(self.authentication_tag(authenticated.as_bytes()))
        })
    }

    /// Verify a token.
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
                    timingsafe_eq(
                        &self.authentication_tag(authenticated.as_bytes()),
                        authentication_tag
                    ),
                    JWTError::InvalidAuthenticationTag
                );
                Ok(())
            },
            |salt: Option<&[u8]>| {
                if let Some(Salt::Verifier(authenticated_salt)) =
                    self.metadata().as_ref().map(|metadata| &metadata.salt)
                {
                    match salt {
                        None => bail!(JWTError::MissingSalt),
                        Some(salt) => {
                            let expected_authenticated_tag = self.authentication_tag(salt);
                            ensure!(
                                timingsafe_eq(authenticated_salt, &expected_authenticated_tag),
                                JWTError::InvalidAuthenticationTag
                            );
                        }
                    }
                } else {
                    ensure!(salt.is_none(), JWTError::MissingSalt);
                }
                Ok(())
            },
        )
    }

    #[cfg(feature = "cwt")]
    fn verify_cwt_token(
        &self,
        token: impl AsRef<[u8]>,
        options: Option<VerificationOptions>,
    ) -> Result<JWTClaims<NoCustomClaims>, Error> {
        CWTToken::verify(
            Self::jwt_alg_name(),
            token,
            options,
            |authenticated, authentication_tag| {
                ensure!(
                    timingsafe_eq(
                        &self.authentication_tag(authenticated.as_bytes()),
                        authentication_tag
                    ),
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
        self.key_id().as_ref().map(|x| x.as_str()).unwrap()
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

    fn metadata(&self) -> &Option<KeyMetadata> {
        &self.key.metadata
    }

    fn attach_metadata(&mut self, metadata: KeyMetadata) -> Result<(), Error> {
        self.key.metadata = Some(metadata);
        Ok(())
    }

    fn authentication_tag(&self, authenticated: &[u8]) -> Vec<u8> {
        hmac_sha256::HMAC::mac(authenticated, self.key().as_ref()).to_vec()
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

    pub fn generate_with_salt() -> Self {
        HS256Key {
            key: HMACKey::generate_with_salt(),
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

    fn metadata(&self) -> &Option<KeyMetadata> {
        &self.key.metadata
    }

    fn attach_metadata(&mut self, metadata: KeyMetadata) -> Result<(), Error> {
        self.key.metadata = Some(metadata);
        Ok(())
    }

    fn authentication_tag(&self, authenticated: &[u8]) -> Vec<u8> {
        hmac_sha512::HMAC::mac(authenticated, self.key().as_ref()).to_vec()
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

    pub fn generate_with_salt() -> Self {
        HS512Key {
            key: HMACKey::generate_with_salt(),
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

    fn metadata(&self) -> &Option<KeyMetadata> {
        &self.key.metadata
    }

    fn attach_metadata(&mut self, metadata: KeyMetadata) -> Result<(), Error> {
        self.key.metadata = Some(metadata);
        Ok(())
    }

    fn authentication_tag(&self, authenticated: &[u8]) -> Vec<u8> {
        hmac_sha384::HMAC::mac(authenticated, self.key().as_ref()).to_vec()
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

    pub fn generate_with_salt() -> Self {
        HS384Key {
            key: HMACKey::generate_with_salt(),
            key_id: None,
        }
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}

//

#[derive(Debug, Clone)]
pub struct Blake2bKey {
    key: HMACKey,
    key_id: Option<String>,
}

impl MACLike for Blake2bKey {
    fn jwt_alg_name() -> &'static str {
        "BLAKE2B"
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

    fn metadata(&self) -> &Option<KeyMetadata> {
        &self.key.metadata
    }

    fn attach_metadata(&mut self, metadata: KeyMetadata) -> Result<(), Error> {
        self.key.metadata = Some(metadata);
        Ok(())
    }

    fn authentication_tag(&self, authenticated: &[u8]) -> Vec<u8> {
        blake2b_simd::Params::new()
            .hash_length(32)
            .key(self.key().as_ref())
            .to_state()
            .update(authenticated)
            .finalize()
            .as_bytes()
            .to_vec()
    }
}

impl Blake2bKey {
    pub fn from_bytes(raw_key: &[u8]) -> Self {
        Blake2bKey {
            key: HMACKey::from_bytes(raw_key),
            key_id: None,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.to_bytes()
    }

    pub fn generate() -> Self {
        Blake2bKey {
            key: HMACKey::generate(),
            key_id: None,
        }
    }

    pub fn generate_with_salt() -> Self {
        Blake2bKey {
            key: HMACKey::generate_with_salt(),
            key_id: None,
        }
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}
