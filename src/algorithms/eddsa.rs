use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use serde::{de::DeserializeOwned, Serialize};

use crate::claims::*;
use crate::common::*;
use crate::error::*;
use crate::jwt_header::*;
use crate::token::*;

#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct Edwards25519PublicKey(ed25519_compact::PublicKey);

impl AsRef<ed25519_compact::PublicKey> for Edwards25519PublicKey {
    fn as_ref(&self) -> &ed25519_compact::PublicKey {
        &self.0
    }
}

impl Edwards25519PublicKey {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let ed25519_pk = ed25519_compact::PublicKey::from_slice(raw);
        Ok(Edwards25519PublicKey(
            ed25519_pk.map_err(|_| JWTError::InvalidPublicKey)?,
        ))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_ref().to_vec()
    }
}

#[doc(hidden)]
#[derive(Clone)]
pub struct Edwards25519KeyPair(ed25519_compact::KeyPair);

impl AsRef<ed25519_compact::KeyPair> for Edwards25519KeyPair {
    fn as_ref(&self) -> &ed25519_compact::KeyPair {
        &self.0
    }
}

impl Edwards25519KeyPair {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let ed25519_key_pair = ed25519_compact::KeyPair::from_slice(raw)?;
        Ok(Edwards25519KeyPair(ed25519_key_pair))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn public_key(&self) -> Edwards25519PublicKey {
        let ed25519_pk = self.0.pk;
        Edwards25519PublicKey(ed25519_pk)
    }

    pub fn generate() -> Self {
        let ed25519_sk = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::generate());
        Edwards25519KeyPair(ed25519_sk)
    }
}

#[doc(hidden)]
pub trait EdDSAKeyPairLike {
    fn jwt_alg_name() -> &'static str;
    fn key_pair(&self) -> &Edwards25519KeyPair;
    fn key_id(&self) -> &Option<String>;

    fn sign<CustomClaims: Serialize + DeserializeOwned>(
        &self,
        claims: JWTClaims<CustomClaims>,
    ) -> Result<String, Error> {
        let mut jwt_header = JWTHeader::default();
        jwt_header.algorithm = Self::jwt_alg_name().to_string();
        jwt_header.key_id = self.key_id().clone();
        Token::build(&jwt_header, claims, |authenticated| {
            let noise = ed25519_compact::Noise::generate();
            let signature = self.key_pair().as_ref().sk.sign(authenticated, Some(noise));
            Ok(signature.to_vec())
        })
    }
}

#[doc(hidden)]
pub trait EdDSAPublicKeyLike {
    fn jwt_alg_name() -> &'static str;
    fn public_key(&self) -> &Edwards25519PublicKey;
    fn key_id(&self) -> &Option<String>;
    fn set_key_id(&mut self, key_id: String);

    fn verify_token<CustomClaims: Serialize + DeserializeOwned>(
        &self,
        token: &str,
        options: Option<VerificationOptions>,
    ) -> Result<JWTClaims<CustomClaims>, Error> {
        Token::verify(
            Self::jwt_alg_name(),
            token,
            options,
            |authenticated, signature| {
                let ed25519_signature = ed25519_compact::Signature::from_slice(signature)?;
                self.public_key()
                    .as_ref()
                    .verify(authenticated, &ed25519_signature)
                    .map_err(|_| JWTError::InvalidSignature)?;
                Ok(())
            },
        )
    }

    fn create_key_id(&mut self) -> &str {
        self.set_key_id(
            Base64UrlSafeNoPadding::encode_to_string(hmac_sha256::Hash::hash(
                &self.public_key().to_bytes(),
            ))
            .unwrap(),
        );
        &self.key_id().as_ref().map(|x| x.as_str()).unwrap()
    }
}

#[derive(Clone)]
pub struct Ed25519KeyPair {
    key_pair: Edwards25519KeyPair,
    key_id: Option<String>,
}

#[derive(Debug)]
pub struct Ed25519PublicKey {
    pk: Edwards25519PublicKey,
    key_id: Option<String>,
}

impl EdDSAKeyPairLike for Ed25519KeyPair {
    fn jwt_alg_name() -> &'static str {
        "EdDSA"
    }

    fn key_pair(&self) -> &Edwards25519KeyPair {
        &self.key_pair
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }
}

impl Ed25519KeyPair {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(Ed25519KeyPair {
            key_pair: Edwards25519KeyPair::from_bytes(raw)?,
            key_id: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key_pair.to_bytes()
    }

    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey {
            pk: self.key_pair.public_key(),
            key_id: self.key_id.clone(),
        }
    }

    pub fn generate() -> Self {
        Ed25519KeyPair {
            key_pair: Edwards25519KeyPair::generate(),
            key_id: None,
        }
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}

impl EdDSAPublicKeyLike for Ed25519PublicKey {
    fn jwt_alg_name() -> &'static str {
        "EdDSA"
    }

    fn public_key(&self) -> &Edwards25519PublicKey {
        &self.pk
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn set_key_id(&mut self, key_id: String) {
        self.key_id = Some(key_id);
    }
}

impl Ed25519PublicKey {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(Ed25519PublicKey {
            pk: Edwards25519PublicKey::from_bytes(raw)?,
            key_id: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.pk.to_bytes()
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}
