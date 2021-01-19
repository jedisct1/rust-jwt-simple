use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use k256::ecdsa::{self, signature::DigestVerifier as _, signature::RandomizedDigestSigner as _};
use p256::pkcs8::{FromPrivateKey as _, FromPublicKey as _};
use serde::{de::DeserializeOwned, Serialize};
use std::convert::TryFrom;

use crate::claims::*;
use crate::common::*;
use crate::error::*;
use crate::jwt_header::*;
use crate::token::*;

#[doc(hidden)]
#[derive(Debug)]
pub struct K256PublicKey(ecdsa::VerifyingKey);

impl AsRef<ecdsa::VerifyingKey> for K256PublicKey {
    fn as_ref(&self) -> &ecdsa::VerifyingKey {
        &self.0
    }
}

impl K256PublicKey {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let k256_pk =
            ecdsa::VerifyingKey::from_sec1_bytes(raw).map_err(|_| JWTError::InvalidPublicKey)?;
        Ok(K256PublicKey(k256_pk))
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let k256_pk = ecdsa::VerifyingKey::from_public_key_der(der)
            .map_err(|_| JWTError::InvalidPublicKey)?;
        Ok(K256PublicKey(k256_pk))
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let k256_pk = ecdsa::VerifyingKey::from_public_key_pem(pem)
            .map_err(|_| JWTError::InvalidPublicKey)?;
        Ok(K256PublicKey(k256_pk))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

#[doc(hidden)]
pub struct K256KeyPair(ecdsa::SigningKey);

impl AsRef<ecdsa::SigningKey> for K256KeyPair {
    fn as_ref(&self) -> &ecdsa::SigningKey {
        &self.0
    }
}

impl K256KeyPair {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let k256_key_pair =
            ecdsa::SigningKey::from_bytes(raw).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(K256KeyPair(k256_key_pair))
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let k256_key_pair =
            ecdsa::SigningKey::from_pkcs8_der(der).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(K256KeyPair(k256_key_pair))
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let k256_key_pair =
            ecdsa::SigningKey::from_pkcs8_pem(pem).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(K256KeyPair(k256_key_pair))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    pub fn public_key(&self) -> K256PublicKey {
        let k256_pk = self.0.verify_key();
        K256PublicKey(k256_pk)
    }

    pub fn generate() -> Self {
        let rng = rand::thread_rng();
        let k256_sk = ecdsa::SigningKey::random(rng);
        K256KeyPair(k256_sk)
    }
}

#[doc(hidden)]
pub trait ECDSAP256kKeyPairLike {
    #[doc(hidden)]
    fn jwt_alg_name() -> &'static str;

    #[doc(hidden)]
    fn key_pair(&self) -> &K256KeyPair;

    #[doc(hidden)]
    fn key_id(&self) -> &Option<String>;

    fn sign<CustomClaims: Serialize + DeserializeOwned>(
        &self,
        claims: JWTClaims<CustomClaims>,
    ) -> Result<String, Error> {
        let jwt_header = JWTHeader {
            algorithm: Self::jwt_alg_name().to_string(),
            key_id: self.key_id().clone(),
            ..Default::default()
        };
        Token::build(&jwt_header, claims, |authenticated| {
            let mut digest = hmac_sha256::Hash::new();
            digest.update(authenticated.as_bytes());
            let rng = rand::thread_rng();
            let signature: ecdsa::Signature =
                self.key_pair().as_ref().sign_digest_with_rng(rng, digest);
            Ok(signature.as_ref().to_vec())
        })
    }
}

#[doc(hidden)]
pub trait ECDSAP256kPublicKeyLike {
    fn jwt_alg_name() -> &'static str;
    fn public_key(&self) -> &K256PublicKey;
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
                let ecdsa_signature = ecdsa::Signature::try_from(signature)
                    .map_err(|_| JWTError::InvalidSignature)?;
                let mut digest = hmac_sha256::Hash::new();
                digest.update(authenticated.as_bytes());
                self.public_key()
                    .as_ref()
                    .verify_digest(digest, &ecdsa_signature)
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

pub struct ES256kKeyPair {
    key_pair: K256KeyPair,
    key_id: Option<String>,
}

#[derive(Debug)]
pub struct ES256kPublicKey {
    pk: K256PublicKey,
    key_id: Option<String>,
}

impl ECDSAP256kKeyPairLike for ES256kKeyPair {
    fn jwt_alg_name() -> &'static str {
        "ES256K"
    }

    fn key_pair(&self) -> &K256KeyPair {
        &self.key_pair
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }
}

impl ES256kKeyPair {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(ES256kKeyPair {
            key_pair: K256KeyPair::from_bytes(raw)?,
            key_id: None,
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(ES256kKeyPair {
            key_pair: K256KeyPair::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(ES256kKeyPair {
            key_pair: K256KeyPair::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key_pair.to_bytes()
    }

    pub fn public_key(&self) -> ES256kPublicKey {
        ES256kPublicKey {
            pk: self.key_pair.public_key(),
            key_id: self.key_id.clone(),
        }
    }

    pub fn generate() -> Self {
        ES256kKeyPair {
            key_pair: K256KeyPair::generate(),
            key_id: None,
        }
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}

impl ECDSAP256kPublicKeyLike for ES256kPublicKey {
    fn jwt_alg_name() -> &'static str {
        "ES256K"
    }

    fn public_key(&self) -> &K256PublicKey {
        &self.pk
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn set_key_id(&mut self, key_id: String) {
        self.key_id = Some(key_id);
    }
}

impl ES256kPublicKey {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(ES256kPublicKey {
            pk: K256PublicKey::from_bytes(raw)?,
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
