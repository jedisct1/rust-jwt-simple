use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use k256::{
    ecdsa::{self, signature::RandomizedSigner, signature::Verifier as _},
    elliptic_curve::Generate as _,
};
use serde::{de::DeserializeOwned, Serialize};
use std::convert::TryFrom;

use crate::claims::*;
use crate::common::*;
use crate::error::*;
use crate::jwt_header::*;
use crate::token::*;

#[doc(hidden)]
#[derive(Debug)]
pub struct K256PublicKey(k256::PublicKey);

impl AsRef<k256::PublicKey> for K256PublicKey {
    fn as_ref(&self) -> &k256::PublicKey {
        &self.0
    }
}

impl K256PublicKey {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let k256_pk = k256::PublicKey::from_bytes(raw);
        Ok(K256PublicKey(k256_pk.ok_or(JWTError::InvalidPublicKey)?))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_ref().to_vec()
    }
}

#[doc(hidden)]
#[derive(Debug)]
pub struct K256KeyPair(k256::SecretKey);

impl AsRef<k256::SecretKey> for K256KeyPair {
    fn as_ref(&self) -> &k256::SecretKey {
        &self.0
    }
}

impl K256KeyPair {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let k256_key_pair = k256::SecretKey::from_bytes(raw)?;
        Ok(K256KeyPair(k256_key_pair))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    pub fn public_key(&self) -> K256PublicKey {
        let k256_pk = k256::PublicKey::from_secret_key(&self.0, true).expect("Invalid secret key");
        K256PublicKey(k256_pk)
    }

    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let k256_sk = k256::SecretKey::generate(&mut rng);
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
        let mut jwt_header = JWTHeader::default();
        jwt_header.algorithm = Self::jwt_alg_name().to_string();
        jwt_header.key_id = self.key_id().clone();
        Token::build(&jwt_header, claims, |authenticated| {
            let mut rng = rand::thread_rng();
            let signer = ecdsa::Signer::new(self.key_pair().as_ref())
                .map_err(|_| JWTError::InvalidKeyPair)?;
            let signature: ecdsa::Signature =
                signer.sign_with_rng(&mut rng, authenticated.as_bytes());
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
                let verifier = ecdsa::Verifier::new(self.public_key().as_ref())
                    .map_err(|_| JWTError::InvalidPublicKey)?;
                let ecdsa_signature = ecdsa::Signature::try_from(signature)
                    .map_err(|_| JWTError::InvalidSignature)?;
                verifier
                    .verify(authenticated.as_bytes(), &ecdsa_signature)
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
