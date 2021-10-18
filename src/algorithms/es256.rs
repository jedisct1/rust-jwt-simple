use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use p256::ecdsa::{self, signature::DigestVerifier as _, signature::RandomizedDigestSigner as _};
use serde::{de::DeserializeOwned, Serialize};
use std::convert::TryFrom;

use crate::claims::*;
use crate::common::*;
use crate::error::*;
use crate::jwt_header::*;
use crate::token::*;

#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct P256PublicKey(ecdsa::VerifyingKey);

impl AsRef<ecdsa::VerifyingKey> for P256PublicKey {
    fn as_ref(&self) -> &ecdsa::VerifyingKey {
        &self.0
    }
}

impl P256PublicKey {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let p256_pk =
            ecdsa::VerifyingKey::from_sec1_bytes(raw).map_err(|_| JWTError::InvalidPublicKey)?;
        Ok(P256PublicKey(p256_pk))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_encoded_point(true).as_bytes().to_vec()
    }

    pub fn to_bytes_uncompressed(&self) -> Vec<u8> {
        self.0.to_encoded_point(false).as_bytes().to_vec()
    }
}

#[doc(hidden)]
pub struct P256KeyPair {
    p256_sk: ecdsa::SigningKey,
    metadata: Option<KeyMetadata>,
}

impl AsRef<ecdsa::SigningKey> for P256KeyPair {
    fn as_ref(&self) -> &ecdsa::SigningKey {
        &self.p256_sk
    }
}

impl P256KeyPair {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let p256_sk = ecdsa::SigningKey::from_bytes(raw).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(P256KeyPair {
            p256_sk,
            metadata: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.p256_sk.to_bytes().to_vec()
    }

    pub fn public_key(&self) -> P256PublicKey {
        let p256_pk = self.p256_sk.verifying_key();
        P256PublicKey(p256_pk)
    }

    pub fn generate() -> Self {
        let rng = rand::thread_rng();
        let p256_sk = ecdsa::SigningKey::random(rng);
        P256KeyPair {
            p256_sk,
            metadata: None,
        }
    }
}

pub trait ECDSAP256KeyPairLike {
    fn jwt_alg_name() -> &'static str;
    fn key_pair(&self) -> &P256KeyPair;
    fn key_id(&self) -> &Option<String>;

    fn sign<CustomClaims: Serialize + DeserializeOwned>(
        &self,
        claims: JWTClaims<CustomClaims>,
    ) -> Result<String, Error> {
        let jwt_header = JWTHeader::new(Self::jwt_alg_name().to_string(), self.key_id().clone());
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

pub trait ECDSAP256PublicKeyLike {
    fn jwt_alg_name() -> &'static str;
    fn public_key(&self) -> &P256PublicKey;
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
        self.key_id().as_ref().map(|x| x.as_str()).unwrap()
    }
}

pub struct ES256KeyPair {
    key_pair: P256KeyPair,
    key_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ES256PublicKey {
    pk: P256PublicKey,
    key_id: Option<String>,
}

impl ECDSAP256KeyPairLike for ES256KeyPair {
    fn jwt_alg_name() -> &'static str {
        "ES256"
    }

    fn key_pair(&self) -> &P256KeyPair {
        &self.key_pair
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }
}

impl ES256KeyPair {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(ES256KeyPair {
            key_pair: P256KeyPair::from_bytes(raw)?,
            key_id: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key_pair.to_bytes()
    }

    pub fn public_key(&self) -> ES256PublicKey {
        ES256PublicKey {
            pk: self.key_pair.public_key(),
            key_id: self.key_id.clone(),
        }
    }

    pub fn generate() -> Self {
        ES256KeyPair {
            key_pair: P256KeyPair::generate(),
            key_id: None,
        }
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}

impl ECDSAP256PublicKeyLike for ES256PublicKey {
    fn jwt_alg_name() -> &'static str {
        "ES256"
    }

    fn public_key(&self) -> &P256PublicKey {
        &self.pk
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn set_key_id(&mut self, key_id: String) {
        self.key_id = Some(key_id);
    }
}

impl ES256PublicKey {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(ES256PublicKey {
            pk: P256PublicKey::from_bytes(raw)?,
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
