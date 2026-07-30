use std::convert::TryInto;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use serde::{de::DeserializeOwned, Serialize};
use superboring::mldsa::{Algorithm, MlDsaPrivateKey, MlDsaPublicKey};

use crate::claims::*;
use crate::common::*;
#[cfg(feature = "cwt")]
use crate::cwt_token::*;
use crate::error::*;
use crate::jwt_header::*;
use crate::token::*;

#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct MLDSAPublicKey(MlDsaPublicKey);

impl AsRef<MlDsaPublicKey> for MLDSAPublicKey {
    fn as_ref(&self) -> &MlDsaPublicKey {
        &self.0
    }
}

impl MLDSAPublicKey {
    pub fn from_bytes(algorithm: Algorithm, raw: &[u8]) -> Result<Self, Error> {
        let mldsa_pk = MlDsaPublicKey::from_slice(algorithm, raw);
        Ok(MLDSAPublicKey(
            mldsa_pk.map_err(|_| JWTError::InvalidPublicKey)?,
        ))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().expect("failed to serialize public key")
    }
}

#[doc(hidden)]
#[derive(Clone)]
pub struct MLDSAKeyPair {
    mldsa_sk: MlDsaPrivateKey,
    metadata: Option<KeyMetadata>,
}

impl std::fmt::Debug for MLDSAKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PKey")
            .field("algorithm", &"ML-DSA")
            .finish()
    }
}

impl AsRef<MlDsaPrivateKey> for MLDSAKeyPair {
    fn as_ref(&self) -> &MlDsaPrivateKey {
        &self.mldsa_sk
    }
}

impl MLDSAKeyPair {
    /// The raw representation of an ML-DSA key pair is its 32-byte seed, as
    /// mandated for JOSE and COSE.
    pub fn from_bytes(algorithm: Algorithm, raw: &[u8]) -> Result<Self, Error> {
        let seed = raw.try_into().map_err(|_| JWTError::InvalidKeyPair)?;
        let mldsa_sk =
            MlDsaPrivateKey::from_seed(algorithm, &seed).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(MLDSAKeyPair {
            mldsa_sk,
            metadata: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.mldsa_sk.seed_bytes().to_vec()
    }

    pub fn public_key(&self) -> MLDSAPublicKey {
        let mldsa_pk = self
            .mldsa_sk
            .public_key()
            .expect("failed to create public key");
        MLDSAPublicKey(mldsa_pk)
    }

    pub fn generate(algorithm: Algorithm) -> Self {
        let (_, mldsa_sk) =
            MlDsaPrivateKey::generate(algorithm).expect("failed to generate key pair");
        MLDSAKeyPair {
            mldsa_sk,
            metadata: None,
        }
    }
}

pub trait MLDSAKeyPairLike {
    fn jwt_alg_name() -> &'static str;
    fn key_pair(&self) -> &MLDSAKeyPair;
    fn key_id(&self) -> &Option<String>;
    fn metadata(&self) -> &Option<KeyMetadata>;
    fn attach_metadata(&mut self, metadata: KeyMetadata) -> Result<(), Error>;

    fn sign<CustomClaims: Serialize>(
        &self,
        claims: JWTClaims<CustomClaims>,
    ) -> Result<String, Error> {
        self.sign_with_options(claims, &Default::default())
    }

    fn sign_with_options<CustomClaims: Serialize>(
        &self,
        claims: JWTClaims<CustomClaims>,
        opts: &HeaderOptions,
    ) -> Result<String, Error> {
        let jwt_header = JWTHeader::new(Self::jwt_alg_name().to_string(), self.key_id().clone())
            .with_key_metadata(self.metadata())
            .with_options(opts);
        Token::build(&jwt_header, claims, |authenticated| {
            let signature = self.key_pair().as_ref().sign(authenticated.as_bytes())?;
            Ok(signature)
        })
    }
}

pub trait MLDSAPublicKeyLike {
    fn jwt_alg_name() -> &'static str;
    fn public_key(&self) -> &MLDSAPublicKey;
    fn key_id(&self) -> &Option<String>;
    fn set_key_id(&mut self, key_id: String);

    fn verify_token<CustomClaims: DeserializeOwned>(
        &self,
        token: &str,
        options: Option<VerificationOptions>,
    ) -> Result<JWTClaims<CustomClaims>, Error> {
        Token::verify(
            Self::jwt_alg_name(),
            token,
            options,
            |authenticated, signature| {
                self.public_key()
                    .as_ref()
                    .verify(authenticated.as_bytes(), signature)
                    .map_err(|_| JWTError::InvalidSignature)?;
                Ok(())
            },
            |_salt: Option<&[u8]>| Ok(()),
        )
    }

    #[cfg(feature = "cwt")]
    fn verify_cwt_token<CustomClaims: DeserializeOwned>(
        &self,
        token: &[u8],
        options: Option<VerificationOptions>,
    ) -> Result<JWTClaims<NoCustomClaims>, Error> {
        CWTToken::verify(
            Self::jwt_alg_name(),
            token,
            options,
            |authenticated, signature| {
                self.public_key()
                    .as_ref()
                    .verify(authenticated.as_bytes(), signature)
                    .map_err(|_| JWTError::InvalidSignature)?;
                Ok(())
            },
        )
    }

    /// Decode CWT token metadata that can be useful prior to signature/tag verification
    #[cfg(feature = "cwt")]
    fn decode_cwt_metadata(&self, token: impl AsRef<[u8]>) -> Result<TokenMetadata, Error> {
        CWTToken::decode_metadata(token)
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

#[derive(Clone)]
pub struct MLDSA44KeyPair {
    key_pair: MLDSAKeyPair,
    key_id: Option<String>,
}

impl std::fmt::Debug for MLDSA44KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PKey")
            .field("algorithm", &"ML-DSA-44")
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct MLDSA44PublicKey {
    pk: MLDSAPublicKey,
    key_id: Option<String>,
}

impl MLDSAKeyPairLike for MLDSA44KeyPair {
    fn jwt_alg_name() -> &'static str {
        "ML-DSA-44"
    }

    fn key_pair(&self) -> &MLDSAKeyPair {
        &self.key_pair
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn metadata(&self) -> &Option<KeyMetadata> {
        &self.key_pair.metadata
    }

    fn attach_metadata(&mut self, metadata: KeyMetadata) -> Result<(), Error> {
        self.key_pair.metadata = Some(metadata);
        Ok(())
    }
}

impl MLDSA44KeyPair {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(MLDSA44KeyPair {
            key_pair: MLDSAKeyPair::from_bytes(Algorithm::MlDsa44, raw)?,
            key_id: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key_pair.to_bytes()
    }

    pub fn public_key(&self) -> MLDSA44PublicKey {
        MLDSA44PublicKey {
            pk: self.key_pair.public_key(),
            key_id: self.key_id.clone(),
        }
    }

    pub fn generate() -> Self {
        MLDSA44KeyPair {
            key_pair: MLDSAKeyPair::generate(Algorithm::MlDsa44),
            key_id: None,
        }
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}

impl MLDSAPublicKeyLike for MLDSA44PublicKey {
    fn jwt_alg_name() -> &'static str {
        "ML-DSA-44"
    }

    fn public_key(&self) -> &MLDSAPublicKey {
        &self.pk
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn set_key_id(&mut self, key_id: String) {
        self.key_id = Some(key_id);
    }
}

impl MLDSA44PublicKey {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(MLDSA44PublicKey {
            pk: MLDSAPublicKey::from_bytes(Algorithm::MlDsa44, raw)?,
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

//

#[derive(Clone)]
pub struct MLDSA65KeyPair {
    key_pair: MLDSAKeyPair,
    key_id: Option<String>,
}

impl std::fmt::Debug for MLDSA65KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PKey")
            .field("algorithm", &"ML-DSA-65")
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct MLDSA65PublicKey {
    pk: MLDSAPublicKey,
    key_id: Option<String>,
}

impl MLDSAKeyPairLike for MLDSA65KeyPair {
    fn jwt_alg_name() -> &'static str {
        "ML-DSA-65"
    }

    fn key_pair(&self) -> &MLDSAKeyPair {
        &self.key_pair
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn metadata(&self) -> &Option<KeyMetadata> {
        &self.key_pair.metadata
    }

    fn attach_metadata(&mut self, metadata: KeyMetadata) -> Result<(), Error> {
        self.key_pair.metadata = Some(metadata);
        Ok(())
    }
}

impl MLDSA65KeyPair {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(MLDSA65KeyPair {
            key_pair: MLDSAKeyPair::from_bytes(Algorithm::MlDsa65, raw)?,
            key_id: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key_pair.to_bytes()
    }

    pub fn public_key(&self) -> MLDSA65PublicKey {
        MLDSA65PublicKey {
            pk: self.key_pair.public_key(),
            key_id: self.key_id.clone(),
        }
    }

    pub fn generate() -> Self {
        MLDSA65KeyPair {
            key_pair: MLDSAKeyPair::generate(Algorithm::MlDsa65),
            key_id: None,
        }
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}

impl MLDSAPublicKeyLike for MLDSA65PublicKey {
    fn jwt_alg_name() -> &'static str {
        "ML-DSA-65"
    }

    fn public_key(&self) -> &MLDSAPublicKey {
        &self.pk
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn set_key_id(&mut self, key_id: String) {
        self.key_id = Some(key_id);
    }
}

impl MLDSA65PublicKey {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(MLDSA65PublicKey {
            pk: MLDSAPublicKey::from_bytes(Algorithm::MlDsa65, raw)?,
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

//

#[derive(Clone)]
pub struct MLDSA87KeyPair {
    key_pair: MLDSAKeyPair,
    key_id: Option<String>,
}

impl std::fmt::Debug for MLDSA87KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PKey")
            .field("algorithm", &"ML-DSA-87")
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct MLDSA87PublicKey {
    pk: MLDSAPublicKey,
    key_id: Option<String>,
}

impl MLDSAKeyPairLike for MLDSA87KeyPair {
    fn jwt_alg_name() -> &'static str {
        "ML-DSA-87"
    }

    fn key_pair(&self) -> &MLDSAKeyPair {
        &self.key_pair
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn metadata(&self) -> &Option<KeyMetadata> {
        &self.key_pair.metadata
    }

    fn attach_metadata(&mut self, metadata: KeyMetadata) -> Result<(), Error> {
        self.key_pair.metadata = Some(metadata);
        Ok(())
    }
}

impl MLDSA87KeyPair {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(MLDSA87KeyPair {
            key_pair: MLDSAKeyPair::from_bytes(Algorithm::MlDsa87, raw)?,
            key_id: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key_pair.to_bytes()
    }

    pub fn public_key(&self) -> MLDSA87PublicKey {
        MLDSA87PublicKey {
            pk: self.key_pair.public_key(),
            key_id: self.key_id.clone(),
        }
    }

    pub fn generate() -> Self {
        MLDSA87KeyPair {
            key_pair: MLDSAKeyPair::generate(Algorithm::MlDsa87),
            key_id: None,
        }
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}

impl MLDSAPublicKeyLike for MLDSA87PublicKey {
    fn jwt_alg_name() -> &'static str {
        "ML-DSA-87"
    }

    fn public_key(&self) -> &MLDSAPublicKey {
        &self.pk
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn set_key_id(&mut self, key_id: String) {
        self.key_id = Some(key_id);
    }
}

impl MLDSA87PublicKey {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(MLDSA87PublicKey {
            pk: MLDSAPublicKey::from_bytes(Algorithm::MlDsa87, raw)?,
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
