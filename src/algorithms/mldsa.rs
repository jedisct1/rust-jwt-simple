use std::convert::TryInto;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use serde::{de::DeserializeOwned, Serialize};
use superboring::mldsa::{Algorithm, MlDsaPrivateKey, MlDsaPublicKey};

use crate::algorithms::jwk::{
    decode_fixed, decode_secret, encode, encode_secret, is_encoding_of, thumbprint, Jwk,
    JwkDescriptor, JwkMembers, KeyRole, KeyType,
};
use crate::claims::*;
use crate::common::*;
#[cfg(feature = "cwt")]
use crate::cwt_token::*;
use crate::error::*;
use crate::jwt_header::*;
use crate::token::*;

fn mldsa_jwk_descriptor(alg: &'static str, role: KeyRole) -> JwkDescriptor {
    JwkDescriptor::new(KeyType::Akp, None, alg, role)
}

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

    pub(crate) fn from_jwk(
        jwk: &str,
        alg: &'static str,
        algorithm: Algorithm,
    ) -> Result<(Self, Option<String>), Error> {
        let jwk = Jwk::parse(jwk, &mldsa_jwk_descriptor(alg, KeyRole::SignaturePublic))?;
        let mut raw = vec![0u8; algorithm.public_key_bytes()];
        ensure!(
            decode_fixed(jwk.public(), &mut raw),
            JWTError::InvalidPublicKey
        );
        Ok((
            Self::from_bytes(algorithm, &raw)?,
            jwk.kid().map(Into::into),
        ))
    }

    pub(crate) fn to_jwk(&self, alg: &'static str, key_id: Option<&str>) -> String {
        let public = encode(&self.to_bytes());
        let members = JwkMembers {
            public: Some(&public),
            ..Default::default()
        };
        mldsa_jwk_descriptor(alg, KeyRole::SignaturePublic).export(members, key_id)
    }

    pub(crate) fn jwk_thumbprint(&self, alg: &str) -> String {
        thumbprint(&[
            ("alg", alg),
            ("kty", "AKP"),
            ("pub", &encode(&self.to_bytes())),
        ])
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

    pub(crate) fn from_jwk(
        jwk: &str,
        alg: &'static str,
        algorithm: Algorithm,
    ) -> Result<(Self, Option<String>), Error> {
        let jwk = Jwk::parse(jwk, &mldsa_jwk_descriptor(alg, KeyRole::SignaturePrivate))?;
        let seed = decode_secret(jwk.private(), 32).ok_or(JWTError::InvalidKeyPair)?;
        let key_pair = Self::from_bytes(algorithm, &seed)?;
        ensure!(
            is_encoding_of(jwk.public(), &key_pair.public_key().to_bytes()),
            JWTError::InvalidKeyPair
        );
        Ok((key_pair, jwk.kid().map(Into::into)))
    }

    pub(crate) fn to_jwk(&self, alg: &'static str, key_id: Option<&str>) -> String {
        let public = encode(&self.public_key().to_bytes());
        let private = encode_secret(self.mldsa_sk.seed_bytes());
        let members = JwkMembers {
            public: Some(&public),
            private: Some(&private),
            ..Default::default()
        };
        mldsa_jwk_descriptor(alg, KeyRole::SignaturePrivate).export(members, key_id)
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

    /// Import a key pair from a private AKP JWK, with `alg: ML-DSA-44`.
    ///
    /// `priv` must contain the 32-byte seed used by `from_bytes()`.
    /// See [strict JWK validation](crate#strict-jwk-validation) for the other rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let (key_pair, key_id) =
            MLDSAKeyPair::from_jwk(jwk, Self::jwt_alg_name(), Algorithm::MlDsa44)?;
        Ok(MLDSA44KeyPair { key_pair, key_id })
    }

    /// Export the key pair as a JWK, private key included.
    ///
    /// Use `public_key().to_jwk()` to share the public key.
    pub fn to_jwk(&self) -> String {
        self.key_pair
            .to_jwk(Self::jwt_alg_name(), self.key_id.as_deref())
    }

    /// The JWK thumbprint of the public key, which includes its algorithm.
    pub fn jwk_thumbprint(&self) -> String {
        self.key_pair
            .public_key()
            .jwk_thumbprint(Self::jwt_alg_name())
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

    /// Import a public key from an AKP JWK, with `alg: ML-DSA-44`.
    ///
    /// See [strict JWK validation](crate#strict-jwk-validation) for the rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let (pk, key_id) = MLDSAPublicKey::from_jwk(jwk, Self::jwt_alg_name(), Algorithm::MlDsa44)?;
        Ok(MLDSA44PublicKey { pk, key_id })
    }

    /// Export the public key as an AKP JWK, with `alg: ML-DSA-44` and `use: sig`.
    pub fn to_jwk(&self) -> String {
        self.pk.to_jwk(Self::jwt_alg_name(), self.key_id.as_deref())
    }

    /// The JWK thumbprint of the key, which includes its algorithm.
    pub fn jwk_thumbprint(&self) -> String {
        self.pk.jwk_thumbprint(Self::jwt_alg_name())
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

    /// Import a key pair from a private AKP JWK, with `alg: ML-DSA-65`.
    ///
    /// `priv` must contain the 32-byte seed used by `from_bytes()`.
    /// See [strict JWK validation](crate#strict-jwk-validation) for the other rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let (key_pair, key_id) =
            MLDSAKeyPair::from_jwk(jwk, Self::jwt_alg_name(), Algorithm::MlDsa65)?;
        Ok(MLDSA65KeyPair { key_pair, key_id })
    }

    /// Export the key pair as a JWK, private key included.
    ///
    /// Use `public_key().to_jwk()` to share the public key.
    pub fn to_jwk(&self) -> String {
        self.key_pair
            .to_jwk(Self::jwt_alg_name(), self.key_id.as_deref())
    }

    /// The JWK thumbprint of the public key, which includes its algorithm.
    pub fn jwk_thumbprint(&self) -> String {
        self.key_pair
            .public_key()
            .jwk_thumbprint(Self::jwt_alg_name())
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

    /// Import a public key from an AKP JWK, with `alg: ML-DSA-65`.
    ///
    /// See [strict JWK validation](crate#strict-jwk-validation) for the rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let (pk, key_id) = MLDSAPublicKey::from_jwk(jwk, Self::jwt_alg_name(), Algorithm::MlDsa65)?;
        Ok(MLDSA65PublicKey { pk, key_id })
    }

    /// Export the public key as an AKP JWK, with `alg: ML-DSA-65` and `use: sig`.
    pub fn to_jwk(&self) -> String {
        self.pk.to_jwk(Self::jwt_alg_name(), self.key_id.as_deref())
    }

    /// The JWK thumbprint of the key, which includes its algorithm.
    pub fn jwk_thumbprint(&self) -> String {
        self.pk.jwk_thumbprint(Self::jwt_alg_name())
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

    /// Import a key pair from a private AKP JWK, with `alg: ML-DSA-87`.
    ///
    /// `priv` must contain the 32-byte seed used by `from_bytes()`.
    /// See [strict JWK validation](crate#strict-jwk-validation) for the other rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let (key_pair, key_id) =
            MLDSAKeyPair::from_jwk(jwk, Self::jwt_alg_name(), Algorithm::MlDsa87)?;
        Ok(MLDSA87KeyPair { key_pair, key_id })
    }

    /// Export the key pair as a JWK, private key included.
    ///
    /// Use `public_key().to_jwk()` to share the public key.
    pub fn to_jwk(&self) -> String {
        self.key_pair
            .to_jwk(Self::jwt_alg_name(), self.key_id.as_deref())
    }

    /// The JWK thumbprint of the public key, which includes its algorithm.
    pub fn jwk_thumbprint(&self) -> String {
        self.key_pair
            .public_key()
            .jwk_thumbprint(Self::jwt_alg_name())
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

    /// Import a public key from an AKP JWK, with `alg: ML-DSA-87`.
    ///
    /// See [strict JWK validation](crate#strict-jwk-validation) for the rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let (pk, key_id) = MLDSAPublicKey::from_jwk(jwk, Self::jwt_alg_name(), Algorithm::MlDsa87)?;
        Ok(MLDSA87PublicKey { pk, key_id })
    }

    /// Export the public key as an AKP JWK, with `alg: ML-DSA-87` and `use: sig`.
    pub fn to_jwk(&self) -> String {
        self.pk.to_jwk(Self::jwt_alg_name(), self.key_id.as_deref())
    }

    /// The JWK thumbprint of the key, which includes its algorithm.
    pub fn jwk_thumbprint(&self) -> String {
        self.pk.jwk_thumbprint(Self::jwt_alg_name())
    }
}

#[cfg(test)]
mod jwk_tests {
    use super::*;
    use crate::algorithms::jwk_test_vectors;
    use crate::algorithms::test_util::{b64, error_of, json as value, unb64, with, without};

    macro_rules! rfc9964_vector {
        ($vector:expr, $key_pair:ident, $public_key:ident) => {{
            let vector = $vector;
            let private_jwk = vector["jwk"].to_string();
            let kid = vector["jwk"]["kid"].as_str().unwrap();
            let key_pair = $key_pair::from_jwk(&private_jwk).unwrap();
            assert_eq!(key_pair.key_id.as_deref(), Some(kid));
            assert_eq!(key_pair.to_bytes(), [0u8; 32]);
            assert_eq!(key_pair.jwk_thumbprint(), kid);
            assert_eq!(value(&key_pair.to_jwk())["pub"], vector["jwk"]["pub"]);

            let public_key = $public_key::from_jwk(&without(&private_jwk, &["priv"])).unwrap();
            assert_eq!(public_key.jwk_thumbprint(), kid);
            assert_eq!(key_pair.public_key().to_bytes(), public_key.to_bytes());

            // The example has no claims, so check its signature directly.
            let jws = vector["jws"].as_str().unwrap();
            let (signed, signature) = jws.rsplit_once('.').unwrap();
            public_key
                .public_key()
                .as_ref()
                .verify(signed.as_bytes(), &unb64(signature))
                .unwrap();
            private_jwk
        }};
    }

    #[test]
    fn rfc9964_vectors() {
        let vectors = value(jwk_test_vectors::RFC9964_JOSE);
        let jwk44 = rfc9964_vector!(&vectors[0], MLDSA44KeyPair, MLDSA44PublicKey);
        let jwk65 = rfc9964_vector!(&vectors[1], MLDSA65KeyPair, MLDSA65PublicKey);
        let jwk87 = rfc9964_vector!(&vectors[2], MLDSA87KeyPair, MLDSA87PublicKey);

        // Changing `alg` must not let a key load as a different type.
        assert!(MLDSA65KeyPair::from_jwk(&jwk44).is_err());
        assert!(MLDSA44KeyPair::from_jwk(&jwk65).is_err());
        assert!(MLDSA44PublicKey::from_jwk(&without(&jwk87, &["priv"])).is_err());
        let relabeled = with(&jwk44, "alg", "ML-DSA-65".into());
        assert!(MLDSA65KeyPair::from_jwk(&relabeled).is_err());
        assert!(MLDSA44KeyPair::from_jwk(&relabeled).is_err());
    }

    #[test]
    fn akp_keys_require_their_algorithm() {
        let key_pair = MLDSA44KeyPair::generate();
        let private_jwk = key_pair.to_jwk();
        let public_jwk = key_pair.public_key().to_jwk();
        for jwk in [
            without(&public_jwk, &["alg"]),
            with(&public_jwk, "alg", "ML-DSA-44 ".into()),
            with(&public_jwk, "alg", serde_json::Value::Null),
            with(&public_jwk, "crv", "Ed25519".into()),
            with(&public_jwk, "x", "AAAA".into()),
            with(&public_jwk, "priv", serde_json::Value::Null),
            with(&public_jwk, "use", "enc".into()),
            with(&public_jwk, "kty", "OKP".into()),
        ] {
            assert!(
                matches!(
                    error_of(MLDSA44PublicKey::from_jwk(&jwk)),
                    JWTError::InvalidPublicKey
                ),
                "{}",
                jwk
            );
        }
        assert!(matches!(
            error_of(MLDSA44KeyPair::from_jwk(&without(&private_jwk, &["alg"]))),
            JWTError::InvalidKeyPair
        ));
    }

    #[test]
    fn private_key_is_the_seed() {
        let key_pair = MLDSA44KeyPair::generate();
        let other = MLDSA44KeyPair::generate();
        let private_jwk = key_pair.to_jwk();
        let seed = key_pair.to_bytes();
        let with_private = |private: &[u8]| with(&private_jwk, "priv", b64(private).into());
        let other_public = value(&other.to_jwk())["pub"].clone();
        for (case, jwk) in [
            ("short seed", with_private(&seed[..31])),
            ("long seed", with_private(&[&seed[..], &[0]].concat())),
            // ML-DSA-44 expanded keys are 2560 bytes.
            ("expanded key", with_private(&[0x5au8; 2560])),
            ("empty", with_private(&[])),
            ("other seed", with_private(&other.to_bytes())),
            ("other public key", with(&private_jwk, "pub", other_public)),
            ("no public key", without(&private_jwk, &["pub"])),
        ] {
            assert!(
                matches!(
                    error_of(MLDSA44KeyPair::from_jwk(&jwk)),
                    JWTError::InvalidKeyPair
                ),
                "{}",
                case
            );
        }
    }

    #[test]
    fn round_trips() {
        let key_pair = MLDSA65KeyPair::generate().with_key_id("pq");
        let private_jwk = key_pair.to_jwk();
        let public_jwk = key_pair.public_key().to_jwk();
        let exported = value(&public_jwk);
        assert_eq!(exported["kty"], "AKP");
        assert_eq!(exported["alg"], "ML-DSA-65");
        assert_eq!(exported["use"], "sig");
        assert_eq!(exported["kid"], "pq");
        assert!(exported.get("priv").is_none());

        let restored = MLDSA65KeyPair::from_jwk(&private_jwk).unwrap();
        let public_key = MLDSA65PublicKey::from_jwk(&public_jwk).unwrap();
        assert_eq!(restored.to_jwk(), private_jwk);
        assert_eq!(public_key.to_jwk(), public_jwk);
        assert_eq!(restored.jwk_thumbprint(), public_key.jwk_thumbprint());
        let token = restored
            .sign(Claims::create(coarsetime::Duration::from_hours(1)))
            .unwrap();
        public_key
            .verify_token::<NoCustomClaims>(&token, None)
            .unwrap();

        let mut public_key = public_key;
        let key_id = public_key.create_key_id().to_string();
        let raw_hash = hmac_sha256::Hash::hash(&public_key.to_bytes());
        assert_eq!(key_id, b64(&raw_hash));
    }

    #[test]
    fn webcrypto_exports() {
        for export in jwk_test_vectors::ALL {
            let export = value(export);
            let keys = &export["keys"];
            if let Some(entry) = keys.get("ML-DSA-44") {
                let key_pair = MLDSA44KeyPair::from_jwk(&entry["private"].to_string()).unwrap();
                let public_key = MLDSA44PublicKey::from_jwk(&entry["public"].to_string()).unwrap();
                assert_eq!(key_pair.jwk_thumbprint(), public_key.jwk_thumbprint());
                public_key
                    .verify_token::<NoCustomClaims>(entry["jwt"].as_str().unwrap(), None)
                    .unwrap();
            }
            if let Some(entry) = keys.get("ML-DSA-65") {
                let key_pair = MLDSA65KeyPair::from_jwk(&entry["private"].to_string()).unwrap();
                let public_key = MLDSA65PublicKey::from_jwk(&entry["public"].to_string()).unwrap();
                assert_eq!(key_pair.jwk_thumbprint(), public_key.jwk_thumbprint());
            }
            if let Some(entry) = keys.get("ML-DSA-87") {
                let key_pair = MLDSA87KeyPair::from_jwk(&entry["private"].to_string()).unwrap();
                let public_key = MLDSA87PublicKey::from_jwk(&entry["public"].to_string()).unwrap();
                assert_eq!(key_pair.jwk_thumbprint(), public_key.jwk_thumbprint());
            }
        }
    }
}
