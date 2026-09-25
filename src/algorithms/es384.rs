use std::convert::{TryFrom, TryInto};

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use p384::ecdsa::{self, signature::DigestVerifier as _, signature::RandomizedDigestSigner as _};
use p384::elliptic_curve::Generate as _;
use p384::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use p384::NonZeroScalar;
use serde::{de::DeserializeOwned, Serialize};

use crate::algorithms::jwk::{
    decode_secret, ec_export, ec_point, ec_point_matches, ec_thumbprint, Jwk, JwkDescriptor,
    KeyRole, KeyType,
};
use crate::claims::*;
use crate::common::*;
#[cfg(feature = "cwt")]
use crate::cwt_token::*;
use crate::error::*;
use crate::jwt_header::*;
use crate::token::*;

const ES384_PUBLIC_JWK: JwkDescriptor = JwkDescriptor::new(
    KeyType::Ec,
    Some("P-384"),
    "ES384",
    KeyRole::SignaturePublic,
);
const ES384_PRIVATE_JWK: JwkDescriptor = ES384_PUBLIC_JWK.with_role(KeyRole::SignaturePrivate);

#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct P384PublicKey(ecdsa::VerifyingKey);

impl AsRef<ecdsa::VerifyingKey> for P384PublicKey {
    fn as_ref(&self) -> &ecdsa::VerifyingKey {
        &self.0
    }
}

impl P384PublicKey {
    pub(crate) fn from_jwk(jwk: &str) -> Result<(Self, Option<String>), Error> {
        let jwk = Jwk::parse(jwk, &ES384_PUBLIC_JWK)?;
        let point = ec_point(&jwk, 48).ok_or(JWTError::InvalidPublicKey)?;
        let pk = Self::from_bytes(&point)?;
        Ok((pk, jwk.kid().map(Into::into)))
    }

    pub(crate) fn to_jwk(&self, key_id: Option<&str>) -> String {
        ec_export(
            &ES384_PUBLIC_JWK,
            &self.to_bytes_uncompressed(),
            None,
            key_id,
        )
    }

    pub(crate) fn jwk_thumbprint(&self) -> String {
        ec_thumbprint("P-384", &self.to_bytes_uncompressed())
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let p384_pk =
            ecdsa::VerifyingKey::from_sec1_bytes(raw).map_err(|_| JWTError::InvalidPublicKey)?;
        Ok(P384PublicKey(p384_pk))
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let p384_pk = ecdsa::VerifyingKey::from_public_key_der(der)
            .map_err(|_| JWTError::InvalidPublicKey)?;
        Ok(P384PublicKey(p384_pk))
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let p384_pk = ecdsa::VerifyingKey::from_public_key_pem(pem)
            .map_err(|_| JWTError::InvalidPublicKey)?;
        Ok(P384PublicKey(p384_pk))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_sec1_point(true).as_bytes().to_vec()
    }

    pub fn to_bytes_uncompressed(&self) -> Vec<u8> {
        self.0.to_sec1_point(false).as_bytes().to_vec()
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let p384_pk = p384::PublicKey::from(self.0);
        Ok(p384_pk
            .to_public_key_der()
            .map_err(|_| JWTError::InvalidPublicKey)?
            .as_ref()
            .to_vec())
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        let p384_pk = p384::PublicKey::from(self.0);
        Ok(p384_pk
            .to_public_key_pem(Default::default())
            .map_err(|_| JWTError::InvalidPublicKey)?)
    }
}

#[doc(hidden)]
pub struct P384KeyPair {
    p384_sk: ecdsa::SigningKey,
    metadata: Option<KeyMetadata>,
}

impl std::fmt::Debug for P384KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EcKey")
    }
}

impl AsRef<ecdsa::SigningKey> for P384KeyPair {
    fn as_ref(&self) -> &ecdsa::SigningKey {
        &self.p384_sk
    }
}

impl P384KeyPair {
    pub(crate) fn from_jwk(jwk: &str) -> Result<(Self, Option<String>), Error> {
        let jwk = Jwk::parse(jwk, &ES384_PRIVATE_JWK)?;
        let d = decode_secret(jwk.d(), 48).ok_or(JWTError::InvalidKeyPair)?;
        let key_pair = Self::from_bytes(&d)?;
        ensure!(
            ec_point_matches(&jwk, &key_pair.public_key().to_bytes_uncompressed()),
            JWTError::InvalidKeyPair
        );
        Ok((key_pair, jwk.kid().map(Into::into)))
    }

    pub(crate) fn to_jwk(&self, key_id: Option<&str>) -> String {
        let point = self.public_key().to_bytes_uncompressed();
        let d = zeroize::Zeroizing::new(self.p384_sk.to_bytes().to_vec());
        ec_export(&ES384_PRIVATE_JWK, &point, Some(&d), key_id)
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let raw: &p384::FieldBytes = raw.try_into().map_err(|_| JWTError::InvalidKeyPair)?;
        let p384_sk = ecdsa::SigningKey::from_bytes(raw).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(P384KeyPair {
            p384_sk,
            metadata: None,
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let p384_sk =
            ecdsa::SigningKey::from_pkcs8_der(der).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(P384KeyPair {
            p384_sk,
            metadata: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let p384_sk =
            ecdsa::SigningKey::from_pkcs8_pem(pem).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(P384KeyPair {
            p384_sk,
            metadata: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.p384_sk.to_bytes().to_vec()
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let scalar = NonZeroScalar::from_repr(self.p384_sk.to_bytes());
        if bool::from(scalar.is_none()) {
            return Err(JWTError::InvalidKeyPair.into());
        }
        let p384_sk =
            p384::SecretKey::from(NonZeroScalar::from_repr(scalar.unwrap().into()).unwrap());
        Ok(p384_sk
            .to_pkcs8_der()
            .map_err(|_| JWTError::InvalidKeyPair)?
            .as_bytes()
            .to_vec())
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        let scalar = NonZeroScalar::from_repr(self.p384_sk.to_bytes());
        if bool::from(scalar.is_none()) {
            return Err(JWTError::InvalidKeyPair.into());
        }
        let p384_sk =
            p384::SecretKey::from(NonZeroScalar::from_repr(scalar.unwrap().into()).unwrap());
        Ok(p384_sk
            .to_pkcs8_pem(Default::default())
            .map_err(|_| JWTError::InvalidKeyPair)?
            .to_string())
    }

    pub fn public_key(&self) -> P384PublicKey {
        let p384_sk = self.p384_sk.verifying_key();
        P384PublicKey(*p384_sk)
    }

    pub fn generate() -> Self {
        let mut rng = rand::rng();
        let p384_sk = ecdsa::SigningKey::generate_from_rng(&mut rng);
        P384KeyPair {
            p384_sk,
            metadata: None,
        }
    }
}

pub trait ECDSAP384KeyPairLike {
    fn jwt_alg_name() -> &'static str;
    fn key_pair(&self) -> &P384KeyPair;
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
            let mut rng = rand::rng();
            let signature: ecdsa::Signature = self
                .key_pair()
                .as_ref()
                .sign_digest_with_rng(&mut rng, |digest: &mut hmac_sha512::sha384::Hash| {
                    digest.update(authenticated.as_bytes())
                });
            Ok(signature.to_vec())
        })
    }
}

pub trait ECDSAP384PublicKeyLike {
    fn jwt_alg_name() -> &'static str;
    fn public_key(&self) -> &P384PublicKey;
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
                let ecdsa_signature = ecdsa::Signature::try_from(signature)
                    .map_err(|_| JWTError::InvalidSignature)?;
                self.public_key()
                    .as_ref()
                    .verify_digest(
                        |digest: &mut hmac_sha512::sha384::Hash| {
                            digest.update(authenticated.as_bytes());
                            Ok(())
                        },
                        &ecdsa_signature,
                    )
                    .map_err(|_| JWTError::InvalidSignature)?;
                Ok(())
            },
            |_salt: Option<&[u8]>| Ok(()),
        )
    }

    #[cfg(feature = "cwt")]
    fn verify_cwt_token<CustomClaims: DeserializeOwned>(
        &self,
        token: &str,
        options: Option<VerificationOptions>,
    ) -> Result<JWTClaims<NoCustomClaims>, Error> {
        CWTToken::verify(
            Self::jwt_alg_name(),
            token,
            options,
            |authenticated, signature| {
                let ecdsa_signature = ecdsa::Signature::try_from(signature)
                    .map_err(|_| JWTError::InvalidSignature)?;
                self.public_key()
                    .as_ref()
                    .verify_digest(
                        |digest: &mut hmac_sha512::sha384::Hash| {
                            digest.update(authenticated.as_bytes());
                            Ok(())
                        },
                        &ecdsa_signature,
                    )
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

pub struct ES384KeyPair {
    key_pair: P384KeyPair,
    key_id: Option<String>,
}

impl std::fmt::Debug for ES384KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EcKey")
    }
}

#[derive(Debug, Clone)]
pub struct ES384PublicKey {
    pk: P384PublicKey,
    key_id: Option<String>,
}

impl ECDSAP384KeyPairLike for ES384KeyPair {
    fn jwt_alg_name() -> &'static str {
        "ES384"
    }

    fn key_pair(&self) -> &P384KeyPair {
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

impl ES384KeyPair {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(ES384KeyPair {
            key_pair: P384KeyPair::from_bytes(raw)?,
            key_id: None,
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(ES384KeyPair {
            key_pair: P384KeyPair::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(ES384KeyPair {
            key_pair: P384KeyPair::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key_pair.to_bytes()
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.key_pair.to_der()
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.key_pair.to_pem()
    }

    pub fn public_key(&self) -> ES384PublicKey {
        ES384PublicKey {
            pk: self.key_pair.public_key(),
            key_id: self.key_id.clone(),
        }
    }

    pub fn generate() -> Self {
        ES384KeyPair {
            key_pair: P384KeyPair::generate(),
            key_id: None,
        }
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }

    /// Import a key pair from a private JWK (`kty: EC`, `crv: P-384`).
    ///
    /// See [strict JWK validation](crate#strict-jwk-validation) for the rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let (key_pair, key_id) = P384KeyPair::from_jwk(jwk)?;
        Ok(ES384KeyPair { key_pair, key_id })
    }

    /// Export the key pair as a JWK, private key included.
    ///
    /// Use `public_key().to_jwk()` to share the public key.
    pub fn to_jwk(&self) -> String {
        self.key_pair.to_jwk(self.key_id.as_deref())
    }

    /// The JWK thumbprint of the public key.
    pub fn jwk_thumbprint(&self) -> String {
        self.key_pair.public_key().jwk_thumbprint()
    }
}

impl ECDSAP384PublicKeyLike for ES384PublicKey {
    fn jwt_alg_name() -> &'static str {
        "ES384"
    }

    fn public_key(&self) -> &P384PublicKey {
        &self.pk
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn set_key_id(&mut self, key_id: String) {
        self.key_id = Some(key_id);
    }
}

impl ES384PublicKey {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(ES384PublicKey {
            pk: P384PublicKey::from_bytes(raw)?,
            key_id: None,
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(ES384PublicKey {
            pk: P384PublicKey::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(ES384PublicKey {
            pk: P384PublicKey::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.pk.to_bytes()
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.pk.to_der()
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.pk.to_pem()
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }

    /// Import a public key from a JWK (`kty: EC`, `crv: P-384`).
    ///
    /// See [strict JWK validation](crate#strict-jwk-validation) for the rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let (pk, key_id) = P384PublicKey::from_jwk(jwk)?;
        Ok(ES384PublicKey { pk, key_id })
    }

    /// Export the public key as a JWK, with `alg: ES384` and `use: sig`.
    pub fn to_jwk(&self) -> String {
        self.pk.to_jwk(self.key_id.as_deref())
    }

    /// The JWK thumbprint of the key.
    pub fn jwk_thumbprint(&self) -> String {
        self.pk.jwk_thumbprint()
    }
}
