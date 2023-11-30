use std::mem;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use hmac_sha1_compact::Hash as SHA1;
use hmac_sha256::Hash as SHA256;
use hmac_sha512::sha384::Hash as SHA384;
use hmac_sha512::Hash as SHA512;
use rsa::pkcs1::{DecodeRsaPrivateKey as _, DecodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _, EncodePrivateKey as _};
use rsa::{BigUint, PublicKey as _, PublicKeyParts as _};
use serde::{de::DeserializeOwned, Serialize};
#[allow(unused_imports)]
use spki::{DecodePublicKey as _, EncodePublicKey as _};

use crate::claims::*;
use crate::common::*;
#[cfg(feature = "cwt")]
use crate::cwt_token::*;
use crate::error::*;
use crate::jwt_header::*;
use crate::token::*;

#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct RSAPublicKey(rsa::RsaPublicKey);

impl AsRef<rsa::RsaPublicKey> for RSAPublicKey {
    fn as_ref(&self) -> &rsa::RsaPublicKey {
        &self.0
    }
}

pub struct RSAPublicKeyComponents {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

impl RSAPublicKey {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let rsa_pk = rsa::RsaPublicKey::from_public_key_der(der)
            .or_else(|_| rsa::RsaPublicKey::from_pkcs1_der(der))?;
        Ok(RSAPublicKey(rsa_pk))
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let pem = pem.trim();
        let rsa_pk = rsa::RsaPublicKey::from_public_key_pem(pem)
            .or_else(|_| rsa::RsaPublicKey::from_pkcs1_pem(pem))?;
        Ok(RSAPublicKey(rsa_pk))
    }

    pub fn from_components(n: &[u8], e: &[u8]) -> Result<Self, Error> {
        let n = BigUint::from_bytes_be(n);
        let e = BigUint::from_bytes_be(e);
        let rsa_pk = rsa::RsaPublicKey::new(n, e)?;
        Ok(RSAPublicKey(rsa_pk))
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.0
            .to_public_key_der()
            .map_err(Into::into)
            .map(|x| x.as_ref().to_vec())
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.0
            .to_public_key_pem(Default::default())
            .map_err(Into::into)
    }

    pub fn to_components(&self) -> RSAPublicKeyComponents {
        let n = self.0.n().to_bytes_be();
        let e = self.0.e().to_bytes_be();
        RSAPublicKeyComponents { n, e }
    }
}

#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct RSAKeyPair {
    rsa_sk: rsa::RsaPrivateKey,
    metadata: Option<KeyMetadata>,
}

impl AsRef<rsa::RsaPrivateKey> for RSAKeyPair {
    fn as_ref(&self) -> &rsa::RsaPrivateKey {
        &self.rsa_sk
    }
}

impl RSAKeyPair {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let mut rsa_sk = rsa::RsaPrivateKey::from_pkcs8_der(der)
            .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_der(der))?;
        rsa_sk.validate()?;
        rsa_sk.precompute()?;
        Ok(RSAKeyPair {
            rsa_sk,
            metadata: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let pem = pem.trim();
        let mut rsa_sk = rsa::RsaPrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(pem))?;
        rsa_sk.validate()?;
        rsa_sk.precompute()?;
        Ok(RSAKeyPair {
            rsa_sk,
            metadata: None,
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.rsa_sk
            .to_pkcs8_der()
            .map_err(Into::into)
            .map(|x| mem::take(x.to_bytes().as_mut()))
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.rsa_sk
            .to_pkcs8_pem(Default::default())
            .map_err(Into::into)
            .map(|x| x.to_string())
    }

    pub fn public_key(&self) -> RSAPublicKey {
        let rsa_pk = self.rsa_sk.to_public_key();
        RSAPublicKey(rsa_pk)
    }

    pub fn generate(modulus_bits: usize) -> Result<Self, Error> {
        match modulus_bits {
            2048 | 3072 | 4096 => {}
            _ => bail!(JWTError::UnsupportedRSAModulus),
        };
        let mut rng = rand::thread_rng();
        let rsa_sk = rsa::RsaPrivateKey::new(&mut rng, modulus_bits)?;
        Ok(RSAKeyPair {
            rsa_sk,
            metadata: None,
        })
    }
}

pub trait RSAKeyPairLike {
    fn jwt_alg_name() -> &'static str;
    fn key_pair(&self) -> &RSAKeyPair;
    fn key_id(&self) -> &Option<String>;
    fn metadata(&self) -> &Option<KeyMetadata>;
    fn attach_metadata(&mut self, metadata: KeyMetadata) -> Result<(), Error>;
    fn hash(message: &[u8]) -> Vec<u8>;
    fn padding_scheme(&self) -> rsa::PaddingScheme;

    fn sign<CustomClaims: Serialize + DeserializeOwned>(
        &self,
        claims: JWTClaims<CustomClaims>,
    ) -> Result<String, Error> {
        let jwt_header = JWTHeader::new(Self::jwt_alg_name().to_string(), self.key_id().clone())
            .with_metadata(self.metadata());
        Token::build(&jwt_header, claims, |authenticated| {
            let digest = Self::hash(authenticated.as_bytes());
            let mut rng = rand::thread_rng();
            let token =
                self.key_pair()
                    .as_ref()
                    .sign_blinded(&mut rng, self.padding_scheme(), &digest)?;
            Ok(token)
        })
    }
}

pub trait RSAPublicKeyLike {
    fn jwt_alg_name() -> &'static str;
    fn public_key(&self) -> &RSAPublicKey;
    fn key_id(&self) -> &Option<String>;
    fn set_key_id(&mut self, key_id: String);
    fn hash(message: &[u8]) -> Vec<u8>;
    fn padding_scheme(&self) -> rsa::PaddingScheme;
    fn padding_scheme_alt(&self) -> Option<rsa::PaddingScheme>;

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
                let digest = Self::hash(authenticated.as_bytes());
                let mut verification_failed = self
                    .public_key()
                    .as_ref()
                    .verify(self.padding_scheme(), &digest, signature)
                    .is_err();
                if verification_failed {
                    if let Some(padding_scheme_alt) = self.padding_scheme_alt() {
                        verification_failed = self
                            .public_key()
                            .as_ref()
                            .verify(padding_scheme_alt, &digest, signature)
                            .is_err();
                    }
                }
                if verification_failed {
                    bail!(JWTError::InvalidSignature);
                }
                Ok(())
            },
        )
    }

    #[cfg(feature = "cwt")]
    fn verify_cwt_token<CustomClaims: Serialize + DeserializeOwned>(
        &self,
        token: &[u8],
        options: Option<VerificationOptions>,
    ) -> Result<JWTClaims<NoCustomClaims>, Error> {
        CWTToken::verify(
            Self::jwt_alg_name(),
            token,
            options,
            |authenticated, signature| {
                let digest = Self::hash(authenticated.as_bytes());
                let mut verification_failed = self
                    .public_key()
                    .as_ref()
                    .verify(self.padding_scheme(), &digest, signature)
                    .is_err();
                if verification_failed {
                    if let Some(padding_scheme_alt) = self.padding_scheme_alt() {
                        verification_failed = self
                            .public_key()
                            .as_ref()
                            .verify(padding_scheme_alt, &digest, signature)
                            .is_err();
                    }
                }
                if verification_failed {
                    bail!(JWTError::InvalidSignature);
                }
                Ok(())
            },
        )
    }
}

#[derive(Debug, Clone)]
pub struct RS256KeyPair {
    key_pair: RSAKeyPair,
    key_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RS256PublicKey {
    pk: RSAPublicKey,
    key_id: Option<String>,
}

impl RSAKeyPairLike for RS256KeyPair {
    fn jwt_alg_name() -> &'static str {
        "RS256"
    }

    fn key_pair(&self) -> &RSAKeyPair {
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

    fn hash(message: &[u8]) -> Vec<u8> {
        SHA256::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pkcs1v15_sign::<SHA256>()
    }
}

impl RS256KeyPair {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(RS256KeyPair {
            key_pair: RSAKeyPair::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(RS256KeyPair {
            key_pair: RSAKeyPair::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.key_pair.to_der()
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.key_pair.to_pem()
    }

    pub fn public_key(&self) -> RS256PublicKey {
        RS256PublicKey {
            pk: self.key_pair.public_key(),
            key_id: self.key_id.clone(),
        }
    }

    pub fn generate(modulus_bits: usize) -> Result<Self, Error> {
        Ok(RS256KeyPair {
            key_pair: RSAKeyPair::generate(modulus_bits)?,
            key_id: None,
        })
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}

impl RSAPublicKeyLike for RS256PublicKey {
    fn jwt_alg_name() -> &'static str {
        "RS256"
    }

    fn hash(message: &[u8]) -> Vec<u8> {
        SHA256::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pkcs1v15_sign::<SHA256>()
    }

    fn padding_scheme_alt(&self) -> Option<rsa::PaddingScheme> {
        None
    }

    fn public_key(&self) -> &RSAPublicKey {
        &self.pk
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn set_key_id(&mut self, key_id: String) {
        self.key_id = Some(key_id);
    }
}

impl RS256PublicKey {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(RS256PublicKey {
            pk: RSAPublicKey::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(RS256PublicKey {
            pk: RSAPublicKey::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn from_components(n: &[u8], e: &[u8]) -> Result<Self, Error> {
        Ok(RS256PublicKey {
            pk: RSAPublicKey::from_components(n, e)?,
            key_id: None,
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.pk.to_der()
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.pk.to_pem()
    }

    pub fn to_components(&self) -> RSAPublicKeyComponents {
        self.pk.to_components()
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }

    pub fn sha1_thumbprint(&self) -> String {
        Base64UrlSafeNoPadding::encode_to_string(SHA1::hash(&self.pk.to_der().unwrap())).unwrap()
    }

    pub fn sha256_thumbprint(&self) -> String {
        Base64UrlSafeNoPadding::encode_to_string(SHA256::hash(&self.pk.to_der().unwrap())).unwrap()
    }
}

//

#[derive(Debug, Clone)]
pub struct RS512KeyPair {
    key_pair: RSAKeyPair,
    key_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RS512PublicKey {
    pk: RSAPublicKey,
    key_id: Option<String>,
}

impl RSAKeyPairLike for RS512KeyPair {
    fn jwt_alg_name() -> &'static str {
        "RS512"
    }

    fn key_pair(&self) -> &RSAKeyPair {
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

    fn hash(message: &[u8]) -> Vec<u8> {
        SHA512::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pkcs1v15_sign::<SHA512>()
    }
}

impl RS512KeyPair {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(RS512KeyPair {
            key_pair: RSAKeyPair::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(RS512KeyPair {
            key_pair: RSAKeyPair::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.key_pair.to_der()
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.key_pair.to_pem()
    }

    pub fn public_key(&self) -> RS512PublicKey {
        RS512PublicKey {
            pk: self.key_pair.public_key(),
            key_id: self.key_id.clone(),
        }
    }

    pub fn generate(modulus_bits: usize) -> Result<Self, Error> {
        Ok(RS512KeyPair {
            key_pair: RSAKeyPair::generate(modulus_bits)?,
            key_id: None,
        })
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}

impl RSAPublicKeyLike for RS512PublicKey {
    fn jwt_alg_name() -> &'static str {
        "RS512"
    }

    fn hash(message: &[u8]) -> Vec<u8> {
        SHA512::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pkcs1v15_sign::<SHA512>()
    }

    fn padding_scheme_alt(&self) -> Option<rsa::PaddingScheme> {
        None
    }

    fn public_key(&self) -> &RSAPublicKey {
        &self.pk
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn set_key_id(&mut self, key_id: String) {
        self.key_id = Some(key_id);
    }
}

impl RS512PublicKey {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(RS512PublicKey {
            pk: RSAPublicKey::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(RS512PublicKey {
            pk: RSAPublicKey::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn from_components(n: &[u8], e: &[u8]) -> Result<Self, Error> {
        Ok(RS512PublicKey {
            pk: RSAPublicKey::from_components(n, e)?,
            key_id: None,
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.pk.to_der()
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.pk.to_pem()
    }

    pub fn to_components(&self) -> RSAPublicKeyComponents {
        self.pk.to_components()
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }

    pub fn sha1_thumbprint(&self) -> String {
        Base64UrlSafeNoPadding::encode_to_string(SHA1::hash(&self.pk.to_der().unwrap())).unwrap()
    }

    pub fn sha256_thumbprint(&self) -> String {
        Base64UrlSafeNoPadding::encode_to_string(SHA256::hash(&self.pk.to_der().unwrap())).unwrap()
    }
}

//

#[derive(Debug, Clone)]
pub struct RS384KeyPair {
    key_pair: RSAKeyPair,
    key_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RS384PublicKey {
    pk: RSAPublicKey,
    key_id: Option<String>,
}

impl RSAKeyPairLike for RS384KeyPair {
    fn jwt_alg_name() -> &'static str {
        "RS384"
    }

    fn key_pair(&self) -> &RSAKeyPair {
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

    fn hash(message: &[u8]) -> Vec<u8> {
        SHA384::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pkcs1v15_sign::<SHA384>()
    }
}

impl RS384KeyPair {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(RS384KeyPair {
            key_pair: RSAKeyPair::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(RS384KeyPair {
            key_pair: RSAKeyPair::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.key_pair.to_der()
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.key_pair.to_pem()
    }

    pub fn public_key(&self) -> RS384PublicKey {
        RS384PublicKey {
            pk: self.key_pair.public_key(),
            key_id: self.key_id.clone(),
        }
    }

    pub fn generate(modulus_bits: usize) -> Result<Self, Error> {
        Ok(RS384KeyPair {
            key_pair: RSAKeyPair::generate(modulus_bits)?,
            key_id: None,
        })
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}

impl RSAPublicKeyLike for RS384PublicKey {
    fn jwt_alg_name() -> &'static str {
        "RS384"
    }

    fn hash(message: &[u8]) -> Vec<u8> {
        SHA384::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pkcs1v15_sign::<SHA384>()
    }

    fn padding_scheme_alt(&self) -> Option<rsa::PaddingScheme> {
        None
    }

    fn public_key(&self) -> &RSAPublicKey {
        &self.pk
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn set_key_id(&mut self, key_id: String) {
        self.key_id = Some(key_id);
    }
}

impl RS384PublicKey {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(RS384PublicKey {
            pk: RSAPublicKey::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(RS384PublicKey {
            pk: RSAPublicKey::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn from_components(n: &[u8], e: &[u8]) -> Result<Self, Error> {
        Ok(RS384PublicKey {
            pk: RSAPublicKey::from_components(n, e)?,
            key_id: None,
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.pk.to_der()
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.pk.to_pem()
    }

    pub fn to_components(&self) -> RSAPublicKeyComponents {
        self.pk.to_components()
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }

    pub fn sha1_thumbprint(&self) -> String {
        Base64UrlSafeNoPadding::encode_to_string(SHA1::hash(&self.pk.to_der().unwrap())).unwrap()
    }

    pub fn sha256_thumbprint(&self) -> String {
        Base64UrlSafeNoPadding::encode_to_string(SHA256::hash(&self.pk.to_der().unwrap())).unwrap()
    }
}

//

#[derive(Debug, Clone)]
pub struct PS256KeyPair {
    key_pair: RSAKeyPair,
    key_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PS256PublicKey {
    pk: RSAPublicKey,
    key_id: Option<String>,
}

impl RSAKeyPairLike for PS256KeyPair {
    fn jwt_alg_name() -> &'static str {
        "PS256"
    }

    fn key_pair(&self) -> &RSAKeyPair {
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

    fn hash(message: &[u8]) -> Vec<u8> {
        SHA256::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pss_with_salt::<SHA256>(256 / 8)
    }
}

impl PS256KeyPair {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(PS256KeyPair {
            key_pair: RSAKeyPair::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(PS256KeyPair {
            key_pair: RSAKeyPair::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.key_pair.to_der()
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.key_pair.to_pem()
    }

    pub fn public_key(&self) -> PS256PublicKey {
        PS256PublicKey {
            pk: self.key_pair.public_key(),
            key_id: self.key_id.clone(),
        }
    }

    pub fn generate(modulus_bits: usize) -> Result<Self, Error> {
        Ok(PS256KeyPair {
            key_pair: RSAKeyPair::generate(modulus_bits)?,
            key_id: None,
        })
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}

impl RSAPublicKeyLike for PS256PublicKey {
    fn jwt_alg_name() -> &'static str {
        "PS256"
    }

    fn hash(message: &[u8]) -> Vec<u8> {
        SHA256::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pss_with_salt::<SHA256>(256 / 8)
    }

    fn padding_scheme_alt(&self) -> Option<rsa::PaddingScheme> {
        Some(rsa::PaddingScheme::new_pss::<SHA256>())
    }

    fn public_key(&self) -> &RSAPublicKey {
        &self.pk
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn set_key_id(&mut self, key_id: String) {
        self.key_id = Some(key_id);
    }
}

impl PS256PublicKey {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(PS256PublicKey {
            pk: RSAPublicKey::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(PS256PublicKey {
            pk: RSAPublicKey::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn from_components(n: &[u8], e: &[u8]) -> Result<Self, Error> {
        Ok(PS256PublicKey {
            pk: RSAPublicKey::from_components(n, e)?,
            key_id: None,
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.pk.to_der()
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.pk.to_pem()
    }

    pub fn to_components(&self) -> RSAPublicKeyComponents {
        self.pk.to_components()
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}

//

#[derive(Debug, Clone)]
pub struct PS512KeyPair {
    key_pair: RSAKeyPair,
    key_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PS512PublicKey {
    pk: RSAPublicKey,
    key_id: Option<String>,
}

impl RSAKeyPairLike for PS512KeyPair {
    fn jwt_alg_name() -> &'static str {
        "PS512"
    }

    fn key_pair(&self) -> &RSAKeyPair {
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

    fn hash(message: &[u8]) -> Vec<u8> {
        SHA512::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pss_with_salt::<SHA512>(512 / 8)
    }
}

impl PS512KeyPair {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(PS512KeyPair {
            key_pair: RSAKeyPair::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(PS512KeyPair {
            key_pair: RSAKeyPair::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.key_pair.to_der()
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.key_pair.to_pem()
    }

    pub fn public_key(&self) -> PS512PublicKey {
        PS512PublicKey {
            pk: self.key_pair.public_key(),
            key_id: self.key_id.clone(),
        }
    }

    pub fn generate(modulus_bits: usize) -> Result<Self, Error> {
        Ok(PS512KeyPair {
            key_pair: RSAKeyPair::generate(modulus_bits)?,
            key_id: None,
        })
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}

impl RSAPublicKeyLike for PS512PublicKey {
    fn jwt_alg_name() -> &'static str {
        "PS512"
    }

    fn hash(message: &[u8]) -> Vec<u8> {
        SHA512::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pss_with_salt::<SHA512>(512 / 8)
    }

    fn padding_scheme_alt(&self) -> Option<rsa::PaddingScheme> {
        Some(rsa::PaddingScheme::new_pss::<SHA512>())
    }

    fn public_key(&self) -> &RSAPublicKey {
        &self.pk
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn set_key_id(&mut self, key_id: String) {
        self.key_id = Some(key_id);
    }
}

impl PS512PublicKey {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(PS512PublicKey {
            pk: RSAPublicKey::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(PS512PublicKey {
            pk: RSAPublicKey::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn from_components(n: &[u8], e: &[u8]) -> Result<Self, Error> {
        Ok(PS512PublicKey {
            pk: RSAPublicKey::from_components(n, e)?,
            key_id: None,
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.pk.to_der()
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.pk.to_pem()
    }

    pub fn to_components(&self) -> RSAPublicKeyComponents {
        self.pk.to_components()
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }

    pub fn sha1_thumbprint(&self) -> String {
        Base64UrlSafeNoPadding::encode_to_string(SHA1::hash(&self.pk.to_der().unwrap())).unwrap()
    }

    pub fn sha256_thumbprint(&self) -> String {
        Base64UrlSafeNoPadding::encode_to_string(SHA256::hash(&self.pk.to_der().unwrap())).unwrap()
    }
}

//

#[derive(Debug, Clone)]
pub struct PS384KeyPair {
    key_pair: RSAKeyPair,
    key_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PS384PublicKey {
    pk: RSAPublicKey,
    key_id: Option<String>,
}

impl RSAKeyPairLike for PS384KeyPair {
    fn jwt_alg_name() -> &'static str {
        "PS384"
    }

    fn key_pair(&self) -> &RSAKeyPair {
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

    fn hash(message: &[u8]) -> Vec<u8> {
        SHA384::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pss_with_salt::<SHA384>(384 / 8)
    }
}

impl PS384KeyPair {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(PS384KeyPair {
            key_pair: RSAKeyPair::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(PS384KeyPair {
            key_pair: RSAKeyPair::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.key_pair.to_der()
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.key_pair.to_pem()
    }

    pub fn public_key(&self) -> PS384PublicKey {
        PS384PublicKey {
            pk: self.key_pair.public_key(),
            key_id: self.key_id.clone(),
        }
    }

    pub fn generate(modulus_bits: usize) -> Result<Self, Error> {
        Ok(PS384KeyPair {
            key_pair: RSAKeyPair::generate(modulus_bits)?,
            key_id: None,
        })
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }
}

impl RSAPublicKeyLike for PS384PublicKey {
    fn jwt_alg_name() -> &'static str {
        "PS384"
    }

    fn hash(message: &[u8]) -> Vec<u8> {
        SHA384::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pss_with_salt::<SHA384>(384 / 8)
    }

    fn padding_scheme_alt(&self) -> Option<rsa::PaddingScheme> {
        Some(rsa::PaddingScheme::new_pss::<SHA384>())
    }

    fn public_key(&self) -> &RSAPublicKey {
        &self.pk
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn set_key_id(&mut self, key_id: String) {
        self.key_id = Some(key_id);
    }
}

impl PS384PublicKey {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(PS384PublicKey {
            pk: RSAPublicKey::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(PS384PublicKey {
            pk: RSAPublicKey::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn from_components(n: &[u8], e: &[u8]) -> Result<Self, Error> {
        Ok(PS384PublicKey {
            pk: RSAPublicKey::from_components(n, e)?,
            key_id: None,
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.pk.to_der()
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.pk.to_pem()
    }

    pub fn to_components(&self) -> RSAPublicKeyComponents {
        self.pk.to_components()
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }

    pub fn sha1_thumbprint(&self) -> String {
        Base64UrlSafeNoPadding::encode_to_string(SHA1::hash(&self.pk.to_der().unwrap())).unwrap()
    }

    pub fn sha256_thumbprint(&self) -> String {
        Base64UrlSafeNoPadding::encode_to_string(SHA256::hash(&self.pk.to_der().unwrap())).unwrap()
    }
}
