use hmac_sha512::sha384 as hmac_sha384;
use rsa::{BigUint, PublicKey as _};
use rsa_export::{Encode as _, PemEncode as _};
use serde::{de::DeserializeOwned, Serialize};
use std::convert::TryFrom;

use crate::claims::*;
use crate::common::*;
use crate::error::*;
use crate::jwt_header::*;
use crate::token::*;

#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct RSAPublicKey(rsa::RSAPublicKey);

impl AsRef<rsa::RSAPublicKey> for RSAPublicKey {
    fn as_ref(&self) -> &rsa::RSAPublicKey {
        &self.0
    }
}

impl RSAPublicKey {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let rsa_pk = rsa::RSAPublicKey::from_pkcs8(der)?;
        Ok(RSAPublicKey(rsa_pk))
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let parsed_pem = rsa::pem::parse(pem)?;
        let rsa_pk = rsa::RSAPublicKey::try_from(parsed_pem)?;
        Ok(RSAPublicKey(rsa_pk))
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.0.as_pkcs8().map_err(Into::into)
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.0.as_pkcs8_pem().map_err(Into::into)
    }

    pub fn from_components(n: &[u8], e: &[u8]) -> Result<Self, Error> {
        let n = BigUint::from_bytes_be(n);
        let e = BigUint::from_bytes_be(e);
        let rsa_pk = rsa::RSAPublicKey::new(n, e)?;
        Ok(RSAPublicKey(rsa_pk))
    }
}

#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct RSAKeyPair(rsa::RSAPrivateKey);

impl AsRef<rsa::RSAPrivateKey> for RSAKeyPair {
    fn as_ref(&self) -> &rsa::RSAPrivateKey {
        &self.0
    }
}

impl RSAKeyPair {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let mut rsa_sk = rsa::RSAPrivateKey::from_pkcs8(&der)?;
        rsa_sk.validate()?;
        rsa_sk.precompute()?;
        Ok(RSAKeyPair(rsa_sk))
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let parsed_pem = rsa::pem::parse(pem)?;
        let mut rsa_sk = rsa::RSAPrivateKey::try_from(parsed_pem)?;
        rsa_sk.validate()?;
        rsa_sk.precompute()?;
        Ok(RSAKeyPair(rsa_sk))
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.0.as_pkcs8().map_err(Into::into)
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        self.0.as_pkcs8_pem().map_err(Into::into)
    }

    pub fn public_key(&self) -> RSAPublicKey {
        let rsa_pk = self.0.to_public_key();
        RSAPublicKey(rsa_pk)
    }

    pub fn generate(modulus_bits: usize) -> Result<Self, Error> {
        match modulus_bits {
            2048 | 3072 | 4096 => {}
            _ => bail!(JWTError::UnsupportedRSAModulus),
        };
        let mut rng = rand::thread_rng();
        let rsa_sk = rsa::RSAPrivateKey::new(&mut rng, modulus_bits)?;
        Ok(RSAKeyPair(rsa_sk))
    }
}

#[doc(hidden)]
pub trait RSAKeyPairLike {
    fn jwt_alg_name() -> &'static str;
    fn key_pair(&self) -> &RSAKeyPair;
    fn key_id(&self) -> &Option<String>;
    fn hash(message: &[u8]) -> Vec<u8>;
    fn padding_scheme(&self) -> rsa::PaddingScheme;

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

#[doc(hidden)]
pub trait RSAPublicKeyLike {
    fn jwt_alg_name() -> &'static str;
    fn public_key(&self) -> &RSAPublicKey;
    fn key_id(&self) -> &Option<String>;
    fn set_key_id(&mut self, key_id: String);
    fn hash(message: &[u8]) -> Vec<u8>;
    fn padding_scheme(&self) -> rsa::PaddingScheme;

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
                self.public_key()
                    .as_ref()
                    .verify(self.padding_scheme(), &digest, signature)
                    .map_err(|_| JWTError::InvalidSignature)?;
                Ok(())
            },
        )
    }
}

#[derive(Clone)]
pub struct RS256KeyPair {
    key_pair: RSAKeyPair,
    key_id: Option<String>,
}

#[derive(Debug)]
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

    fn hash(message: &[u8]) -> Vec<u8> {
        hmac_sha256::Hash::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_256))
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
        hmac_sha256::Hash::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_256))
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
}

//

#[derive(Debug)]
pub struct RS512KeyPair {
    key_pair: RSAKeyPair,
    key_id: Option<String>,
}

#[derive(Debug)]
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

    fn hash(message: &[u8]) -> Vec<u8> {
        hmac_sha512::Hash::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_512))
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
        hmac_sha512::Hash::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_512))
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
}

//

#[derive(Debug)]
pub struct RS384KeyPair {
    key_pair: RSAKeyPair,
    key_id: Option<String>,
}

#[derive(Debug)]
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

    fn hash(message: &[u8]) -> Vec<u8> {
        hmac_sha384::Hash::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_384))
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
        hmac_sha384::Hash::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_384))
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
}

//

pub struct PS256KeyPair {
    key_pair: RSAKeyPair,
    key_id: Option<String>,
}

#[derive(Debug)]
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

    fn hash(message: &[u8]) -> Vec<u8> {
        hmac_sha256::Hash::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pss::<hmac_sha256::Hash, _>(rand::thread_rng())
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
        hmac_sha256::Hash::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pss::<hmac_sha256::Hash, _>(rand::thread_rng())
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
}

//

pub struct PS512KeyPair {
    key_pair: RSAKeyPair,
    key_id: Option<String>,
}

#[derive(Debug)]
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

    fn hash(message: &[u8]) -> Vec<u8> {
        hmac_sha512::Hash::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pss::<hmac_sha512::Hash, _>(rand::thread_rng())
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
        hmac_sha512::Hash::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pss::<hmac_sha512::Hash, _>(rand::thread_rng())
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
}

//

pub struct PS384KeyPair {
    key_pair: RSAKeyPair,
    key_id: Option<String>,
}

#[derive(Debug)]
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

    fn hash(message: &[u8]) -> Vec<u8> {
        hmac_sha384::Hash::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pss::<hmac_sha384::Hash, _>(rand::thread_rng())
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
        hmac_sha384::Hash::hash(message).to_vec()
    }

    fn padding_scheme(&self) -> rsa::PaddingScheme {
        rsa::PaddingScheme::new_pss::<hmac_sha384::Hash, _>(rand::thread_rng())
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
}
