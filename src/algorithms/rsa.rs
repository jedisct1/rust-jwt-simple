#[cfg(any(feature = "pure-rust", target_arch = "wasm32", target_arch = "wasm64"))]
use superboring as boring;

use boring::bn::BigNum;
use boring::hash::MessageDigest;
use boring::pkey::{PKey, Private, Public};
use boring::rsa::{Padding, Rsa};
use boring::sign::{Signer, Verifier};
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use hmac_sha1_compact::Hash as SHA1;
use hmac_sha256::Hash as SHA256;
use serde::{de::DeserializeOwned, Serialize};

use crate::claims::*;
use crate::common::*;
#[cfg(feature = "cwt")]
use crate::cwt_token::*;
use crate::error::*;
use crate::jwt_header::*;
use crate::token::*;

#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct RSAPublicKey(Rsa<Public>);

impl AsRef<Rsa<Public>> for RSAPublicKey {
    fn as_ref(&self) -> &Rsa<Public> {
        &self.0
    }
}

pub struct RSAPublicKeyComponents {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

impl RSAPublicKey {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let rsa_pk = Rsa::<Public>::public_key_from_der(der)
            .or_else(|_| Rsa::<Public>::public_key_from_der_pkcs1(der))?;
        Ok(RSAPublicKey(rsa_pk))
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let pem = pem.trim();
        let rsa_pk = Rsa::<Public>::public_key_from_pem(pem.as_bytes())
            .or_else(|_| Rsa::<Public>::public_key_from_pem_pkcs1(pem.as_bytes()))?;
        Ok(RSAPublicKey(rsa_pk))
    }

    pub fn from_components(n: &[u8], e: &[u8]) -> Result<Self, Error> {
        let n = BigNum::from_slice(n)?;
        let e = BigNum::from_slice(e)?;
        let rsa_pk = Rsa::<Public>::from_public_components(n, e)?;
        Ok(RSAPublicKey(rsa_pk))
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.0.public_key_to_der().map_err(Into::into)
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        let bytes = self.0.public_key_to_pem()?;
        let pem = String::from_utf8(bytes)?;
        Ok(pem)
    }

    pub fn to_components(&self) -> RSAPublicKeyComponents {
        let n = self.0.n().to_vec();
        let e = self.0.e().to_vec();
        RSAPublicKeyComponents { n, e }
    }
}

#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct RSAKeyPair {
    rsa_sk: Rsa<Private>,
    metadata: Option<KeyMetadata>,
}

impl AsRef<Rsa<Private>> for RSAKeyPair {
    fn as_ref(&self) -> &Rsa<Private> {
        &self.rsa_sk
    }
}

impl RSAKeyPair {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let rsa_sk = Rsa::<Private>::private_key_from_der(der)?;
        if !(rsa_sk.check_key()?) {
            bail!(JWTError::InvalidKeyPair);
        }
        Ok(RSAKeyPair {
            rsa_sk,
            metadata: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let pem = pem.trim();
        let rsa_sk = Rsa::<Private>::private_key_from_pem(pem.as_bytes())?;
        if !(rsa_sk.check_key()?) {
            bail!(JWTError::InvalidKeyPair);
        }
        Ok(RSAKeyPair {
            rsa_sk,
            metadata: None,
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.rsa_sk.private_key_to_der().map_err(Into::into)
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        let bytes = self.rsa_sk.private_key_to_pem()?;
        let pem = String::from_utf8(bytes)?;
        Ok(pem)
    }

    pub fn public_key(&self) -> RSAPublicKey {
        let rsa_pk = Rsa::<Public>::from_public_components(
            self.rsa_sk
                .n()
                .to_owned()
                .expect("failed to create public key"),
            self.rsa_sk
                .e()
                .to_owned()
                .expect("failed to create public key"),
        )
        .expect("failed to create public key");
        RSAPublicKey(rsa_pk)
    }

    pub fn generate(modulus_bits: usize) -> Result<Self, Error> {
        match modulus_bits {
            2048 | 3072 | 4096 => {}
            _ => bail!(JWTError::UnsupportedRSAModulus),
        };
        let rsa_sk = Rsa::<Private>::generate(modulus_bits as _)?;
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
    fn hash() -> MessageDigest;
    fn padding_scheme(&self) -> Padding;

    fn sign<CustomClaims: Serialize + DeserializeOwned>(
        &self,
        claims: JWTClaims<CustomClaims>,
    ) -> Result<String, Error> {
        let jwt_header = JWTHeader::new(Self::jwt_alg_name().to_string(), self.key_id().clone())
            .with_metadata(self.metadata());
        Token::build(&jwt_header, claims, |authenticated| {
            let digest = Self::hash();
            let pkey = PKey::from_rsa(self.key_pair().as_ref().clone())?;
            let mut signer = Signer::new(digest, &pkey).unwrap();
            signer.set_rsa_padding(self.padding_scheme())?;
            signer.update(authenticated.as_bytes())?;
            let signature = signer.sign_to_vec()?;
            Ok(signature)
        })
    }
}

pub trait RSAPublicKeyLike {
    fn jwt_alg_name() -> &'static str;
    fn public_key(&self) -> &RSAPublicKey;
    fn key_id(&self) -> &Option<String>;
    fn set_key_id(&mut self, key_id: String);
    fn hash() -> MessageDigest;
    fn padding_scheme(&self) -> Padding;

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
                let digest = Self::hash();
                let pkey = PKey::from_rsa(self.public_key().as_ref().clone())?;
                let mut verifier = Verifier::new(digest, &pkey)?;
                verifier.set_rsa_padding(self.padding_scheme())?;
                verifier.update(authenticated.as_bytes())?;
                if !(verifier
                    .verify(signature)
                    .map_err(|_| JWTError::InvalidSignature)?)
                {
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
                let digest = Self::hash();
                let pkey = PKey::from_rsa(self.public_key().as_ref().clone())?;
                let mut verifier = Verifier::new(digest, &pkey)?;
                verifier.update(authenticated.as_bytes())?;
                if verifier
                    .verify(&signature)
                    .map_err(|_| JWTError::InvalidSignature)?
                    == false
                {
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

    fn hash() -> MessageDigest {
        MessageDigest::sha256()
    }

    fn padding_scheme(&self) -> Padding {
        Padding::PKCS1
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

    fn hash() -> MessageDigest {
        MessageDigest::sha256()
    }

    fn padding_scheme(&self) -> Padding {
        Padding::PKCS1
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

    fn hash() -> MessageDigest {
        MessageDigest::sha512()
    }

    fn padding_scheme(&self) -> Padding {
        Padding::PKCS1
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

    fn hash() -> MessageDigest {
        MessageDigest::sha512()
    }

    fn padding_scheme(&self) -> Padding {
        Padding::PKCS1
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

    fn hash() -> MessageDigest {
        MessageDigest::sha384()
    }

    fn padding_scheme(&self) -> Padding {
        Padding::PKCS1
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

    fn hash() -> MessageDigest {
        MessageDigest::sha384()
    }

    fn padding_scheme(&self) -> Padding {
        Padding::PKCS1
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

    fn hash() -> MessageDigest {
        MessageDigest::sha256()
    }

    fn padding_scheme(&self) -> Padding {
        Padding::PKCS1_PSS
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

    fn hash() -> MessageDigest {
        MessageDigest::sha256()
    }

    fn padding_scheme(&self) -> Padding {
        Padding::PKCS1_PSS
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

    fn hash() -> MessageDigest {
        MessageDigest::sha512()
    }

    fn padding_scheme(&self) -> Padding {
        Padding::PKCS1_PSS
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

    fn hash() -> MessageDigest {
        MessageDigest::sha512()
    }

    fn padding_scheme(&self) -> Padding {
        Padding::PKCS1_PSS
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

    fn hash() -> MessageDigest {
        MessageDigest::sha384()
    }

    fn padding_scheme(&self) -> Padding {
        Padding::PKCS1_PSS
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

    fn hash() -> MessageDigest {
        MessageDigest::sha384()
    }

    fn padding_scheme(&self) -> Padding {
        Padding::PKCS1_PSS
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
