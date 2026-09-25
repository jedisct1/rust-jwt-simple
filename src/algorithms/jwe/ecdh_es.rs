//! ECDH-ES key agreement algorithms for JWE.
//!
//! Implements ECDH-ES+A256KW and ECDH-ES+A128KW (Elliptic Curve Diffie-Hellman
//! Ephemeral Static key agreement with AES Key Wrap).

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use p256::elliptic_curve::Generate as _;
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use p256::{NonZeroScalar, PublicKey, Sec1Point, SecretKey};
use rand::rng;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use crate::algorithms::jwe::aes_kw::{A128KWKey, A256KWKey};
use crate::algorithms::jwe::kdf::derive_kek;
use crate::algorithms::jwk::{
    decode_secret, ec_export, ec_point, ec_point_matches, ec_thumbprint, Jwk, JwkDescriptor,
    KeyRole, KeyType,
};
use crate::claims::*;
use crate::error::*;
use crate::jwe_header::JWEHeader;
use crate::jwe_token::{DecryptionOptions, EncryptionOptions, JWEToken, JWETokenMetadata};

// Accept Deno's non-standard `"alg": "ECDH"` exports.
const A256KW_PUBLIC_JWK: JwkDescriptor = JwkDescriptor::new(
    KeyType::Ec,
    Some("P-256"),
    "ECDH-ES+A256KW",
    KeyRole::AgreementPublic,
)
.with_aliases(&["ECDH"]);
const A256KW_PRIVATE_JWK: JwkDescriptor = A256KW_PUBLIC_JWK.with_role(KeyRole::AgreementPrivate);

const A128KW_PUBLIC_JWK: JwkDescriptor = JwkDescriptor::new(
    KeyType::Ec,
    Some("P-256"),
    "ECDH-ES+A128KW",
    KeyRole::AgreementPublic,
)
.with_aliases(&["ECDH"]);
const A128KW_PRIVATE_JWK: JwkDescriptor = A128KW_PUBLIC_JWK.with_role(KeyRole::AgreementPrivate);

fn public_key_from_jwk(
    jwk: &str,
    descriptor: &JwkDescriptor,
) -> Result<(PublicKey, Option<String>), Error> {
    let jwk = Jwk::parse(jwk, descriptor)?;
    let point = ec_point(&jwk, 32).ok_or(JWTError::InvalidPublicKey)?;
    let pk = PublicKey::from_sec1_bytes(&point).map_err(|_| JWTError::InvalidPublicKey)?;
    Ok((pk, jwk.kid().map(Into::into)))
}

fn secret_key_from_jwk(
    jwk: &str,
    descriptor: &JwkDescriptor,
) -> Result<(SecretKey, Option<String>), Error> {
    let jwk = Jwk::parse(jwk, descriptor)?;
    let d = decode_secret(jwk.d(), 32).ok_or(JWTError::InvalidKeyPair)?;
    let sk = SecretKey::from_slice(&d).map_err(|_| JWTError::InvalidKeyPair)?;
    ensure!(
        ec_point_matches(&jwk, sk.public_key().to_sec1_point(false).as_bytes()),
        JWTError::InvalidKeyPair
    );
    Ok((sk, jwk.kid().map(Into::into)))
}

fn secret_key_to_jwk(sk: &SecretKey, descriptor: &JwkDescriptor, key_id: Option<&str>) -> String {
    let point = sk.public_key().to_sec1_point(false);
    let d = Zeroizing::new(sk.to_bytes().to_vec());
    ec_export(descriptor, point.as_bytes(), Some(&d), key_id)
}

/// Apply the recipient key checks to the token's ephemeral key too.
fn parse_epk(epk: &serde_json::Value, descriptor: &JwkDescriptor) -> Result<PublicKey, Error> {
    let jwk = Jwk::from_value(epk, descriptor).map_err(|_| JWTError::InvalidEphemeralKey)?;
    let point = ec_point(&jwk, 32).ok_or(JWTError::InvalidEphemeralKey)?;
    PublicKey::from_sec1_bytes(&point).map_err(|_| JWTError::InvalidEphemeralKey.into())
}

/// P-256 public key for ECDH-ES+A256KW encryption.
#[derive(Debug, Clone)]
pub struct EcdhEsA256KWEncryptionKey {
    pk: PublicKey,
    key_id: Option<String>,
}

impl EcdhEsA256KWEncryptionKey {
    const ALG_NAME: &'static str = "ECDH-ES+A256KW";
    const KEY_WRAP_SIZE: usize = 32;

    /// Import a public key from a JWK (`kty: EC`, `crv: P-256`).
    ///
    /// See [strict JWK validation](crate#strict-jwk-validation) for the rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let (pk, key_id) = public_key_from_jwk(jwk, &A256KW_PUBLIC_JWK)?;
        Ok(EcdhEsA256KWEncryptionKey { pk, key_id })
    }

    /// Export the public key as a JWK, with `alg: ECDH-ES+A256KW` and `use: enc`.
    pub fn to_jwk(&self) -> String {
        let point = self.pk.to_sec1_point(false);
        ec_export(
            &A256KW_PUBLIC_JWK,
            point.as_bytes(),
            None,
            self.key_id.as_deref(),
        )
    }

    /// The JWK thumbprint of the key.
    pub fn jwk_thumbprint(&self) -> String {
        ec_thumbprint("P-256", self.pk.to_sec1_point(false).as_bytes())
    }

    /// Create from SEC1-encoded bytes (compressed or uncompressed).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let point = Sec1Point::from_bytes(bytes).map_err(|_| JWTError::InvalidPublicKey)?;
        let pk = PublicKey::from_sec1_point(&point);
        if pk.is_none().into() {
            bail!(JWTError::InvalidPublicKey);
        }
        Ok(EcdhEsA256KWEncryptionKey {
            pk: pk.unwrap(),
            key_id: None,
        })
    }

    /// Create from DER-encoded public key.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let pk = PublicKey::from_public_key_der(der).map_err(|_| JWTError::InvalidPublicKey)?;
        Ok(EcdhEsA256KWEncryptionKey { pk, key_id: None })
    }

    /// Create from PEM-encoded public key.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let pk = PublicKey::from_public_key_pem(pem).map_err(|_| JWTError::InvalidPublicKey)?;
        Ok(EcdhEsA256KWEncryptionKey { pk, key_id: None })
    }

    /// Export as SEC1 compressed bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.pk.to_sec1_point(true).as_bytes().to_vec()
    }

    /// Export as SEC1 uncompressed bytes.
    pub fn to_bytes_uncompressed(&self) -> Vec<u8> {
        self.pk.to_sec1_point(false).as_bytes().to_vec()
    }

    /// Export as DER.
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        Ok(self
            .pk
            .to_public_key_der()
            .map_err(|_| JWTError::InvalidPublicKey)?
            .as_ref()
            .to_vec())
    }

    /// Export as PEM.
    pub fn to_pem(&self) -> Result<String, Error> {
        Ok(self
            .pk
            .to_public_key_pem(Default::default())
            .map_err(|_| JWTError::InvalidPublicKey)?)
    }

    /// Set the key ID.
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Get the key ID.
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    fn build_epk_jwk(&self, ephemeral_pk: &PublicKey) -> serde_json::Value {
        let point = ephemeral_pk.to_sec1_point(false);
        let x = Base64UrlSafeNoPadding::encode_to_string(point.x().unwrap()).unwrap();
        let y = Base64UrlSafeNoPadding::encode_to_string(point.y().unwrap()).unwrap();
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        })
    }

    /// Encrypt claims into a JWE token.
    pub fn encrypt<CustomClaims: Serialize>(
        &self,
        claims: JWTClaims<CustomClaims>,
    ) -> Result<String, Error> {
        self.encrypt_with_options(claims, &EncryptionOptions::default())
    }

    /// Encrypt claims into a JWE token with options.
    pub fn encrypt_with_options<CustomClaims: Serialize>(
        &self,
        claims: JWTClaims<CustomClaims>,
        options: &EncryptionOptions,
    ) -> Result<String, Error> {
        let content_encryption = options.content_encryption;

        let ephemeral_secret = EphemeralSecret::generate_from_rng(&mut rng());
        let ephemeral_pk = ephemeral_secret.public_key();

        let shared_secret = ephemeral_secret.diffie_hellman(&self.pk);

        let mut header = JWEHeader::new(Self::ALG_NAME, content_encryption.alg_name());
        header.ephemeral_public_key = Some(self.build_epk_jwk(&ephemeral_pk));

        let kek = derive_kek(
            shared_secret.raw_secret_bytes(),
            Self::KEY_WRAP_SIZE,
            &header,
        )?;
        let wrap_key = A256KWKey::from_bytes(&kek)?;

        if let Some(key_id) = &self.key_id {
            header.key_id = Some(key_id.clone());
        }
        if let Some(key_id) = &options.key_id {
            header.key_id = Some(key_id.clone());
        }
        if let Some(cty) = &options.content_type {
            header.content_type = Some(cty.clone());
        }

        JWEToken::build_from_claims(&header, &claims, content_encryption, |cek| {
            wrap_key.wrap_key(cek)
        })
    }
}

/// P-256 key pair for ECDH-ES+A256KW decryption.
#[derive(Clone)]
pub struct EcdhEsA256KWDecryptionKey {
    sk: SecretKey,
    key_id: Option<String>,
}

impl std::fmt::Debug for EcdhEsA256KWDecryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdhEsA256KWDecryptionKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl EcdhEsA256KWDecryptionKey {
    const ALG_NAME: &'static str = "ECDH-ES+A256KW";
    const KEY_WRAP_SIZE: usize = 32;

    /// Import a key pair from a private JWK (`kty: EC`, `crv: P-256`).
    ///
    /// See [strict JWK validation](crate#strict-jwk-validation) for the rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let (sk, key_id) = secret_key_from_jwk(jwk, &A256KW_PRIVATE_JWK)?;
        Ok(EcdhEsA256KWDecryptionKey { sk, key_id })
    }

    /// Export the key pair as a JWK, private key included.
    /// Use `encryption_key().to_jwk()` to share the public key.
    pub fn to_jwk(&self) -> String {
        secret_key_to_jwk(&self.sk, &A256KW_PRIVATE_JWK, self.key_id.as_deref())
    }

    /// The JWK thumbprint of the public key.
    pub fn jwk_thumbprint(&self) -> String {
        self.encryption_key().jwk_thumbprint()
    }

    /// Create from raw scalar bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let sk = SecretKey::from_slice(bytes).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(EcdhEsA256KWDecryptionKey { sk, key_id: None })
    }

    /// Create from DER-encoded private key.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let sk = SecretKey::from_pkcs8_der(der).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(EcdhEsA256KWDecryptionKey { sk, key_id: None })
    }

    /// Create from PEM-encoded private key.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let sk = SecretKey::from_pkcs8_pem(pem).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(EcdhEsA256KWDecryptionKey { sk, key_id: None })
    }

    /// Generate a new key pair.
    pub fn generate() -> Self {
        let sk = SecretKey::generate_from_rng(&mut rng());
        EcdhEsA256KWDecryptionKey { sk, key_id: None }
    }

    /// Export private key as raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.sk.to_bytes().to_vec()
    }

    /// Export private key as DER.
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let scalar = NonZeroScalar::from_repr(self.sk.to_bytes());
        if bool::from(scalar.is_none()) {
            return Err(JWTError::InvalidKeyPair.into());
        }
        let sk = SecretKey::from(NonZeroScalar::from_repr(scalar.unwrap().into()).unwrap());
        Ok(sk
            .to_pkcs8_der()
            .map_err(|_| JWTError::InvalidKeyPair)?
            .as_bytes()
            .to_vec())
    }

    /// Export private key as PEM.
    pub fn to_pem(&self) -> Result<String, Error> {
        let scalar = NonZeroScalar::from_repr(self.sk.to_bytes());
        if bool::from(scalar.is_none()) {
            return Err(JWTError::InvalidKeyPair.into());
        }
        let sk = SecretKey::from(NonZeroScalar::from_repr(scalar.unwrap().into()).unwrap());
        Ok(sk
            .to_pkcs8_pem(Default::default())
            .map_err(|_| JWTError::InvalidKeyPair)?
            .to_string())
    }

    /// Get the public encryption key.
    pub fn encryption_key(&self) -> EcdhEsA256KWEncryptionKey {
        EcdhEsA256KWEncryptionKey {
            pk: self.sk.public_key(),
            key_id: self.key_id.clone(),
        }
    }

    /// Set the key ID.
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Get the key ID.
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    /// Encrypt claims into a JWE token.
    pub fn encrypt<CustomClaims: Serialize>(
        &self,
        claims: JWTClaims<CustomClaims>,
    ) -> Result<String, Error> {
        self.encryption_key().encrypt(claims)
    }

    /// Encrypt claims into a JWE token with options.
    pub fn encrypt_with_options<CustomClaims: Serialize>(
        &self,
        claims: JWTClaims<CustomClaims>,
        options: &EncryptionOptions,
    ) -> Result<String, Error> {
        self.encryption_key().encrypt_with_options(claims, options)
    }

    /// Decrypt a JWE token and return the claims.
    ///
    /// Decryption does not authenticate the sender: the encryption key is public,
    /// so anyone can mint a token that decrypts successfully, with any claims.
    /// Do not treat the result as trusted input without a separate signature check.
    pub fn decrypt_token<CustomClaims: DeserializeOwned>(
        &self,
        token: &str,
        options: Option<DecryptionOptions>,
    ) -> Result<JWTClaims<CustomClaims>, Error> {
        JWEToken::decrypt(Self::ALG_NAME, token, options, |header, encrypted_key| {
            let epk = header
                .ephemeral_public_key
                .as_ref()
                .ok_or(JWTError::MissingEphemeralKey)?;
            let ephemeral_pk = parse_epk(epk, &A256KW_PUBLIC_JWK)?;

            let shared_secret =
                p256::ecdh::diffie_hellman(self.sk.to_nonzero_scalar(), ephemeral_pk.as_affine());

            let kek = derive_kek(
                shared_secret.raw_secret_bytes(),
                Self::KEY_WRAP_SIZE,
                header,
            )?;
            let wrap_key = A256KWKey::from_bytes(&kek)?;
            wrap_key.unwrap_key(encrypted_key)
        })
    }

    /// Decode token metadata without decrypting.
    pub fn decode_metadata(token: &str) -> Result<JWETokenMetadata, Error> {
        JWEToken::decode_metadata(token)
    }
}

/// P-256 public key for ECDH-ES+A128KW encryption.
#[derive(Debug, Clone)]
pub struct EcdhEsA128KWEncryptionKey {
    pk: PublicKey,
    key_id: Option<String>,
}

impl EcdhEsA128KWEncryptionKey {
    const ALG_NAME: &'static str = "ECDH-ES+A128KW";
    const KEY_WRAP_SIZE: usize = 16;

    /// Import a public key from a JWK (`kty: EC`, `crv: P-256`).
    ///
    /// See [strict JWK validation](crate#strict-jwk-validation) for the rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let (pk, key_id) = public_key_from_jwk(jwk, &A128KW_PUBLIC_JWK)?;
        Ok(EcdhEsA128KWEncryptionKey { pk, key_id })
    }

    /// Export the public key as a JWK, with `alg: ECDH-ES+A128KW` and `use: enc`.
    pub fn to_jwk(&self) -> String {
        let point = self.pk.to_sec1_point(false);
        ec_export(
            &A128KW_PUBLIC_JWK,
            point.as_bytes(),
            None,
            self.key_id.as_deref(),
        )
    }

    /// The JWK thumbprint of the key.
    pub fn jwk_thumbprint(&self) -> String {
        ec_thumbprint("P-256", self.pk.to_sec1_point(false).as_bytes())
    }

    /// Create from SEC1-encoded bytes (compressed or uncompressed).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let point = Sec1Point::from_bytes(bytes).map_err(|_| JWTError::InvalidPublicKey)?;
        let pk = PublicKey::from_sec1_point(&point);
        if pk.is_none().into() {
            bail!(JWTError::InvalidPublicKey);
        }
        Ok(EcdhEsA128KWEncryptionKey {
            pk: pk.unwrap(),
            key_id: None,
        })
    }

    /// Create from DER-encoded public key.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let pk = PublicKey::from_public_key_der(der).map_err(|_| JWTError::InvalidPublicKey)?;
        Ok(EcdhEsA128KWEncryptionKey { pk, key_id: None })
    }

    /// Create from PEM-encoded public key.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let pk = PublicKey::from_public_key_pem(pem).map_err(|_| JWTError::InvalidPublicKey)?;
        Ok(EcdhEsA128KWEncryptionKey { pk, key_id: None })
    }

    /// Export as SEC1 compressed bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.pk.to_sec1_point(true).as_bytes().to_vec()
    }

    /// Export as DER.
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        Ok(self
            .pk
            .to_public_key_der()
            .map_err(|_| JWTError::InvalidPublicKey)?
            .as_ref()
            .to_vec())
    }

    /// Export as PEM.
    pub fn to_pem(&self) -> Result<String, Error> {
        Ok(self
            .pk
            .to_public_key_pem(Default::default())
            .map_err(|_| JWTError::InvalidPublicKey)?)
    }

    /// Set the key ID.
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Get the key ID.
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    fn build_epk_jwk(&self, ephemeral_pk: &PublicKey) -> serde_json::Value {
        let point = ephemeral_pk.to_sec1_point(false);
        let x = Base64UrlSafeNoPadding::encode_to_string(point.x().unwrap()).unwrap();
        let y = Base64UrlSafeNoPadding::encode_to_string(point.y().unwrap()).unwrap();
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        })
    }

    /// Encrypt claims into a JWE token.
    pub fn encrypt<CustomClaims: Serialize>(
        &self,
        claims: JWTClaims<CustomClaims>,
    ) -> Result<String, Error> {
        self.encrypt_with_options(claims, &EncryptionOptions::default())
    }

    /// Encrypt claims into a JWE token with options.
    pub fn encrypt_with_options<CustomClaims: Serialize>(
        &self,
        claims: JWTClaims<CustomClaims>,
        options: &EncryptionOptions,
    ) -> Result<String, Error> {
        let content_encryption = options.content_encryption;

        let ephemeral_secret = EphemeralSecret::generate_from_rng(&mut rng());
        let ephemeral_pk = ephemeral_secret.public_key();

        let shared_secret = ephemeral_secret.diffie_hellman(&self.pk);

        let mut header = JWEHeader::new(Self::ALG_NAME, content_encryption.alg_name());
        header.ephemeral_public_key = Some(self.build_epk_jwk(&ephemeral_pk));

        let kek = derive_kek(
            shared_secret.raw_secret_bytes(),
            Self::KEY_WRAP_SIZE,
            &header,
        )?;
        let wrap_key = A128KWKey::from_bytes(&kek)?;

        if let Some(key_id) = &self.key_id {
            header.key_id = Some(key_id.clone());
        }
        if let Some(key_id) = &options.key_id {
            header.key_id = Some(key_id.clone());
        }
        if let Some(cty) = &options.content_type {
            header.content_type = Some(cty.clone());
        }

        JWEToken::build_from_claims(&header, &claims, content_encryption, |cek| {
            wrap_key.wrap_key(cek)
        })
    }
}

/// P-256 key pair for ECDH-ES+A128KW decryption.
#[derive(Clone)]
pub struct EcdhEsA128KWDecryptionKey {
    sk: SecretKey,
    key_id: Option<String>,
}

impl std::fmt::Debug for EcdhEsA128KWDecryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdhEsA128KWDecryptionKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl EcdhEsA128KWDecryptionKey {
    const ALG_NAME: &'static str = "ECDH-ES+A128KW";
    const KEY_WRAP_SIZE: usize = 16;

    /// Import a key pair from a private JWK (`kty: EC`, `crv: P-256`).
    ///
    /// See [strict JWK validation](crate#strict-jwk-validation) for the rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let (sk, key_id) = secret_key_from_jwk(jwk, &A128KW_PRIVATE_JWK)?;
        Ok(EcdhEsA128KWDecryptionKey { sk, key_id })
    }

    /// Export the key pair as a JWK, private key included.
    /// Use `encryption_key().to_jwk()` to share the public key.
    pub fn to_jwk(&self) -> String {
        secret_key_to_jwk(&self.sk, &A128KW_PRIVATE_JWK, self.key_id.as_deref())
    }

    /// The JWK thumbprint of the public key.
    pub fn jwk_thumbprint(&self) -> String {
        self.encryption_key().jwk_thumbprint()
    }

    /// Create from raw scalar bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let sk = SecretKey::from_slice(bytes).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(EcdhEsA128KWDecryptionKey { sk, key_id: None })
    }

    /// Create from DER-encoded private key.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let sk = SecretKey::from_pkcs8_der(der).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(EcdhEsA128KWDecryptionKey { sk, key_id: None })
    }

    /// Create from PEM-encoded private key.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let sk = SecretKey::from_pkcs8_pem(pem).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(EcdhEsA128KWDecryptionKey { sk, key_id: None })
    }

    /// Generate a new key pair.
    pub fn generate() -> Self {
        let sk = SecretKey::generate_from_rng(&mut rng());
        EcdhEsA128KWDecryptionKey { sk, key_id: None }
    }

    /// Export private key as raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.sk.to_bytes().to_vec()
    }

    /// Export private key as DER.
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let scalar = NonZeroScalar::from_repr(self.sk.to_bytes());
        if bool::from(scalar.is_none()) {
            return Err(JWTError::InvalidKeyPair.into());
        }
        let sk = SecretKey::from(NonZeroScalar::from_repr(scalar.unwrap().into()).unwrap());
        Ok(sk
            .to_pkcs8_der()
            .map_err(|_| JWTError::InvalidKeyPair)?
            .as_bytes()
            .to_vec())
    }

    /// Export private key as PEM.
    pub fn to_pem(&self) -> Result<String, Error> {
        let scalar = NonZeroScalar::from_repr(self.sk.to_bytes());
        if bool::from(scalar.is_none()) {
            return Err(JWTError::InvalidKeyPair.into());
        }
        let sk = SecretKey::from(NonZeroScalar::from_repr(scalar.unwrap().into()).unwrap());
        Ok(sk
            .to_pkcs8_pem(Default::default())
            .map_err(|_| JWTError::InvalidKeyPair)?
            .to_string())
    }

    /// Get the public encryption key.
    pub fn encryption_key(&self) -> EcdhEsA128KWEncryptionKey {
        EcdhEsA128KWEncryptionKey {
            pk: self.sk.public_key(),
            key_id: self.key_id.clone(),
        }
    }

    /// Set the key ID.
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Get the key ID.
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    /// Encrypt claims into a JWE token.
    pub fn encrypt<CustomClaims: Serialize>(
        &self,
        claims: JWTClaims<CustomClaims>,
    ) -> Result<String, Error> {
        self.encryption_key().encrypt(claims)
    }

    /// Encrypt claims into a JWE token with options.
    pub fn encrypt_with_options<CustomClaims: Serialize>(
        &self,
        claims: JWTClaims<CustomClaims>,
        options: &EncryptionOptions,
    ) -> Result<String, Error> {
        self.encryption_key().encrypt_with_options(claims, options)
    }

    /// Decrypt a JWE token and return the claims.
    ///
    /// Decryption does not authenticate the sender: the encryption key is public,
    /// so anyone can mint a token that decrypts successfully, with any claims.
    /// Do not treat the result as trusted input without a separate signature check.
    pub fn decrypt_token<CustomClaims: DeserializeOwned>(
        &self,
        token: &str,
        options: Option<DecryptionOptions>,
    ) -> Result<JWTClaims<CustomClaims>, Error> {
        JWEToken::decrypt(Self::ALG_NAME, token, options, |header, encrypted_key| {
            let epk = header
                .ephemeral_public_key
                .as_ref()
                .ok_or(JWTError::MissingEphemeralKey)?;
            let ephemeral_pk = parse_epk(epk, &A128KW_PUBLIC_JWK)?;

            let shared_secret =
                p256::ecdh::diffie_hellman(self.sk.to_nonzero_scalar(), ephemeral_pk.as_affine());

            let kek = derive_kek(
                shared_secret.raw_secret_bytes(),
                Self::KEY_WRAP_SIZE,
                header,
            )?;
            let wrap_key = A128KWKey::from_bytes(&kek)?;
            wrap_key.unwrap_key(encrypted_key)
        })
    }

    /// Decode token metadata without decrypting.
    pub fn decode_metadata(token: &str) -> Result<JWETokenMetadata, Error> {
        JWEToken::decode_metadata(token)
    }
}

#[cfg(test)]
mod tests {
    use ct_codecs::Decoder;

    use super::*;
    use crate::algorithms::test_util::{error_of, with_epk, with_header_change};
    use crate::claims::NoCustomClaims;

    const RECIPIENT_D: &str = "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw";

    // Generated by jwcrypto 1.5.6 with apu "Alice" and apv "Bob".
    // Checked against jose 6.2.12.
    const JWCRYPTO_A128KW: &str = concat!(
        "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImFwdSI6IlFXeHBZMlUiLCJhcHYiOiJRbTlpIiwiZW5jIjoiQTEyOEdDTSIsImV",
        "wayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6Ims0TWFKN0x4OXJpTm0tUTNuajRGTzdOZmYxcW1Obk5na3R3c3",
        "VIVHBkbTQiLCJ5IjoiblBTdmFTZmJ0SXBYREVyNDRQbXFEcm9RdlNhRUY5bjZfaXN6SHVNZ2xROCJ9fQ.HAxHPWcla6utff",
        "mgI_nbNyWKyxmthKlK.LxfrpOEx7PuSUWf3.bLGAfvfJocvl5OV73i44k5Ax8Tpo8_nlTm5srgMbauqlpGSPb1-W7u2rI4A",
        ".uBQhz3Py_2GPjNJVfqKliQ"
    );
    const JWCRYPTO_A256KW: &str = concat!(
        "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImFwdSI6IlFXeHBZMlUiLCJhcHYiOiJRbTlpIiwiZW5jIjoiQTI1NkdDTSIsImV",
        "wayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6InBuMGpuaXZCcWZoREM3R3JsYi1Ma3d0OGVOYzNjTlUyOWk0VH",
        "haQkNuUFkiLCJ5IjoieXdtUHVocFJRWFhHRU93bXh5bThoSDJqZ252eWZ4bjN1UzhURExiOG05ayJ9fQ.ZtWfkfnDsZeMWU",
        "mafQlLg4qT851x9-xisHDaEYzsUEq0c2nvvAC0eQ.5g1OCq4lDKcKgzpJ.9TOueJRKmz895p04jOiilbqjOCejGWlLgY1yL",
        "BXSdp9v66iGPXAIrcmFwzw.1DBxGPgd1pQjlpSVISKlhw"
    );

    fn recipient_d() -> Vec<u8> {
        Base64UrlSafeNoPadding::decode_to_vec(RECIPIENT_D, None).unwrap()
    }

    fn jwe_error(result: Result<JWTClaims<NoCustomClaims>, Error>) -> JWTError {
        error_of(result)
    }

    fn check_party_info(
        alg: &str,
        fixture: &str,
        decrypt: impl Fn(&str) -> Result<JWTClaims<NoCustomClaims>, Error>,
    ) {
        let claims = decrypt(fixture).unwrap();
        assert_eq!(claims.subject.as_deref(), Some(alg));

        // Key unwrapping must fail before the changed header causes a tag mismatch.
        let changed = [
            ("apu", Some("QWxpY2Y")),
            ("apv", Some("Qm9j")),
            ("apu", None),
            ("apv", None),
        ];
        for (name, value) in changed {
            let token = with_header_change(fixture, |header| match value {
                Some(value) => header[name] = value.into(),
                None => {
                    header.as_object_mut().unwrap().remove(name);
                }
            });
            assert!(
                matches!(jwe_error(decrypt(&token)), JWTError::KeyUnwrapFailed),
                "{}: {} set to {:?}",
                alg,
                name,
                value
            );
        }

        // Check that token decryption applies the rules tested in kdf.rs.
        for (apu, apv) in [("QWxpY2U", "QWxpY2U"), ("QWxpY2U", "Qm9i!")] {
            let token = with_header_change(fixture, |header| {
                header["apu"] = apu.into();
                header["apv"] = apv.into();
            });
            assert!(
                matches!(jwe_error(decrypt(&token)), JWTError::InvalidJWEFormat),
                "{}: apu {:?}, apv {:?}",
                alg,
                apu,
                apv
            );
        }
    }

    #[test]
    fn decrypts_independent_fixtures_and_checks_their_party_info() {
        let a128kw = EcdhEsA128KWDecryptionKey::from_bytes(&recipient_d()).unwrap();
        let a256kw = EcdhEsA256KWDecryptionKey::from_bytes(&recipient_d()).unwrap();
        check_party_info("ECDH-ES+A128KW", JWCRYPTO_A128KW, |token| {
            a128kw.decrypt_token(token, None)
        });
        check_party_info("ECDH-ES+A256KW", JWCRYPTO_A256KW, |token| {
            a256kw.decrypt_token(token, None)
        });
    }

    fn epk_error(key: &EcdhEsA256KWDecryptionKey, token: &str, epk: &str) -> JWTError {
        jwe_error(key.decrypt_token(&with_epk(token, epk), None))
    }

    #[test]
    fn ephemeral_keys_are_decoded_strictly() {
        let key = EcdhEsA256KWDecryptionKey::generate();
        let token = key
            .encrypt(Claims::create(coarsetime::Duration::from_hours(1)))
            .unwrap();
        let metadata = EcdhEsA256KWDecryptionKey::decode_metadata(&token).unwrap();
        let epk = metadata.header().ephemeral_public_key.clone().unwrap();
        let x = epk["x"].as_str().unwrap();
        let y = epk["y"].as_str().unwrap();
        let xy = [
            Base64UrlSafeNoPadding::decode_to_vec(x, None).unwrap(),
            Base64UrlSafeNoPadding::decode_to_vec(y, None).unwrap(),
        ]
        .concat();
        let b64 = |bin: &[u8]| Base64UrlSafeNoPadding::encode_to_string(bin).unwrap();
        let other = EcdhEsA256KWDecryptionKey::generate().to_jwk();
        let other: serde_json::Value = serde_json::from_str(&other).unwrap();

        let rejected = [
            // Valid point bytes, split at the wrong place.
            format!(
                r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}"#,
                b64(&xy[..31]),
                b64(&xy[31..])
            ),
            format!(
                r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}"#,
                b64(&xy[..33]),
                b64(&xy[33..])
            ),
            format!(
                r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","d":{}}}"#,
                x, y, other["d"]
            ),
            format!(
                r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","d":null}}"#,
                x, y
            ),
            format!(r#"{{"kty":"OKP","crv":"P-256","x":"{}","y":"{}"}}"#, x, y),
            format!(r#"{{"kty":"EC","crv":"P-384","x":"{}","y":"{}"}}"#, x, y),
            format!(
                r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","alg":"ES256"}}"#,
                x, y
            ),
            format!(
                r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","alg":"ECDH-ES+A128KW"}}"#,
                x, y
            ),
            format!(
                r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","use":"sig"}}"#,
                x, y
            ),
            format!(
                r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","key_ops":["sign"]}}"#,
                x, y
            ),
            format!(r#"{{"kty":"EC","crv":"P-256","x":"{}"}}"#, x),
            format!(r#"{{"kty":"EC","crv":"P-256","x":"{}=","y":"{}"}}"#, x, y),
            "\"epk\"".to_string(),
            "[]".to_string(),
        ];
        for epk in &rejected {
            assert!(
                matches!(epk_error(&key, &token, epk), JWTError::InvalidEphemeralKey),
                "{}",
                epk
            );
        }

        for epk in [
            format!(
                r#"{{"kty":"EC","crv":"P-256","x":"{0}","x":"{0}","y":"{1}"}}"#,
                x, y
            ),
            format!(
                r#"{{"kty":"EC","crv":"P-256","x":"{0}","\u0078":"{0}","y":"{1}"}}"#,
                x, y
            ),
            format!(
                r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","ext":{{"a":1,"a":1}}}}"#,
                x, y
            ),
        ] {
            let tampered = with_epk(&token, &epk);
            let err = key
                .decrypt_token::<NoCustomClaims>(&tampered, None)
                .unwrap_err();
            assert!(err.downcast_ref::<serde_json::Error>().is_some(), "{}", err);
            assert!(EcdhEsA256KWDecryptionKey::decode_metadata(&tampered).is_err());
        }

        // Accept the metadata, then fail because the changed header invalidates the tag.
        let fine = format!(
            r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","use":"enc","key_ops":[]}}"#,
            x, y
        );
        assert!(matches!(
            epk_error(&key, &token, &fine),
            JWTError::DecryptionFailed | JWTError::InvalidAuthenticationTag
        ));

        let without_epk = with_header_change(&token, |header| {
            header.as_object_mut().unwrap().remove("epk");
        });
        assert!(matches!(
            jwe_error(key.decrypt_token(&without_epk, None)),
            JWTError::MissingEphemeralKey
        ));

        let null_epk = with_header_change(&token, |header| {
            header["epk"] = serde_json::Value::Null;
        });
        assert!(matches!(
            jwe_error(key.decrypt_token(&null_epk, None)),
            JWTError::MissingEphemeralKey
        ));
        let metadata = EcdhEsA256KWDecryptionKey::decode_metadata(&null_epk).unwrap();
        assert!(metadata.header().ephemeral_public_key.is_none());
    }

    #[test]
    fn jwk_round_trips() {
        let key = EcdhEsA256KWDecryptionKey::generate().with_key_id("recipient");
        let private_jwk = key.to_jwk();
        let public_jwk = key.encryption_key().to_jwk();
        let exported: serde_json::Value = serde_json::from_str(&public_jwk).unwrap();
        assert_eq!(exported["alg"], "ECDH-ES+A256KW");
        assert_eq!(exported["use"], "enc");
        assert_eq!(exported["kid"], "recipient");
        assert!(exported.get("d").is_none());

        let restored = EcdhEsA256KWDecryptionKey::from_jwk(&private_jwk).unwrap();
        let encryption_key = EcdhEsA256KWEncryptionKey::from_jwk(&public_jwk).unwrap();
        assert_eq!(restored.to_bytes(), key.to_bytes());
        assert_eq!(restored.key_id(), Some("recipient"));
        assert_eq!(encryption_key.key_id(), Some("recipient"));
        assert_eq!(restored.jwk_thumbprint(), encryption_key.jwk_thumbprint());
        assert_eq!(restored.to_jwk(), private_jwk);

        let token = encryption_key
            .encrypt(Claims::create(coarsetime::Duration::from_hours(1)))
            .unwrap();
        assert_eq!(
            EcdhEsA256KWDecryptionKey::decode_metadata(&token)
                .unwrap()
                .key_id(),
            Some("recipient")
        );
        restored
            .decrypt_token::<NoCustomClaims>(&token, None)
            .unwrap();

        // The same key works in either mode if its `alg` matches.
        assert!(EcdhEsA128KWEncryptionKey::from_jwk(&public_jwk).is_err());
        assert!(EcdhEsA128KWDecryptionKey::from_jwk(&private_jwk).is_err());
        let key = EcdhEsA128KWDecryptionKey::from_jwk(
            &private_jwk.replace("ECDH-ES+A256KW", "ECDH-ES+A128KW"),
        )
        .unwrap();
        assert_eq!(key.jwk_thumbprint(), encryption_key.jwk_thumbprint());

        let token = key
            .encrypt(Claims::create(coarsetime::Duration::from_hours(1)))
            .unwrap();
        let metadata = EcdhEsA128KWDecryptionKey::decode_metadata(&token).unwrap();
        assert!(metadata.header().apu.is_none());
        assert!(metadata.header().apv.is_none());
        key.decrypt_token::<NoCustomClaims>(&token, None).unwrap();
    }

    #[test]
    fn jwk_import_rejects_signature_keys() {
        let es256 = crate::algorithms::ES256KeyPair::generate();
        let public_jwk = es256.public_key().to_jwk();
        assert!(EcdhEsA256KWEncryptionKey::from_jwk(&public_jwk).is_err());
        assert!(EcdhEsA128KWEncryptionKey::from_jwk(&public_jwk).is_err());
        assert!(EcdhEsA256KWDecryptionKey::from_jwk(&es256.to_jwk()).is_err());
    }

    #[test]
    fn webcrypto_exports() {
        use crate::algorithms::jwk_test_vectors;

        for export in jwk_test_vectors::ALL {
            let export: serde_json::Value = serde_json::from_str(export).unwrap();
            let entry = &export["keys"]["ECDH-P256"];
            let private_jwk = entry["private"].to_string();
            let public_jwk = entry["public"].to_string();
            let decryption_key = EcdhEsA256KWDecryptionKey::from_jwk(&private_jwk).unwrap();
            let encryption_key = EcdhEsA256KWEncryptionKey::from_jwk(&public_jwk).unwrap();
            assert_eq!(
                decryption_key.jwk_thumbprint(),
                encryption_key.jwk_thumbprint()
            );
            let token = encryption_key
                .encrypt(Claims::create(coarsetime::Duration::from_hours(1)))
                .unwrap();
            decryption_key
                .decrypt_token::<NoCustomClaims>(&token, None)
                .unwrap();
            EcdhEsA128KWDecryptionKey::from_jwk(&private_jwk).unwrap();

            // Node.js and Bun export ES256 keys without `alg`, so `key_ops` rejects them.
            let es256 = &export["keys"]["ES256"]["private"];
            assert!(EcdhEsA256KWDecryptionKey::from_jwk(&es256.to_string()).is_err());
        }
    }
}
