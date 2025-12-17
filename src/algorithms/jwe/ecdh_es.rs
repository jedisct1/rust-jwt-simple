//! ECDH-ES key agreement algorithms for JWE.
//!
//! Implements ECDH-ES+A256KW and ECDH-ES+A128KW (Elliptic Curve Diffie-Hellman
//! Ephemeral Static key agreement with AES Key Wrap).

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use p256::{EncodedPoint, NonZeroScalar, PublicKey, SecretKey};
use rand::thread_rng;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::json;
use zeroize::Zeroize;

use crate::algorithms::jwe::aes_kw::{A128KWKey, A256KWKey};
use crate::claims::*;
use crate::error::*;
use crate::jwe_header::JWEHeader;
use crate::jwe_token::{DecryptionOptions, EncryptionOptions, JWEToken, JWETokenMetadata};

/// Derive a key using Concat KDF as specified in NIST SP 800-56A.
fn concat_kdf(
    shared_secret: &[u8],
    key_len: usize,
    alg: &str,
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Vec<u8> {
    use hmac_sha256::Hash as SHA256;

    let apu = apu.unwrap_or(&[]);
    let apv = apv.unwrap_or(&[]);

    // AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo
    let alg_bytes = alg.as_bytes();
    let alg_len = (alg_bytes.len() as u32).to_be_bytes();
    let apu_len = (apu.len() as u32).to_be_bytes();
    let apv_len = (apv.len() as u32).to_be_bytes();
    let key_bits = ((key_len * 8) as u32).to_be_bytes();

    let mut derived_key = Vec::with_capacity(key_len);
    let mut counter: u32 = 1;

    while derived_key.len() < key_len {
        let counter_bytes = counter.to_be_bytes();

        // Hash: counter || Z || OtherInfo
        let mut hasher = SHA256::new();
        hasher.update(counter_bytes);
        hasher.update(shared_secret);
        // OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo
        hasher.update(alg_len);
        hasher.update(alg_bytes);
        hasher.update(apu_len);
        hasher.update(apu);
        hasher.update(apv_len);
        hasher.update(apv);
        hasher.update(key_bits);

        let hash = hasher.finalize();
        derived_key.extend_from_slice(&hash);
        counter += 1;
    }

    derived_key.truncate(key_len);
    derived_key
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

    /// Create from SEC1-encoded bytes (compressed or uncompressed).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let point = EncodedPoint::from_bytes(bytes).map_err(|_| JWTError::InvalidPublicKey)?;
        let pk = PublicKey::from_encoded_point(&point);
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
        self.pk.to_encoded_point(true).as_bytes().to_vec()
    }

    /// Export as SEC1 uncompressed bytes.
    pub fn to_bytes_uncompressed(&self) -> Vec<u8> {
        self.pk.to_encoded_point(false).as_bytes().to_vec()
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
        let point = ephemeral_pk.to_encoded_point(false);
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

        let ephemeral_secret = EphemeralSecret::random(&mut thread_rng());
        let ephemeral_pk = ephemeral_secret.public_key();

        let shared_secret = ephemeral_secret.diffie_hellman(&self.pk);

        let mut kek = concat_kdf(
            shared_secret.raw_secret_bytes(),
            Self::KEY_WRAP_SIZE,
            Self::ALG_NAME,
            None,
            None,
        );

        let wrap_key = A256KWKey::from_bytes(&kek)?;
        kek.zeroize();

        let mut header = JWEHeader::new(Self::ALG_NAME, content_encryption.alg_name());
        header.ephemeral_public_key = Some(self.build_epk_jwk(&ephemeral_pk));

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
        let sk = SecretKey::random(&mut thread_rng());
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

    fn parse_epk(epk: &serde_json::Value) -> Result<PublicKey, Error> {
        let kty = epk.get("kty").and_then(|v| v.as_str());
        ensure!(kty == Some("EC"), JWTError::InvalidEphemeralKey);

        let crv = epk.get("crv").and_then(|v| v.as_str());
        ensure!(crv == Some("P-256"), JWTError::InvalidEphemeralKey);

        let x = epk
            .get("x")
            .and_then(|v| v.as_str())
            .ok_or(JWTError::InvalidEphemeralKey)?;
        let y = epk
            .get("y")
            .and_then(|v| v.as_str())
            .ok_or(JWTError::InvalidEphemeralKey)?;

        let x_bytes =
            Base64UrlSafeNoPadding::decode_to_vec(x, None).map_err(|_| JWTError::InvalidEphemeralKey)?;
        let y_bytes =
            Base64UrlSafeNoPadding::decode_to_vec(y, None).map_err(|_| JWTError::InvalidEphemeralKey)?;

        // Build uncompressed point: 0x04 || x || y
        let mut point_bytes = vec![0x04];
        point_bytes.extend_from_slice(&x_bytes);
        point_bytes.extend_from_slice(&y_bytes);

        let point =
            EncodedPoint::from_bytes(&point_bytes).map_err(|_| JWTError::InvalidEphemeralKey)?;
        let pk = PublicKey::from_encoded_point(&point);
        if pk.is_none().into() {
            bail!(JWTError::InvalidEphemeralKey);
        }

        Ok(pk.unwrap())
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
            let ephemeral_pk = Self::parse_epk(epk)?;

            let shared_secret = p256::ecdh::diffie_hellman(
                self.sk.to_nonzero_scalar(),
                ephemeral_pk.as_affine(),
            );

            let mut kek = concat_kdf(
                shared_secret.raw_secret_bytes(),
                Self::KEY_WRAP_SIZE,
                Self::ALG_NAME,
                None,
                None,
            );

            let wrap_key = A256KWKey::from_bytes(&kek)?;
            kek.zeroize();
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

    /// Create from SEC1-encoded bytes (compressed or uncompressed).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let point = EncodedPoint::from_bytes(bytes).map_err(|_| JWTError::InvalidPublicKey)?;
        let pk = PublicKey::from_encoded_point(&point);
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
        self.pk.to_encoded_point(true).as_bytes().to_vec()
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
        let point = ephemeral_pk.to_encoded_point(false);
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

        let ephemeral_secret = EphemeralSecret::random(&mut thread_rng());
        let ephemeral_pk = ephemeral_secret.public_key();

        let shared_secret = ephemeral_secret.diffie_hellman(&self.pk);

        let mut kek = concat_kdf(
            shared_secret.raw_secret_bytes(),
            Self::KEY_WRAP_SIZE,
            Self::ALG_NAME,
            None,
            None,
        );

        let wrap_key = A128KWKey::from_bytes(&kek)?;
        kek.zeroize();

        let mut header = JWEHeader::new(Self::ALG_NAME, content_encryption.alg_name());
        header.ephemeral_public_key = Some(self.build_epk_jwk(&ephemeral_pk));

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
        let sk = SecretKey::random(&mut thread_rng());
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

    fn parse_epk(epk: &serde_json::Value) -> Result<PublicKey, Error> {
        let kty = epk.get("kty").and_then(|v| v.as_str());
        ensure!(kty == Some("EC"), JWTError::InvalidEphemeralKey);

        let crv = epk.get("crv").and_then(|v| v.as_str());
        ensure!(crv == Some("P-256"), JWTError::InvalidEphemeralKey);

        let x = epk
            .get("x")
            .and_then(|v| v.as_str())
            .ok_or(JWTError::InvalidEphemeralKey)?;
        let y = epk
            .get("y")
            .and_then(|v| v.as_str())
            .ok_or(JWTError::InvalidEphemeralKey)?;

        let x_bytes =
            Base64UrlSafeNoPadding::decode_to_vec(x, None).map_err(|_| JWTError::InvalidEphemeralKey)?;
        let y_bytes =
            Base64UrlSafeNoPadding::decode_to_vec(y, None).map_err(|_| JWTError::InvalidEphemeralKey)?;

        // Build uncompressed point: 0x04 || x || y
        let mut point_bytes = vec![0x04];
        point_bytes.extend_from_slice(&x_bytes);
        point_bytes.extend_from_slice(&y_bytes);

        let point =
            EncodedPoint::from_bytes(&point_bytes).map_err(|_| JWTError::InvalidEphemeralKey)?;
        let pk = PublicKey::from_encoded_point(&point);
        if pk.is_none().into() {
            bail!(JWTError::InvalidEphemeralKey);
        }

        Ok(pk.unwrap())
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
            let ephemeral_pk = Self::parse_epk(epk)?;

            let shared_secret = p256::ecdh::diffie_hellman(
                self.sk.to_nonzero_scalar(),
                ephemeral_pk.as_affine(),
            );

            let mut kek = concat_kdf(
                shared_secret.raw_secret_bytes(),
                Self::KEY_WRAP_SIZE,
                Self::ALG_NAME,
                None,
                None,
            );

            let wrap_key = A128KWKey::from_bytes(&kek)?;
            kek.zeroize();
            wrap_key.unwrap_key(encrypted_key)
        })
    }

    /// Decode token metadata without decrypting.
    pub fn decode_metadata(token: &str) -> Result<JWETokenMetadata, Error> {
        JWEToken::decode_metadata(token)
    }
}
