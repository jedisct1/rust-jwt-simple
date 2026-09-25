//! ECDH-ES key agreement over X25519 for JWE.
//!
//! Implements ECDH-ES+A256KW and ECDH-ES+A128KW with X25519 keys, using the
//! same key derivation and key wrapping as the P-256 variants.

use ed25519_compact::x25519;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::json;

use crate::algorithms::jwe::aes_kw::{A128KWKey, A256KWKey};
use crate::algorithms::jwe::kdf::derive_kek;
use crate::algorithms::jwk::{
    decode_fixed, decode_secret, encode, is_encoding_of, okp_export, okp_thumbprint, Jwk,
    JwkDescriptor, KeyRole, KeyType,
};
use crate::claims::*;
use crate::error::*;
use crate::jwe_header::JWEHeader;
use crate::jwe_token::{DecryptionOptions, EncryptionOptions, JWEToken, JWETokenMetadata};

/// Choose the algorithm from the key type, never from a token.
#[derive(Clone, Copy)]
enum Mode {
    A128KW,
    A256KW,
}

impl Mode {
    fn alg(self) -> &'static str {
        match self {
            Mode::A128KW => "ECDH-ES+A128KW",
            Mode::A256KW => "ECDH-ES+A256KW",
        }
    }

    fn key_wrap_size(self) -> usize {
        match self {
            Mode::A128KW => 16,
            Mode::A256KW => 32,
        }
    }

    fn descriptor(self, role: KeyRole) -> JwkDescriptor {
        JwkDescriptor::new(KeyType::Okp, Some("X25519"), self.alg(), role)
    }

    fn wrap_key(self, kek: &[u8], cek: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            Mode::A128KW => A128KWKey::from_bytes(kek)?.wrap_key(cek),
            Mode::A256KW => A256KWKey::from_bytes(kek)?.wrap_key(cek),
        }
    }

    fn unwrap_key(self, kek: &[u8], encrypted_key: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            Mode::A128KW => A128KWKey::from_bytes(kek)?.unwrap_key(encrypted_key),
            Mode::A256KW => A256KWKey::from_bytes(kek)?.unwrap_key(encrypted_key),
        }
    }
}

/// Require one encoding per public key so its thumbprint cannot change.
///
/// Reject weak keys too, since they produce a predictable shared secret.
fn checked_public_key(raw: &[u8]) -> Option<x25519::PublicKey> {
    if raw.len() != x25519::PublicKey::BYTES || raw[x25519::PublicKey::BYTES - 1] & 0x80 != 0 {
        return None;
    }
    let pk = x25519::PublicKey::from_slice(raw).ok()?;
    pk.clear_cofactor().ok()?;
    Some(pk)
}

fn checked_jwk_public_key(jwk: &Jwk<'_>, error: JWTError) -> Result<x25519::PublicKey, Error> {
    let mut x = [0u8; x25519::PublicKey::BYTES];
    ensure!(decode_fixed(jwk.x(), &mut x), error);
    checked_public_key(&x).ok_or_else(|| error.into())
}

#[derive(Debug, Clone)]
struct X25519PublicKey(x25519::PublicKey);

impl X25519PublicKey {
    fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let pk = checked_public_key(raw).ok_or(JWTError::InvalidPublicKey)?;
        Ok(X25519PublicKey(pk))
    }

    fn from_der(der: &[u8]) -> Result<Self, Error> {
        let pk = x25519::PublicKey::from_der(der).map_err(|_| JWTError::InvalidPublicKey)?;
        Self::from_bytes(&pk[..])
    }

    fn from_pem(pem: &str) -> Result<Self, Error> {
        let pk = x25519::PublicKey::from_pem(pem).map_err(|_| JWTError::InvalidPublicKey)?;
        Self::from_bytes(&pk[..])
    }

    fn from_jwk(jwk: &str, mode: Mode) -> Result<(Self, Option<String>), Error> {
        let jwk = Jwk::parse(jwk, &mode.descriptor(KeyRole::AgreementPublic))?;
        let pk = checked_jwk_public_key(&jwk, JWTError::InvalidPublicKey)?;
        Ok((X25519PublicKey(pk), jwk.kid().map(Into::into)))
    }

    /// Apply the recipient key checks to the token's ephemeral key too.
    fn from_epk(epk: &serde_json::Value, mode: Mode) -> Result<Self, Error> {
        let descriptor = mode.descriptor(KeyRole::AgreementPublic);
        let jwk = Jwk::from_value(epk, &descriptor).map_err(|_| JWTError::InvalidEphemeralKey)?;
        let pk = checked_jwk_public_key(&jwk, JWTError::InvalidEphemeralKey)?;
        Ok(X25519PublicKey(pk))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn to_der(&self) -> Vec<u8> {
        self.0.to_der()
    }

    fn to_pem(&self) -> String {
        self.0.to_pem()
    }

    fn to_jwk(&self, mode: Mode, key_id: Option<&str>) -> String {
        okp_export(
            &mode.descriptor(KeyRole::AgreementPublic),
            &self.0[..],
            None,
            key_id,
        )
    }

    fn jwk_thumbprint(&self) -> String {
        okp_thumbprint("X25519", &self.0[..])
    }

    fn encrypt<CustomClaims: Serialize>(
        &self,
        mode: Mode,
        key_id: Option<&String>,
        claims: JWTClaims<CustomClaims>,
        options: &EncryptionOptions,
    ) -> Result<String, Error> {
        let content_encryption = options.content_encryption;

        let ephemeral = x25519::KeyPair::generate();
        let shared_secret = self
            .0
            .dh(&ephemeral.sk)
            .map_err(|_| JWTError::InvalidPublicKey)?;

        let mut header = JWEHeader::new(mode.alg(), content_encryption.alg_name());
        header.ephemeral_public_key = Some(json!({
            "kty": "OKP",
            "crv": "X25519",
            "x": encode(&ephemeral.pk[..]),
        }));
        if let Some(key_id) = key_id {
            header.key_id = Some(key_id.clone());
        }
        if let Some(key_id) = &options.key_id {
            header.key_id = Some(key_id.clone());
        }
        if let Some(cty) = &options.content_type {
            header.content_type = Some(cty.clone());
        }

        let kek = derive_kek(&shared_secret[..], mode.key_wrap_size(), &header)?;
        JWEToken::build_from_claims(&header, &claims, content_encryption, |cek| {
            mode.wrap_key(&kek, cek)
        })
    }
}

/// Preserve imported secret bytes so exports return the original key.
#[derive(Clone)]
struct X25519SecretKey {
    sk: x25519::SecretKey,
    pk: x25519::PublicKey,
}

impl X25519SecretKey {
    fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let sk = x25519::SecretKey::from_slice(raw).map_err(|_| JWTError::InvalidKeyPair)?;
        Self::from_secret_key(sk)
    }

    fn from_der(der: &[u8]) -> Result<Self, Error> {
        let sk = x25519::SecretKey::from_der(der).map_err(|_| JWTError::InvalidKeyPair)?;
        Self::from_secret_key(sk)
    }

    fn from_pem(pem: &str) -> Result<Self, Error> {
        let sk = x25519::SecretKey::from_pem(pem).map_err(|_| JWTError::InvalidKeyPair)?;
        Self::from_secret_key(sk)
    }

    fn from_secret_key(sk: x25519::SecretKey) -> Result<Self, Error> {
        let pk = sk
            .recover_public_key()
            .map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(X25519SecretKey { sk, pk })
    }

    fn from_jwk(jwk: &str, mode: Mode) -> Result<(Self, Option<String>), Error> {
        let jwk = Jwk::parse(jwk, &mode.descriptor(KeyRole::AgreementPrivate))?;
        let d = decode_secret(jwk.d(), x25519::SecretKey::BYTES).ok_or(JWTError::InvalidKeyPair)?;
        let sk = Self::from_bytes(&d)?;
        ensure!(
            is_encoding_of(jwk.x(), &sk.pk[..]),
            JWTError::InvalidKeyPair
        );
        Ok((sk, jwk.kid().map(Into::into)))
    }

    fn generate() -> Self {
        let kp = x25519::KeyPair::generate();
        X25519SecretKey {
            sk: kp.sk,
            pk: kp.pk,
        }
    }

    fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey(self.pk)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.sk.to_vec()
    }

    fn to_der(&self) -> Vec<u8> {
        self.sk.to_der()
    }

    fn to_pem(&self) -> String {
        self.sk.to_pem()
    }

    fn to_jwk(&self, mode: Mode, key_id: Option<&str>) -> String {
        okp_export(
            &mode.descriptor(KeyRole::AgreementPrivate),
            &self.pk[..],
            Some(&self.sk[..]),
            key_id,
        )
    }

    fn decrypt<CustomClaims: DeserializeOwned>(
        &self,
        mode: Mode,
        token: &str,
        options: Option<DecryptionOptions>,
    ) -> Result<JWTClaims<CustomClaims>, Error> {
        JWEToken::decrypt(mode.alg(), token, options, |header, encrypted_key| {
            let epk = header
                .ephemeral_public_key
                .as_ref()
                .ok_or(JWTError::MissingEphemeralKey)?;
            let ephemeral_pk = X25519PublicKey::from_epk(epk, mode)?;
            let shared_secret = ephemeral_pk
                .0
                .dh(&self.sk)
                .map_err(|_| JWTError::InvalidEphemeralKey)?;
            let kek = derive_kek(&shared_secret[..], mode.key_wrap_size(), header)?;
            mode.unwrap_key(&kek, encrypted_key)
        })
    }
}

/// X25519 public key for ECDH-ES+A256KW encryption.
#[derive(Debug, Clone)]
pub struct X25519EcdhEsA256KWEncryptionKey {
    pk: X25519PublicKey,
    key_id: Option<String>,
}

impl X25519EcdhEsA256KWEncryptionKey {
    const MODE: Mode = Mode::A256KW;

    /// Create from the raw 32-byte public key.
    ///
    /// The top bit must be clear and the value below 2^255 - 19.
    /// Small-order points are rejected.
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(X25519EcdhEsA256KWEncryptionKey {
            pk: X25519PublicKey::from_bytes(raw)?,
            key_id: None,
        })
    }

    /// Create from a DER-encoded public key (SubjectPublicKeyInfo), with the same checks
    /// as `from_bytes()`.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(X25519EcdhEsA256KWEncryptionKey {
            pk: X25519PublicKey::from_der(der)?,
            key_id: None,
        })
    }

    /// Create from a PEM-encoded public key, with the same checks as `from_bytes()`.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(X25519EcdhEsA256KWEncryptionKey {
            pk: X25519PublicKey::from_pem(pem)?,
            key_id: None,
        })
    }

    /// Import a public key from a JWK (`kty: OKP`, `crv: X25519`), with the same checks as
    /// `from_bytes()`.
    ///
    /// See [strict JWK validation](crate#strict-jwk-validation) for the rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let (pk, key_id) = X25519PublicKey::from_jwk(jwk, Self::MODE)?;
        Ok(X25519EcdhEsA256KWEncryptionKey { pk, key_id })
    }

    /// Export as the raw 32-byte public key.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.pk.to_bytes()
    }

    /// Export as DER.
    pub fn to_der(&self) -> Vec<u8> {
        self.pk.to_der()
    }

    /// Export as PEM.
    pub fn to_pem(&self) -> String {
        self.pk.to_pem()
    }

    /// Export as a JWK, with `alg: ECDH-ES+A256KW` and `use: enc`.
    pub fn to_jwk(&self) -> String {
        self.pk.to_jwk(Self::MODE, self.key_id.as_deref())
    }

    /// The JWK thumbprint of the key.
    pub fn jwk_thumbprint(&self) -> String {
        self.pk.jwk_thumbprint()
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
        self.encrypt_with_options(claims, &EncryptionOptions::default())
    }

    /// Encrypt claims into a JWE token with options.
    pub fn encrypt_with_options<CustomClaims: Serialize>(
        &self,
        claims: JWTClaims<CustomClaims>,
        options: &EncryptionOptions,
    ) -> Result<String, Error> {
        self.pk
            .encrypt(Self::MODE, self.key_id.as_ref(), claims, options)
    }
}

/// X25519 secret key for ECDH-ES+A256KW decryption.
#[derive(Clone)]
pub struct X25519EcdhEsA256KWDecryptionKey {
    sk: X25519SecretKey,
    key_id: Option<String>,
}

impl std::fmt::Debug for X25519EcdhEsA256KWDecryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519EcdhEsA256KWDecryptionKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl X25519EcdhEsA256KWDecryptionKey {
    const MODE: Mode = Mode::A256KW;

    /// Create from the raw 32-byte secret key, which is kept as is.
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(X25519EcdhEsA256KWDecryptionKey {
            sk: X25519SecretKey::from_bytes(raw)?,
            key_id: None,
        })
    }

    /// Create from a DER-encoded private key (PKCS#8 version 0).
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(X25519EcdhEsA256KWDecryptionKey {
            sk: X25519SecretKey::from_der(der)?,
            key_id: None,
        })
    }

    /// Create from a PEM-encoded private key (PKCS#8 version 0).
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(X25519EcdhEsA256KWDecryptionKey {
            sk: X25519SecretKey::from_pem(pem)?,
            key_id: None,
        })
    }

    /// Import a key pair from a private JWK (`kty: OKP`, `crv: X25519`).
    ///
    /// See [strict JWK validation](crate#strict-jwk-validation) for the rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let (sk, key_id) = X25519SecretKey::from_jwk(jwk, Self::MODE)?;
        Ok(X25519EcdhEsA256KWDecryptionKey { sk, key_id })
    }

    /// Generate a new key pair.
    pub fn generate() -> Self {
        X25519EcdhEsA256KWDecryptionKey {
            sk: X25519SecretKey::generate(),
            key_id: None,
        }
    }

    /// Export the secret key as raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.sk.to_bytes()
    }

    /// Export the secret key as DER.
    pub fn to_der(&self) -> Vec<u8> {
        self.sk.to_der()
    }

    /// Export the secret key as PEM.
    pub fn to_pem(&self) -> String {
        self.sk.to_pem()
    }

    /// Export the key pair as a JWK, private key included.
    /// Use `encryption_key().to_jwk()` to share the public key.
    pub fn to_jwk(&self) -> String {
        self.sk.to_jwk(Self::MODE, self.key_id.as_deref())
    }

    /// The JWK thumbprint of the public key.
    pub fn jwk_thumbprint(&self) -> String {
        self.encryption_key().jwk_thumbprint()
    }

    /// Get the public encryption key.
    pub fn encryption_key(&self) -> X25519EcdhEsA256KWEncryptionKey {
        X25519EcdhEsA256KWEncryptionKey {
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
    /// Anyone with the public key can create a token with any claims.
    /// Verify a separate signature before trusting the sender.
    pub fn decrypt_token<CustomClaims: DeserializeOwned>(
        &self,
        token: &str,
        options: Option<DecryptionOptions>,
    ) -> Result<JWTClaims<CustomClaims>, Error> {
        self.sk.decrypt(Self::MODE, token, options)
    }

    /// Decode token metadata without decrypting.
    pub fn decode_metadata(token: &str) -> Result<JWETokenMetadata, Error> {
        JWEToken::decode_metadata(token)
    }
}

/// X25519 public key for ECDH-ES+A128KW encryption.
#[derive(Debug, Clone)]
pub struct X25519EcdhEsA128KWEncryptionKey {
    pk: X25519PublicKey,
    key_id: Option<String>,
}

impl X25519EcdhEsA128KWEncryptionKey {
    const MODE: Mode = Mode::A128KW;

    /// Create from the raw 32-byte public key.
    ///
    /// The top bit must be clear and the value below 2^255 - 19.
    /// Small-order points are rejected.
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(X25519EcdhEsA128KWEncryptionKey {
            pk: X25519PublicKey::from_bytes(raw)?,
            key_id: None,
        })
    }

    /// Create from a DER-encoded public key (SubjectPublicKeyInfo), with the same checks
    /// as `from_bytes()`.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(X25519EcdhEsA128KWEncryptionKey {
            pk: X25519PublicKey::from_der(der)?,
            key_id: None,
        })
    }

    /// Create from a PEM-encoded public key, with the same checks as `from_bytes()`.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(X25519EcdhEsA128KWEncryptionKey {
            pk: X25519PublicKey::from_pem(pem)?,
            key_id: None,
        })
    }

    /// Import a public key from a JWK (`kty: OKP`, `crv: X25519`), with the same checks as
    /// `from_bytes()`.
    ///
    /// See [strict JWK validation](crate#strict-jwk-validation) for the rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let (pk, key_id) = X25519PublicKey::from_jwk(jwk, Self::MODE)?;
        Ok(X25519EcdhEsA128KWEncryptionKey { pk, key_id })
    }

    /// Export as the raw 32-byte public key.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.pk.to_bytes()
    }

    /// Export as DER.
    pub fn to_der(&self) -> Vec<u8> {
        self.pk.to_der()
    }

    /// Export as PEM.
    pub fn to_pem(&self) -> String {
        self.pk.to_pem()
    }

    /// Export as a JWK, with `alg: ECDH-ES+A128KW` and `use: enc`.
    pub fn to_jwk(&self) -> String {
        self.pk.to_jwk(Self::MODE, self.key_id.as_deref())
    }

    /// The JWK thumbprint of the key.
    pub fn jwk_thumbprint(&self) -> String {
        self.pk.jwk_thumbprint()
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
        self.encrypt_with_options(claims, &EncryptionOptions::default())
    }

    /// Encrypt claims into a JWE token with options.
    pub fn encrypt_with_options<CustomClaims: Serialize>(
        &self,
        claims: JWTClaims<CustomClaims>,
        options: &EncryptionOptions,
    ) -> Result<String, Error> {
        self.pk
            .encrypt(Self::MODE, self.key_id.as_ref(), claims, options)
    }
}

/// X25519 secret key for ECDH-ES+A128KW decryption.
#[derive(Clone)]
pub struct X25519EcdhEsA128KWDecryptionKey {
    sk: X25519SecretKey,
    key_id: Option<String>,
}

impl std::fmt::Debug for X25519EcdhEsA128KWDecryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519EcdhEsA128KWDecryptionKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl X25519EcdhEsA128KWDecryptionKey {
    const MODE: Mode = Mode::A128KW;

    /// Create from the raw 32-byte secret key, which is kept as is.
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(X25519EcdhEsA128KWDecryptionKey {
            sk: X25519SecretKey::from_bytes(raw)?,
            key_id: None,
        })
    }

    /// Create from a DER-encoded private key (PKCS#8 version 0).
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(X25519EcdhEsA128KWDecryptionKey {
            sk: X25519SecretKey::from_der(der)?,
            key_id: None,
        })
    }

    /// Create from a PEM-encoded private key (PKCS#8 version 0).
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(X25519EcdhEsA128KWDecryptionKey {
            sk: X25519SecretKey::from_pem(pem)?,
            key_id: None,
        })
    }

    /// Import a key pair from a private JWK (`kty: OKP`, `crv: X25519`).
    ///
    /// See [strict JWK validation](crate#strict-jwk-validation) for the rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let (sk, key_id) = X25519SecretKey::from_jwk(jwk, Self::MODE)?;
        Ok(X25519EcdhEsA128KWDecryptionKey { sk, key_id })
    }

    /// Generate a new key pair.
    pub fn generate() -> Self {
        X25519EcdhEsA128KWDecryptionKey {
            sk: X25519SecretKey::generate(),
            key_id: None,
        }
    }

    /// Export the secret key as raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.sk.to_bytes()
    }

    /// Export the secret key as DER.
    pub fn to_der(&self) -> Vec<u8> {
        self.sk.to_der()
    }

    /// Export the secret key as PEM.
    pub fn to_pem(&self) -> String {
        self.sk.to_pem()
    }

    /// Export the key pair as a JWK, private key included.
    /// Use `encryption_key().to_jwk()` to share the public key.
    pub fn to_jwk(&self) -> String {
        self.sk.to_jwk(Self::MODE, self.key_id.as_deref())
    }

    /// The JWK thumbprint of the public key.
    pub fn jwk_thumbprint(&self) -> String {
        self.encryption_key().jwk_thumbprint()
    }

    /// Get the public encryption key.
    pub fn encryption_key(&self) -> X25519EcdhEsA128KWEncryptionKey {
        X25519EcdhEsA128KWEncryptionKey {
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
    /// Anyone with the public key can create a token with any claims.
    /// Verify a separate signature before trusting the sender.
    pub fn decrypt_token<CustomClaims: DeserializeOwned>(
        &self,
        token: &str,
        options: Option<DecryptionOptions>,
    ) -> Result<JWTClaims<CustomClaims>, Error> {
        self.sk.decrypt(Self::MODE, token, options)
    }

    /// Decode token metadata without decrypting.
    pub fn decode_metadata(token: &str) -> Result<JWETokenMetadata, Error> {
        JWEToken::decode_metadata(token)
    }
}

#[cfg(test)]
mod tests {
    use ct_codecs::{Decoder, Hex};

    use super::*;
    use crate::algorithms::jwk_test_vectors;
    use crate::algorithms::test_util::{b64, error_of, pem, with_epk, with_header_change};
    use crate::claims::NoCustomClaims;

    const BOB_SK: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const BOB_PK: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const ALICE_SK: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const ALICE_PK: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const SHARED: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    // All five weak public key values below p.
    const SMALL_ORDER: [&str; 5] = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];

    // p, p + 1 and 2^255 - 1: values that aren't reduced modulo p.
    const NOT_REDUCED: [&str; 3] = [
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];

    const SPKI_PREFIX: [u8; 12] = [48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0];

    fn hex(s: &str) -> Vec<u8> {
        Hex::decode_to_vec(s, None).unwrap()
    }

    // Tokens for Bob's key, with apu "Alice" and apv "Bob".
    // Generated with jwcrypto 1.5.6 and jose 6.2.12 (Node.js v26.10.0).
    // Each tool also decrypted its own tokens.
    const JWCRYPTO_A128KW: &str = concat!(
        "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImFwdSI6IlFXeHBZMlUiLCJhcHYiOiJRbTlpIiwiZW5jIjoiQTEyOEdDTS",
        "IsImVwayI6eyJjcnYiOiJYMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiZDgzU1lBYWUzWTVWcVhHcDduakdNNlVad1Yx",
        "MkMtaElDdlgtSElvWXJVYyJ9fQ.8zW7Ue1cQceRC1JGno1CAad68C8nmt-O.IBUoPFY2rAVL4Re-.ziqL8md9j1hpu",
        "HMZok16yrsJm9UPzomuW8iOtC6F6wt0SeoQ8Q7czFNFQec._uj5W0cOpP0EYQ0YFsiaoA",
    );
    const JWCRYPTO_A256KW: &str = concat!(
        "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImFwdSI6IlFXeHBZMlUiLCJhcHYiOiJRbTlpIiwiZW5jIjoiQTI1NkdDTS",
        "IsImVwayI6eyJjcnYiOiJYMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiQTdERUVEeUp2MVdhZTJKODhGMTFHX1JhXzhK",
        "SVhhMldjdUZFTlM1NlNRRSJ9fQ.N0DRywkAEF8VDRc4JN75C4PFyMOulVikDXmIsG-pe09xPOK-z-kGsw.rik__TKX",
        "ndiB0Yfb.chUR0ETH8st2HAT2GE8BR3nBI51G5wgl1TMqY2Vfqg9uI9NTZhZARNoVY9Q.Erh2dLSztvteugQgCU-ec",
        "w",
    );
    const JOSE_A128KW: &str = concat!(
        "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhHQ00iLCJlcGsiOnsieCI6Im9MOUhnSlIyTzN6WWRzaX",
        "o0M3FYTGJiVUc0bFZKRkhhUWNFWlN1LWVHSEUiLCJjcnYiOiJYMjU1MTkiLCJrdHkiOiJPS1AifSwiYXB1IjoiUVd4",
        "cFkyVSIsImFwdiI6IlFtOWkifQ.NgZNyh9WXR67e9CmpD1BKwSJsglg_1ZF.J2jtQGSjlBGLmm1P.1lTjmlPBKv3Zd",
        "I0AUnqPIZDhXaiTe4kE4kyZ1Z3epTxTFU0OKA.XUzES6koISTnqOrEGT_ALA",
    );
    const JOSE_A256KW: &str = concat!(
        "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsieCI6IkNJb3BwemVEV1Z2WV9NNn",
        "N4Rmo3MjRIUEVQVnZPd2trRkRCWWVrNXVFQWsiLCJjcnYiOiJYMjU1MTkiLCJrdHkiOiJPS1AifSwiYXB1IjoiUVd4",
        "cFkyVSIsImFwdiI6IlFtOWkifQ.ft0Fj2OmPDUeRZif3Bi-s2qDHZOtCR-qu9CgzRXJKNr3Kfi2nShPYg.Qep0cjfj",
        "n_OT95a9.ruPJfHq4IvCnjzeVYBgUS_YRlyvDGQ_6Ey6p45J9GJ4kAkE23Q.0Of3t_-m-nPLReoba4sSXg",
    );

    #[test]
    fn decrypts_independent_fixtures() {
        let a128kw = X25519EcdhEsA128KWDecryptionKey::from_bytes(&hex(BOB_SK)).unwrap();
        let a256kw = X25519EcdhEsA256KWDecryptionKey::from_bytes(&hex(BOB_SK)).unwrap();
        for (token, issuer) in [(JWCRYPTO_A128KW, "jwcrypto"), (JOSE_A128KW, "jose")] {
            let claims = a128kw.decrypt_token::<NoCustomClaims>(token, None).unwrap();
            assert_eq!(claims.issuer.as_deref(), Some(issuer));
        }
        for (token, issuer) in [(JWCRYPTO_A256KW, "jwcrypto"), (JOSE_A256KW, "jose")] {
            let claims = a256kw.decrypt_token::<NoCustomClaims>(token, None).unwrap();
            assert_eq!(claims.issuer.as_deref(), Some(issuer));
        }

        // Key unwrapping must fail before the changed header causes a tag mismatch.
        let tampered = with_header_change(JWCRYPTO_A256KW, |header| header["apv"] = "Qm9j".into());
        assert!(matches!(
            error_of(a256kw.decrypt_token::<NoCustomClaims>(&tampered, None)),
            JWTError::KeyUnwrapFailed
        ));
    }

    #[test]
    fn matches_rfc8037_appendix_a6() {
        let key = X25519EcdhEsA128KWDecryptionKey::from_bytes(&hex(BOB_SK))
            .unwrap()
            .with_key_id("Bob");
        assert_eq!(key.encryption_key().to_bytes(), hex(BOB_PK));
        let jwk: serde_json::Value = serde_json::from_str(&key.encryption_key().to_jwk()).unwrap();
        assert_eq!(jwk["x"], "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08");
        assert_eq!(jwk["kid"], "Bob");

        // The vector stops at the shared secret, before any key derivation.
        let ephemeral = X25519PublicKey::from_bytes(&hex(ALICE_PK)).unwrap();
        let shared = ephemeral.0.dh(&key.sk.sk).unwrap();
        assert_eq!(&shared[..], &hex(SHARED)[..]);
        let alice = X25519SecretKey::from_bytes(&hex(ALICE_SK)).unwrap();
        assert_eq!(alice.public_key().to_bytes(), hex(ALICE_PK));
        let bob = X25519PublicKey::from_bytes(&hex(BOB_PK)).unwrap();
        assert_eq!(&bob.0.dh(&alice.sk).unwrap()[..], &hex(SHARED)[..]);
    }

    #[test]
    fn weak_and_non_canonical_public_keys_are_rejected_everywhere() {
        let valid = hex(BOB_PK);
        assert!(X25519EcdhEsA256KWEncryptionKey::from_bytes(&valid[..31]).is_err());
        let mut high_bit = valid;
        high_bit[31] |= 0x80;
        let rejected: Vec<Vec<u8>> = SMALL_ORDER
            .iter()
            .chain(NOT_REDUCED.iter())
            .map(|u| hex(u))
            .chain(std::iter::once(high_bit))
            .chain(SMALL_ORDER.iter().map(|u| {
                let mut u = hex(u);
                u[31] |= 0x80;
                u
            }))
            .collect();

        for raw in &rejected {
            let der = [&SPKI_PREFIX[..], raw].concat();
            let jwk = format!(r#"{{"kty":"OKP","crv":"X25519","x":"{}"}}"#, b64(raw));
            for res in [
                X25519EcdhEsA256KWEncryptionKey::from_bytes(raw),
                X25519EcdhEsA256KWEncryptionKey::from_der(&der),
                X25519EcdhEsA256KWEncryptionKey::from_pem(&pem("PUBLIC KEY", &der)),
                X25519EcdhEsA256KWEncryptionKey::from_jwk(&jwk),
            ] {
                assert!(matches!(error_of(res), JWTError::InvalidPublicKey));
            }
            assert!(X25519EcdhEsA128KWEncryptionKey::from_bytes(raw).is_err());
        }

        // Key agreement must reject weak keys even if import checks are bypassed.
        let sk = x25519::SecretKey::from_slice(&hex(BOB_SK)).unwrap();
        for u in SMALL_ORDER {
            let pk = x25519::PublicKey::from_slice(&hex(u)).unwrap();
            assert!(pk.dh(&sk).is_err());
        }
    }

    #[test]
    fn weak_and_malformed_ephemeral_keys_are_rejected() {
        let key = X25519EcdhEsA256KWDecryptionKey::generate();
        let token = key
            .encrypt(Claims::create(coarsetime::Duration::from_hours(1)))
            .unwrap();
        let metadata = X25519EcdhEsA256KWDecryptionKey::decode_metadata(&token).unwrap();
        let x = metadata.header().ephemeral_public_key.as_ref().unwrap()["x"]
            .as_str()
            .unwrap()
            .to_string();
        let mut high_bit = key.encryption_key().to_bytes();
        high_bit[31] |= 0x80;
        let other = X25519EcdhEsA256KWDecryptionKey::generate().to_jwk();
        let other: serde_json::Value = serde_json::from_str(&other).unwrap();

        let mut rejected: Vec<String> = SMALL_ORDER
            .iter()
            .chain(NOT_REDUCED.iter())
            .map(|u| hex(u))
            .chain(std::iter::once(high_bit))
            .map(|raw| format!(r#"{{"kty":"OKP","crv":"X25519","x":"{}"}}"#, b64(&raw)))
            .collect();
        rejected.extend([
            format!(
                r#"{{"kty":"OKP","crv":"X25519","x":"{}","d":{}}}"#,
                x, other["d"]
            ),
            format!(r#"{{"kty":"OKP","crv":"X25519","x":"{}","d":null}}"#, x),
            format!(r#"{{"kty":"OKP","crv":"X25519","x":"{}","y":"{}"}}"#, x, x),
            format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#, x),
            format!(r#"{{"kty":"EC","crv":"X25519","x":"{}"}}"#, x),
            format!(
                r#"{{"kty":"OKP","crv":"X25519","x":"{}","alg":"ECDH-ES+A128KW"}}"#,
                x
            ),
            format!(r#"{{"kty":"OKP","crv":"X25519","x":"{}","use":"sig"}}"#, x),
            format!(r#"{{"kty":"OKP","crv":"X25519","x":"{}="}}"#, x),
            format!(r#"{{"kty":"OKP","crv":"X25519","x":"{}"}}"#, &x[..42]),
            r#"{"kty":"OKP","crv":"X25519"}"#.to_string(),
        ]);
        for epk in &rejected {
            assert!(
                matches!(
                    error_of(key.decrypt_token::<NoCustomClaims>(&with_epk(&token, epk), None)),
                    JWTError::InvalidEphemeralKey
                ),
                "{}",
                epk
            );
        }
        for epk in [
            format!(r#"{{"kty":"OKP","crv":"X25519","x":"{0}","x":"{0}"}}"#, x),
            format!(
                r#"{{"kty":"OKP","crv":"X25519","x":"{0}","\u0078":"{0}"}}"#,
                x
            ),
        ] {
            let tampered = with_epk(&token, &epk);
            let err = key
                .decrypt_token::<NoCustomClaims>(&tampered, None)
                .unwrap_err();
            assert!(err.downcast_ref::<serde_json::Error>().is_some());
            assert!(X25519EcdhEsA256KWDecryptionKey::decode_metadata(&tampered).is_err());
        }
    }

    #[test]
    fn round_trips_with_every_mode_and_content_encryption() {
        use crate::algorithms::jwe::content::ContentEncryption;

        for content_encryption in [ContentEncryption::A128GCM, ContentEncryption::A256GCM] {
            let options = EncryptionOptions {
                content_encryption,
                key_id: Some("from options".into()),
                content_type: Some("JWT".into()),
            };
            let key = X25519EcdhEsA256KWDecryptionKey::generate().with_key_id("recipient");
            let token = key
                .encryption_key()
                .encrypt_with_options(
                    Claims::create(coarsetime::Duration::from_hours(1)).with_issuer("me"),
                    &options,
                )
                .unwrap();
            let metadata = X25519EcdhEsA256KWDecryptionKey::decode_metadata(&token).unwrap();
            assert_eq!(metadata.algorithm(), "ECDH-ES+A256KW");
            assert_eq!(metadata.encryption(), content_encryption.alg_name());
            assert_eq!(metadata.key_id(), Some("from options"));
            assert_eq!(metadata.content_type(), Some("JWT"));
            let epk = metadata.header().ephemeral_public_key.as_ref().unwrap();
            assert_eq!(epk.as_object().unwrap().len(), 3);
            assert!(metadata.header().apu.is_none() && metadata.header().apv.is_none());
            let claims = key.decrypt_token::<NoCustomClaims>(&token, None).unwrap();
            assert_eq!(claims.issuer.as_deref(), Some("me"));

            let key = X25519EcdhEsA128KWDecryptionKey::generate().with_key_id("recipient");
            let token = key
                .encryption_key()
                .encrypt_with_options(
                    Claims::create(coarsetime::Duration::from_hours(1)),
                    &options,
                )
                .unwrap();
            let metadata = X25519EcdhEsA128KWDecryptionKey::decode_metadata(&token).unwrap();
            assert_eq!(metadata.algorithm(), "ECDH-ES+A128KW");
            key.decrypt_token::<NoCustomClaims>(&token, None).unwrap();

            let other = X25519EcdhEsA256KWDecryptionKey::from_bytes(&key.to_bytes()).unwrap();
            assert!(matches!(
                error_of(other.decrypt_token::<NoCustomClaims>(&token, None)),
                JWTError::AlgorithmMismatch
            ));
        }

        let key = X25519EcdhEsA128KWDecryptionKey::generate();
        let epk = |token: &str| {
            X25519EcdhEsA128KWDecryptionKey::decode_metadata(token)
                .unwrap()
                .header()
                .ephemeral_public_key
                .clone()
        };
        let claims = || Claims::create(coarsetime::Duration::from_hours(1));
        assert_ne!(
            epk(&key.encrypt(claims()).unwrap()),
            epk(&key.encrypt(claims()).unwrap())
        );
    }

    #[test]
    fn key_formats_round_trip_the_unclamped_scalar() {
        // Keep the bits that key agreement ignores.
        let mut raw = hex(BOB_SK);
        raw[0] |= 7;
        raw[31] |= 0x80;
        let key = X25519EcdhEsA256KWDecryptionKey::from_bytes(&raw)
            .unwrap()
            .with_key_id("k");
        assert_eq!(key.to_bytes(), raw);
        let from_der = X25519EcdhEsA256KWDecryptionKey::from_der(&key.to_der()).unwrap();
        let from_pem = X25519EcdhEsA256KWDecryptionKey::from_pem(&key.to_pem()).unwrap();
        let from_jwk = X25519EcdhEsA256KWDecryptionKey::from_jwk(&key.to_jwk()).unwrap();
        for restored in [&from_der, &from_pem, &from_jwk] {
            assert_eq!(restored.to_bytes(), raw);
            assert_eq!(restored.jwk_thumbprint(), key.jwk_thumbprint());
        }
        assert_eq!(from_jwk.key_id(), Some("k"));
        assert_eq!(from_jwk.to_jwk(), key.to_jwk());

        let public = key.encryption_key();
        for restored in [
            X25519EcdhEsA256KWEncryptionKey::from_bytes(&public.to_bytes()).unwrap(),
            X25519EcdhEsA256KWEncryptionKey::from_der(&public.to_der()).unwrap(),
            X25519EcdhEsA256KWEncryptionKey::from_pem(&public.to_pem()).unwrap(),
            X25519EcdhEsA256KWEncryptionKey::from_jwk(&public.to_jwk()).unwrap(),
        ] {
            assert_eq!(restored.to_bytes(), public.to_bytes());
        }

        let token = public
            .encrypt(Claims::create(coarsetime::Duration::from_hours(1)))
            .unwrap();
        from_pem
            .decrypt_token::<NoCustomClaims>(&token, None)
            .unwrap();

        let exported: serde_json::Value = serde_json::from_str(&public.to_jwk()).unwrap();
        assert_eq!(exported["alg"], "ECDH-ES+A256KW");
        assert_eq!(exported["use"], "enc");
        assert!(exported.get("d").is_none());

        assert_eq!(
            format!("{:?}", key),
            r#"X25519EcdhEsA256KWDecryptionKey { key_id: Some("k"), .. }"#
        );
    }

    #[test]
    fn private_jwk_must_be_consistent() {
        let key = X25519EcdhEsA128KWDecryptionKey::from_bytes(&hex(BOB_SK)).unwrap();
        let jwk = key.to_jwk();
        let other = X25519EcdhEsA128KWDecryptionKey::generate().to_jwk();
        let other: serde_json::Value = serde_json::from_str(&other).unwrap();
        let mut high_bit = hex(BOB_PK);
        high_bit[31] |= 0x80;
        for (name, value) in [
            ("x", other["x"].clone()),
            ("d", other["d"].clone()),
            ("x", b64(&high_bit).into()),
            ("d", b64(&hex(BOB_SK)[..31]).into()),
            ("x", serde_json::Value::Null),
        ] {
            let mut tampered: serde_json::Value = serde_json::from_str(&jwk).unwrap();
            tampered[name] = value;
            assert!(
                matches!(
                    error_of(X25519EcdhEsA128KWDecryptionKey::from_jwk(
                        &tampered.to_string()
                    )),
                    JWTError::InvalidKeyPair
                ),
                "{}",
                tampered
            );
        }
    }

    #[test]
    fn keys_only_load_into_their_own_type() {
        let key = X25519EcdhEsA256KWDecryptionKey::generate();
        let public_jwk = key.encryption_key().to_jwk();
        assert!(X25519EcdhEsA256KWEncryptionKey::from_jwk(&key.to_jwk()).is_err());
        assert!(X25519EcdhEsA128KWEncryptionKey::from_jwk(&public_jwk).is_err());
        assert!(X25519EcdhEsA128KWDecryptionKey::from_jwk(&key.to_jwk()).is_err());
        assert!(crate::algorithms::Ed25519PublicKey::from_jwk(&public_jwk).is_err());

        let ed25519 = crate::algorithms::Ed25519KeyPair::generate();
        assert!(X25519EcdhEsA256KWEncryptionKey::from_jwk(&ed25519.public_key().to_jwk()).is_err());
        let p256 = crate::algorithms::jwe::EcdhEsA256KWDecryptionKey::generate();
        assert!(
            X25519EcdhEsA256KWEncryptionKey::from_jwk(&p256.encryption_key().to_jwk()).is_err()
        );
        assert!(crate::algorithms::jwe::EcdhEsA256KWEncryptionKey::from_jwk(&public_jwk).is_err());
    }

    #[test]
    fn webcrypto_and_provider_keys() {
        for export in jwk_test_vectors::ALL {
            let export: serde_json::Value = serde_json::from_str(export).unwrap();
            let entry = &export["keys"]["X25519"];
            let decryption_key =
                X25519EcdhEsA256KWDecryptionKey::from_jwk(&entry["private"].to_string()).unwrap();
            let encryption_key =
                X25519EcdhEsA128KWEncryptionKey::from_jwk(&entry["public"].to_string()).unwrap();
            assert_eq!(
                decryption_key.jwk_thumbprint(),
                encryption_key.jwk_thumbprint()
            );
            let token = decryption_key
                .encrypt(Claims::create(coarsetime::Duration::from_hours(1)))
                .unwrap();
            decryption_key
                .decrypt_token::<NoCustomClaims>(&token, None)
                .unwrap();

            let ed25519 = &export["keys"]["Ed25519"]["public"];
            assert!(X25519EcdhEsA128KWEncryptionKey::from_jwk(&ed25519.to_string()).is_err());
        }

        let paypal: serde_json::Value =
            serde_json::from_str(jwk_test_vectors::PAYPAL_JWKS).unwrap();
        let x25519 = paypal["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|jwk| jwk["crv"] == "X25519")
            .unwrap();
        let key = X25519EcdhEsA256KWEncryptionKey::from_jwk(&x25519.to_string()).unwrap();
        assert_eq!(key.key_id(), x25519["kid"].as_str());
    }
}
