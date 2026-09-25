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
use zeroize::Zeroizing;

use crate::algorithms::jwk::{
    encode, encode_secret, rsa_modulus, rsa_private_integer, rsa_thumbprint, Jwk, JwkDescriptor,
    JwkMembers, KeyRole, KeyType,
};
use crate::claims::*;
use crate::common::*;
#[cfg(feature = "cwt")]
use crate::cwt_token::*;
use crate::error::*;
use crate::jwt_header::*;
use crate::token::*;

pub(crate) const MIN_RSA_MODULUS_BITS: usize = 2048;
pub(crate) const MAX_RSA_MODULUS_BITS: usize = 4096;

fn trim_leading_zeros(x: &[u8]) -> &[u8] {
    let first = x.iter().position(|&b| b != 0).unwrap_or(x.len());
    &x[first..]
}

fn bit_length(x: &[u8]) -> usize {
    let x = trim_leading_zeros(x);
    match x.first() {
        None => 0,
        Some(&top) => (x.len() - 1) * 8 + (8 - top.leading_zeros() as usize),
    }
}

/// Apply the same RSA key limits across formats and backends.
///
/// `n` and `e` are big-endian and may have leading zeros.
pub(crate) fn check_rsa_key_policy(n: &[u8], e: &[u8], invalid: JWTError) -> Result<(), Error> {
    let bits = bit_length(n);
    ensure!(bits >= MIN_RSA_MODULUS_BITS, JWTError::WeakKey);
    ensure!(
        bits <= MAX_RSA_MODULUS_BITS,
        JWTError::UnsupportedRSAModulus
    );
    ensure!(n[n.len() - 1] & 1 == 1, invalid);
    ensure!(trim_leading_zeros(e) == [1, 0, 1], invalid);
    Ok(())
}

pub(crate) fn check_rsa_public_key(rsa_pk: &Rsa<Public>) -> Result<(), Error> {
    check_rsa_key_policy(
        &rsa_pk.n().to_vec(),
        &rsa_pk.e().to_vec(),
        JWTError::InvalidPublicKey,
    )
}

/// Reject unsupported keys before the more expensive key check.
pub(crate) fn check_rsa_private_key(rsa_sk: &Rsa<Private>) -> Result<(), Error> {
    check_rsa_key_policy(
        &rsa_sk.n().to_vec(),
        &rsa_sk.e().to_vec(),
        JWTError::InvalidKeyPair,
    )?;
    check_rsa_private_key_consistency(rsa_sk)
}

/// Require all private values so the key can be exported as a JWK.
fn check_rsa_private_key_consistency(rsa_sk: &Rsa<Private>) -> Result<(), Error> {
    ensure!(
        rsa_sk.check_key().unwrap_or(false),
        JWTError::InvalidKeyPair
    );
    ensure!(
        private_parameters(rsa_sk).is_some(),
        JWTError::InvalidKeyPair
    );
    Ok(())
}

/// Handle private key values from either RSA backend.
trait ParameterBytes {
    fn parameter_bytes(self) -> Option<Vec<u8>>;
}

#[cfg(not(any(feature = "pure-rust", target_arch = "wasm32", target_arch = "wasm64")))]
impl ParameterBytes for &boring::bn::BigNumRef {
    fn parameter_bytes(self) -> Option<Vec<u8>> {
        Some(self.to_vec())
    }
}

#[cfg(not(any(feature = "pure-rust", target_arch = "wasm32", target_arch = "wasm64")))]
impl ParameterBytes for Option<&boring::bn::BigNumRef> {
    fn parameter_bytes(self) -> Option<Vec<u8>> {
        self.map(|x| x.to_vec())
    }
}

#[cfg(any(feature = "pure-rust", target_arch = "wasm32", target_arch = "wasm64"))]
impl ParameterBytes for BigNum {
    fn parameter_bytes(self) -> Option<Vec<u8>> {
        Some(self.to_vec())
    }
}

#[cfg(any(feature = "pure-rust", target_arch = "wasm32", target_arch = "wasm64"))]
impl ParameterBytes for Option<BigNum> {
    fn parameter_bytes(self) -> Option<Vec<u8>> {
        self.map(|x| x.to_vec())
    }
}

fn private_parameters(rsa_sk: &Rsa<Private>) -> Option<[Zeroizing<Vec<u8>>; 6]> {
    Some([
        Zeroizing::new(rsa_sk.d().parameter_bytes()?),
        Zeroizing::new(rsa_sk.p().parameter_bytes()?),
        Zeroizing::new(rsa_sk.q().parameter_bytes()?),
        Zeroizing::new(rsa_sk.dmp1().parameter_bytes()?),
        Zeroizing::new(rsa_sk.dmq1().parameter_bytes()?),
        Zeroizing::new(rsa_sk.iqmp().parameter_bytes()?),
    ])
}

pub(crate) const fn rsa_jwk_descriptor(alg: &'static str, role: KeyRole) -> JwkDescriptor {
    JwkDescriptor::new(KeyType::Rsa, None, alg, role)
}

const RSA_EXPONENT: [u8; 3] = [1, 0, 1];

pub(crate) fn rsa_public_key_from_jwk(
    jwk: &str,
    descriptor: &JwkDescriptor,
) -> Result<(Rsa<Public>, Option<String>), Error> {
    let jwk = Jwk::parse(jwk, descriptor)?;
    let n = rsa_modulus(jwk.n(), descriptor)?;
    ensure!(jwk.e() == "AQAB", descriptor.error());
    check_rsa_key_policy(&n, &RSA_EXPONENT, descriptor.error())?;
    let bn = |x: &[u8]| BigNum::from_slice(x).map_err(|_| descriptor.error());
    let rsa_pk = Rsa::<Public>::from_public_components(bn(&n)?, bn(&RSA_EXPONENT)?)
        .map_err(|_| descriptor.error())?;
    Ok((rsa_pk, jwk.kid().map(Into::into)))
}

/// Reject oversized values before passing them to the RSA backend.
pub(crate) fn rsa_private_key_from_jwk(
    jwk: &str,
    descriptor: &JwkDescriptor,
) -> Result<(Rsa<Private>, Option<String>), Error> {
    let jwk = Jwk::parse(jwk, descriptor)?;
    let n = rsa_modulus(jwk.n(), descriptor)?;
    ensure!(jwk.e() == "AQAB", descriptor.error());
    check_rsa_key_policy(&n, &RSA_EXPONENT, descriptor.error())?;
    let d = rsa_private_integer(jwk.d(), descriptor)?;
    let p = rsa_private_integer(jwk.p(), descriptor)?;
    let q = rsa_private_integer(jwk.q(), descriptor)?;
    let dp = rsa_private_integer(jwk.dp(), descriptor)?;
    let dq = rsa_private_integer(jwk.dq(), descriptor)?;
    let qi = rsa_private_integer(jwk.qi(), descriptor)?;
    let bn = |x: &[u8]| BigNum::from_slice(x).map_err(|_| descriptor.error());
    let rsa_sk = Rsa::<Private>::from_private_components(
        bn(&n)?,
        bn(&RSA_EXPONENT)?,
        bn(&d)?,
        bn(&p)?,
        bn(&q)?,
        bn(&dp)?,
        bn(&dq)?,
        bn(&qi)?,
    )
    .map_err(|_| descriptor.error())?;
    check_rsa_private_key_consistency(&rsa_sk)?;
    Ok((rsa_sk, jwk.kid().map(Into::into)))
}

pub(crate) fn rsa_public_key_to_jwk(
    rsa_pk: &Rsa<Public>,
    descriptor: &JwkDescriptor,
    key_id: Option<&str>,
) -> String {
    let n = encode(&rsa_pk.n().to_vec());
    let e = encode(&rsa_pk.e().to_vec());
    let members = JwkMembers {
        n: Some(&n),
        e: Some(&e),
        ..Default::default()
    };
    descriptor.export(members, key_id)
}

pub(crate) fn rsa_private_key_to_jwk(
    rsa_sk: &Rsa<Private>,
    descriptor: &JwkDescriptor,
    key_id: Option<&str>,
) -> String {
    let parameters = private_parameters(rsa_sk)
        .expect("RSA private keys are checked for CRT parameters when they are constructed");
    let [d, p, q, dp, dq, qi] = parameters.each_ref().map(|x| encode_secret(x));
    let n = encode(&rsa_sk.n().to_vec());
    let e = encode(&rsa_sk.e().to_vec());
    let members = JwkMembers {
        n: Some(&n),
        e: Some(&e),
        d: Some(&d),
        p: Some(&p),
        q: Some(&q),
        dp: Some(&dp),
        dq: Some(&dq),
        qi: Some(&qi),
        ..Default::default()
    };
    descriptor.export(members, key_id)
}

pub(crate) fn rsa_public_key_thumbprint(rsa_pk: &Rsa<Public>) -> String {
    rsa_thumbprint(&rsa_pk.n().to_vec(), &rsa_pk.e().to_vec())
}

pub(crate) fn rsa_private_key_thumbprint(rsa_sk: &Rsa<Private>) -> String {
    rsa_thumbprint(&rsa_sk.n().to_vec(), &rsa_sk.e().to_vec())
}

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
        check_rsa_public_key(&rsa_pk)?;
        Ok(RSAPublicKey(rsa_pk))
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let pem = pem.trim();
        let rsa_pk = Rsa::<Public>::public_key_from_pem(pem.as_bytes())
            .or_else(|_| Rsa::<Public>::public_key_from_pem_pkcs1(pem.as_bytes()))?;
        check_rsa_public_key(&rsa_pk)?;
        Ok(RSAPublicKey(rsa_pk))
    }

    pub fn from_components(n: &[u8], e: &[u8]) -> Result<Self, Error> {
        check_rsa_key_policy(n, e, JWTError::InvalidPublicKey)?;
        let n = BigNum::from_slice(n)?;
        let e = BigNum::from_slice(e)?;
        let rsa_pk = Rsa::<Public>::from_public_components(n, e)?;
        Ok(RSAPublicKey(rsa_pk))
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.0.public_key_to_der().map_err(Into::into)
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        Ok(String::from_utf8(self.0.public_key_to_pem()?)?)
    }

    pub fn to_components(&self) -> RSAPublicKeyComponents {
        RSAPublicKeyComponents {
            n: self.0.n().to_vec(),
            e: self.0.e().to_vec(),
        }
    }

    fn thumbprint(&self, hash: impl Fn(&[u8]) -> Vec<u8>) -> String {
        Base64UrlSafeNoPadding::encode_to_string(hash(&self.to_der().unwrap())).unwrap()
    }
}

#[doc(hidden)]
#[derive(Clone)]
pub struct RSAKeyPair {
    rsa_sk: Rsa<Private>,
    metadata: Option<KeyMetadata>,
}

impl std::fmt::Debug for RSAKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Rsa")
    }
}

impl AsRef<Rsa<Private>> for RSAKeyPair {
    fn as_ref(&self) -> &Rsa<Private> {
        &self.rsa_sk
    }
}

impl RSAKeyPair {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let rsa_sk = Rsa::<Private>::private_key_from_der(der)?;
        check_rsa_private_key(&rsa_sk)?;
        Ok(RSAKeyPair {
            rsa_sk,
            metadata: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let pem = pem.trim();
        let rsa_sk = Rsa::<Private>::private_key_from_pem(pem.as_bytes())?;
        check_rsa_private_key(&rsa_sk)?;
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
        check_rsa_private_key(&rsa_sk)?;
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

    /// Decode CWT token metadata that can be useful prior to signature/tag verification
    #[cfg(feature = "cwt")]
    fn decode_cwt_metadata(&self, token: impl AsRef<[u8]>) -> Result<TokenMetadata, Error> {
        CWTToken::decode_metadata(token)
    }
}

#[derive(Clone)]
pub struct RS256KeyPair {
    key_pair: RSAKeyPair,
    key_id: Option<String>,
}

impl std::fmt::Debug for RS256KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Rsa")
    }
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

    /// Import a key pair from a private RSA JWK.
    ///
    /// The modulus must be 2048 to 4096 bits long, and the exponent 65537.
    /// See [strict JWK validation](crate#strict-jwk-validation) for the other rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePrivate);
        let (rsa_sk, key_id) = rsa_private_key_from_jwk(jwk, &descriptor)?;
        let key_pair = RSAKeyPair {
            rsa_sk,
            metadata: None,
        };
        Ok(RS256KeyPair { key_pair, key_id })
    }

    /// Export the key pair as a JWK, private key included.
    /// Use `public_key().to_jwk()` to share the public key.
    pub fn to_jwk(&self) -> String {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePrivate);
        rsa_private_key_to_jwk(&self.key_pair.rsa_sk, &descriptor, self.key_id.as_deref())
    }

    /// The JWK thumbprint of the public key.
    pub fn jwk_thumbprint(&self) -> String {
        rsa_private_key_thumbprint(&self.key_pair.rsa_sk)
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

    /// Import a public key from an RSA JWK.
    ///
    /// The modulus must be 2048 to 4096 bits long, and the exponent 65537.
    /// See [strict JWK validation](crate#strict-jwk-validation) for the other rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePublic);
        let (rsa_pk, key_id) = rsa_public_key_from_jwk(jwk, &descriptor)?;
        Ok(RS256PublicKey {
            pk: RSAPublicKey(rsa_pk),
            key_id,
        })
    }

    /// Export the public key as a JWK, with `alg: RS256` and `use: sig`.
    pub fn to_jwk(&self) -> String {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePublic);
        rsa_public_key_to_jwk(&self.pk.0, &descriptor, self.key_id.as_deref())
    }

    /// The JWK thumbprint of the key.
    pub fn jwk_thumbprint(&self) -> String {
        rsa_public_key_thumbprint(&self.pk.0)
    }

    pub fn sha1_thumbprint(&self) -> String {
        self.pk.thumbprint(|data| SHA1::hash(data).to_vec())
    }

    pub fn sha256_thumbprint(&self) -> String {
        self.pk.thumbprint(|data| SHA256::hash(data).to_vec())
    }
}

//

#[derive(Clone)]
pub struct RS512KeyPair {
    key_pair: RSAKeyPair,
    key_id: Option<String>,
}

impl std::fmt::Debug for RS512KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Rsa")
    }
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

    /// Import a key pair from a private RSA JWK.
    ///
    /// The modulus must be 2048 to 4096 bits long, and the exponent 65537.
    /// See [strict JWK validation](crate#strict-jwk-validation) for the other rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePrivate);
        let (rsa_sk, key_id) = rsa_private_key_from_jwk(jwk, &descriptor)?;
        let key_pair = RSAKeyPair {
            rsa_sk,
            metadata: None,
        };
        Ok(RS512KeyPair { key_pair, key_id })
    }

    /// Export the key pair as a JWK, private key included.
    /// Use `public_key().to_jwk()` to share the public key.
    pub fn to_jwk(&self) -> String {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePrivate);
        rsa_private_key_to_jwk(&self.key_pair.rsa_sk, &descriptor, self.key_id.as_deref())
    }

    /// The JWK thumbprint of the public key.
    pub fn jwk_thumbprint(&self) -> String {
        rsa_private_key_thumbprint(&self.key_pair.rsa_sk)
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

    /// Import a public key from an RSA JWK.
    ///
    /// The modulus must be 2048 to 4096 bits long, and the exponent 65537.
    /// See [strict JWK validation](crate#strict-jwk-validation) for the other rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePublic);
        let (rsa_pk, key_id) = rsa_public_key_from_jwk(jwk, &descriptor)?;
        Ok(RS512PublicKey {
            pk: RSAPublicKey(rsa_pk),
            key_id,
        })
    }

    /// Export the public key as a JWK, with `alg: RS512` and `use: sig`.
    pub fn to_jwk(&self) -> String {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePublic);
        rsa_public_key_to_jwk(&self.pk.0, &descriptor, self.key_id.as_deref())
    }

    /// The JWK thumbprint of the key.
    pub fn jwk_thumbprint(&self) -> String {
        rsa_public_key_thumbprint(&self.pk.0)
    }

    pub fn sha1_thumbprint(&self) -> String {
        self.pk.thumbprint(|data| SHA1::hash(data).to_vec())
    }

    pub fn sha256_thumbprint(&self) -> String {
        self.pk.thumbprint(|data| SHA256::hash(data).to_vec())
    }
}

//

#[derive(Clone)]
pub struct RS384KeyPair {
    key_pair: RSAKeyPair,
    key_id: Option<String>,
}

impl std::fmt::Debug for RS384KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Rsa")
    }
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

    /// Import a key pair from a private RSA JWK.
    ///
    /// The modulus must be 2048 to 4096 bits long, and the exponent 65537.
    /// See [strict JWK validation](crate#strict-jwk-validation) for the other rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePrivate);
        let (rsa_sk, key_id) = rsa_private_key_from_jwk(jwk, &descriptor)?;
        let key_pair = RSAKeyPair {
            rsa_sk,
            metadata: None,
        };
        Ok(RS384KeyPair { key_pair, key_id })
    }

    /// Export the key pair as a JWK, private key included.
    /// Use `public_key().to_jwk()` to share the public key.
    pub fn to_jwk(&self) -> String {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePrivate);
        rsa_private_key_to_jwk(&self.key_pair.rsa_sk, &descriptor, self.key_id.as_deref())
    }

    /// The JWK thumbprint of the public key.
    pub fn jwk_thumbprint(&self) -> String {
        rsa_private_key_thumbprint(&self.key_pair.rsa_sk)
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

    /// Import a public key from an RSA JWK.
    ///
    /// The modulus must be 2048 to 4096 bits long, and the exponent 65537.
    /// See [strict JWK validation](crate#strict-jwk-validation) for the other rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePublic);
        let (rsa_pk, key_id) = rsa_public_key_from_jwk(jwk, &descriptor)?;
        Ok(RS384PublicKey {
            pk: RSAPublicKey(rsa_pk),
            key_id,
        })
    }

    /// Export the public key as a JWK, with `alg: RS384` and `use: sig`.
    pub fn to_jwk(&self) -> String {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePublic);
        rsa_public_key_to_jwk(&self.pk.0, &descriptor, self.key_id.as_deref())
    }

    /// The JWK thumbprint of the key.
    pub fn jwk_thumbprint(&self) -> String {
        rsa_public_key_thumbprint(&self.pk.0)
    }

    pub fn sha1_thumbprint(&self) -> String {
        self.pk.thumbprint(|data| SHA1::hash(data).to_vec())
    }

    pub fn sha256_thumbprint(&self) -> String {
        self.pk.thumbprint(|data| SHA256::hash(data).to_vec())
    }
}

//

#[derive(Clone)]
pub struct PS256KeyPair {
    key_pair: RSAKeyPair,
    key_id: Option<String>,
}

impl std::fmt::Debug for PS256KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Rsa")
    }
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

    /// Import a key pair from a private RSA JWK.
    ///
    /// The modulus must be 2048 to 4096 bits long, and the exponent 65537.
    /// See [strict JWK validation](crate#strict-jwk-validation) for the other rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePrivate);
        let (rsa_sk, key_id) = rsa_private_key_from_jwk(jwk, &descriptor)?;
        let key_pair = RSAKeyPair {
            rsa_sk,
            metadata: None,
        };
        Ok(PS256KeyPair { key_pair, key_id })
    }

    /// Export the key pair as a JWK, private key included.
    /// Use `public_key().to_jwk()` to share the public key.
    pub fn to_jwk(&self) -> String {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePrivate);
        rsa_private_key_to_jwk(&self.key_pair.rsa_sk, &descriptor, self.key_id.as_deref())
    }

    /// The JWK thumbprint of the public key.
    pub fn jwk_thumbprint(&self) -> String {
        rsa_private_key_thumbprint(&self.key_pair.rsa_sk)
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

    /// Import a public key from an RSA JWK.
    ///
    /// The modulus must be 2048 to 4096 bits long, and the exponent 65537.
    /// See [strict JWK validation](crate#strict-jwk-validation) for the other rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePublic);
        let (rsa_pk, key_id) = rsa_public_key_from_jwk(jwk, &descriptor)?;
        Ok(PS256PublicKey {
            pk: RSAPublicKey(rsa_pk),
            key_id,
        })
    }

    /// Export the public key as a JWK, with `alg: PS256` and `use: sig`.
    pub fn to_jwk(&self) -> String {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePublic);
        rsa_public_key_to_jwk(&self.pk.0, &descriptor, self.key_id.as_deref())
    }

    /// The JWK thumbprint of the key.
    pub fn jwk_thumbprint(&self) -> String {
        rsa_public_key_thumbprint(&self.pk.0)
    }
}

//

#[derive(Clone)]
pub struct PS512KeyPair {
    key_pair: RSAKeyPair,
    key_id: Option<String>,
}

impl std::fmt::Debug for PS512KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Rsa")
    }
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

    /// Import a key pair from a private RSA JWK.
    ///
    /// The modulus must be 2048 to 4096 bits long, and the exponent 65537.
    /// See [strict JWK validation](crate#strict-jwk-validation) for the other rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePrivate);
        let (rsa_sk, key_id) = rsa_private_key_from_jwk(jwk, &descriptor)?;
        let key_pair = RSAKeyPair {
            rsa_sk,
            metadata: None,
        };
        Ok(PS512KeyPair { key_pair, key_id })
    }

    /// Export the key pair as a JWK, private key included.
    /// Use `public_key().to_jwk()` to share the public key.
    pub fn to_jwk(&self) -> String {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePrivate);
        rsa_private_key_to_jwk(&self.key_pair.rsa_sk, &descriptor, self.key_id.as_deref())
    }

    /// The JWK thumbprint of the public key.
    pub fn jwk_thumbprint(&self) -> String {
        rsa_private_key_thumbprint(&self.key_pair.rsa_sk)
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

    /// Import a public key from an RSA JWK.
    ///
    /// The modulus must be 2048 to 4096 bits long, and the exponent 65537.
    /// See [strict JWK validation](crate#strict-jwk-validation) for the other rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePublic);
        let (rsa_pk, key_id) = rsa_public_key_from_jwk(jwk, &descriptor)?;
        Ok(PS512PublicKey {
            pk: RSAPublicKey(rsa_pk),
            key_id,
        })
    }

    /// Export the public key as a JWK, with `alg: PS512` and `use: sig`.
    pub fn to_jwk(&self) -> String {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePublic);
        rsa_public_key_to_jwk(&self.pk.0, &descriptor, self.key_id.as_deref())
    }

    /// The JWK thumbprint of the key.
    pub fn jwk_thumbprint(&self) -> String {
        rsa_public_key_thumbprint(&self.pk.0)
    }

    pub fn sha1_thumbprint(&self) -> String {
        self.pk.thumbprint(|data| SHA1::hash(data).to_vec())
    }

    pub fn sha256_thumbprint(&self) -> String {
        self.pk.thumbprint(|data| SHA256::hash(data).to_vec())
    }
}

//

#[derive(Clone)]
pub struct PS384KeyPair {
    key_pair: RSAKeyPair,
    key_id: Option<String>,
}

impl std::fmt::Debug for PS384KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Rsa")
    }
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

    /// Import a key pair from a private RSA JWK.
    ///
    /// The modulus must be 2048 to 4096 bits long, and the exponent 65537.
    /// See [strict JWK validation](crate#strict-jwk-validation) for the other rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePrivate);
        let (rsa_sk, key_id) = rsa_private_key_from_jwk(jwk, &descriptor)?;
        let key_pair = RSAKeyPair {
            rsa_sk,
            metadata: None,
        };
        Ok(PS384KeyPair { key_pair, key_id })
    }

    /// Export the key pair as a JWK, private key included.
    /// Use `public_key().to_jwk()` to share the public key.
    pub fn to_jwk(&self) -> String {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePrivate);
        rsa_private_key_to_jwk(&self.key_pair.rsa_sk, &descriptor, self.key_id.as_deref())
    }

    /// The JWK thumbprint of the public key.
    pub fn jwk_thumbprint(&self) -> String {
        rsa_private_key_thumbprint(&self.key_pair.rsa_sk)
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

    /// Import a public key from an RSA JWK.
    ///
    /// The modulus must be 2048 to 4096 bits long, and the exponent 65537.
    /// See [strict JWK validation](crate#strict-jwk-validation) for the other rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePublic);
        let (rsa_pk, key_id) = rsa_public_key_from_jwk(jwk, &descriptor)?;
        Ok(PS384PublicKey {
            pk: RSAPublicKey(rsa_pk),
            key_id,
        })
    }

    /// Export the public key as a JWK, with `alg: PS384` and `use: sig`.
    pub fn to_jwk(&self) -> String {
        let descriptor = rsa_jwk_descriptor(Self::jwt_alg_name(), KeyRole::SignaturePublic);
        rsa_public_key_to_jwk(&self.pk.0, &descriptor, self.key_id.as_deref())
    }

    /// The JWK thumbprint of the key.
    pub fn jwk_thumbprint(&self) -> String {
        rsa_public_key_thumbprint(&self.pk.0)
    }

    pub fn sha1_thumbprint(&self) -> String {
        self.pk.thumbprint(|data| SHA1::hash(data).to_vec())
    }

    pub fn sha256_thumbprint(&self) -> String {
        self.pk.thumbprint(|data| SHA256::hash(data).to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::rsa_test_keys::{
        der_from_pem, key_2048, TestKey, KEYS, OPENSSL_RS256_JWT_1024,
    };
    use crate::algorithms::test_util::{error_of, unb64};

    fn assert_policy_error(key: &TestKey, error: JWTError, private: bool) {
        assert!(
            key.is_policy_error(&error, private),
            "unexpected error for {}-bit e={}: {:?}",
            key.bits,
            key.e,
            error
        );
    }

    macro_rules! check_policy {
        ($key_pair:ident, $public_key:ident) => {
            for key in KEYS {
                let public_der = der_from_pem(key.public_pem);
                let rsa_pk = Rsa::<Public>::public_key_from_der(&public_der).ok();
                let components = rsa_pk.as_ref().map(|pk| (pk.n().to_vec(), pk.e().to_vec()));

                if !key.is_allowed() {
                    for res in [
                        $key_pair::from_pem(key.private_pem),
                        $key_pair::from_der(&der_from_pem(key.private_pem)),
                    ] {
                        assert_policy_error(key, error_of(res), true);
                    }
                    let public_results = [
                        $public_key::from_pem(key.public_pem),
                        $public_key::from_der(&public_der),
                    ];
                    for res in public_results {
                        if key.backend_rejects_public_key() {
                            assert!(res.is_err(), "{}-bit", key.bits);
                        } else {
                            assert_policy_error(key, error_of(res), false);
                        }
                    }
                    if let Some((n, e)) = &components {
                        assert_policy_error(
                            key,
                            error_of($public_key::from_components(n, e)),
                            false,
                        );
                    }
                    continue;
                }

                let key_pair = $key_pair::from_pem(key.private_pem).unwrap();
                let key_pair_der = $key_pair::from_der(&der_from_pem(key.private_pem)).unwrap();
                let (n, e) = components.unwrap();
                let public_keys = [
                    key_pair.public_key(),
                    $public_key::from_pem(key.public_pem).unwrap(),
                    $public_key::from_der(&public_der).unwrap(),
                    $public_key::from_components(&n, &e).unwrap(),
                ];
                for signer in [&key_pair, &key_pair_der] {
                    let token = signer
                        .sign(Claims::create(coarsetime::Duration::from_hours(1)))
                        .unwrap();
                    for public_key in &public_keys {
                        public_key
                            .verify_token::<NoCustomClaims>(&token, None)
                            .unwrap();
                    }
                }
            }
        };
    }

    #[test]
    fn policy_applies_to_every_signature_type_and_format() {
        check_policy!(RS256KeyPair, RS256PublicKey);
        check_policy!(RS384KeyPair, RS384PublicKey);
        check_policy!(RS512KeyPair, RS512PublicKey);
        check_policy!(PS256KeyPair, PS256PublicKey);
        check_policy!(PS384KeyPair, PS384PublicKey);
        check_policy!(PS512KeyPair, PS512PublicKey);
    }

    #[test]
    fn backend_accepts_the_1024_bit_fixture() {
        let key = KEYS.iter().find(|key| key.bits == 1024).unwrap();
        let rsa_sk = Rsa::<Private>::private_key_from_pem(key.private_pem.as_bytes()).unwrap();
        assert!(rsa_sk.check_key().unwrap());

        let (signed, signature) = OPENSSL_RS256_JWT_1024.rsplit_once('.').unwrap();
        let rsa_pk = Rsa::<Public>::public_key_from_pem(key.public_pem.as_bytes()).unwrap();
        let pkey = PKey::from_rsa(rsa_pk).unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
        verifier.set_rsa_padding(Padding::PKCS1).unwrap();
        verifier.update(signed.as_bytes()).unwrap();
        assert!(verifier.verify(&unb64(signature)).unwrap());
    }

    #[test]
    fn components_are_checked_before_the_backend() {
        let pk = RS256PublicKey::from_pem(key_2048().public_pem).unwrap();
        let components = pk.to_components();
        let (n, e) = (components.n, components.e);

        let padded_n = [&[0u8, 0][..], &n].concat();
        let padded = RS256PublicKey::from_components(&padded_n, &[0, 1, 0, 1]).unwrap();
        assert_eq!(padded.to_components().n, n);

        let n4096 = [&[0x80][..], &[0u8; 510][..], &[1][..]].concat();
        let n4097 = [&[1][..], &[0u8; 511][..], &[1][..]].concat();
        assert_eq!(bit_length(&n4096), 4096);
        assert_eq!(bit_length(&n4097), 4097);
        assert!(check_rsa_key_policy(&n4096, &e, JWTError::InvalidPublicKey).is_ok());

        let mut even_n = n.clone();
        *even_n.last_mut().unwrap() &= 0xfe;
        let large_e = [1, 0, 0, 0, 1];
        for (case, n, e, expected) in [
            ("even n", &even_n[..], &e[..], "InvalidPublicKey"),
            ("e = 3", &n[..], &[3][..], "InvalidPublicKey"),
            ("e = 2^32 + 1", &n[..], &large_e[..], "InvalidPublicKey"),
            ("empty e", &n[..], &[][..], "InvalidPublicKey"),
            ("n one byte short", &n[1..], &e[..], "WeakKey"),
            ("empty n", &[][..], &e[..], "WeakKey"),
            ("4097-bit n", &n4097[..], &e[..], "UnsupportedRSAModulus"),
        ] {
            let error = error_of(RS256PublicKey::from_components(n, e));
            assert_eq!(format!("{:?}", error), expected, "{}", case);
        }
    }

    #[test]
    fn generation_sizes() {
        for bits in [2048, 3072] {
            let key_pair = RS256KeyPair::generate(bits).unwrap();
            let public_key = key_pair.public_key();
            RS256PublicKey::from_der(&public_key.to_der().unwrap()).unwrap();
        }
        for bits in [1024, 2047, 2560, 4097, 8192] {
            assert!(
                matches!(
                    error_of(RS256KeyPair::generate(bits)),
                    JWTError::UnsupportedRSAModulus
                ),
                "{} bits",
                bits
            );
        }
    }
}

#[cfg(test)]
mod jwk_tests {
    use super::*;
    use crate::algorithms::jwk::MAX_JWK_LENGTH;
    use crate::algorithms::jwk_test_vectors;
    use crate::algorithms::rsa_test_keys::{der_from_pem, key_2048, KEYS, THREE_PRIME_PEM};
    use crate::algorithms::test_util::{
        b64, error_of, json as value, member_bytes, pem, with, without,
    };

    const RFC7517_PRIVATE: &str = r#"{"kty":"RSA",
        "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e":"AQAB",
        "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
        "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
        "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
        "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
        "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
        "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
        "alg":"RS256",
        "kid":"2011-04-29"}"#;
    const RFC7638_THUMBPRINT: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
    const PRIVATE_MEMBERS: [&str; 6] = ["d", "p", "q", "dp", "dq", "qi"];

    fn rsa_2048() -> RS256KeyPair {
        RS256KeyPair::from_pem(key_2048().private_pem).unwrap()
    }

    #[test]
    fn rfc_vectors() {
        let key_pair = RS256KeyPair::from_jwk(RFC7517_PRIVATE).unwrap();
        assert_eq!(key_pair.key_id.as_deref(), Some("2011-04-29"));
        assert_eq!(key_pair.jwk_thumbprint(), RFC7638_THUMBPRINT);
        let public_jwk = without(RFC7517_PRIVATE, &PRIVATE_MEMBERS);
        let public_key = RS256PublicKey::from_jwk(&public_jwk).unwrap();
        assert_eq!(public_key.jwk_thumbprint(), RFC7638_THUMBPRINT);
        assert_eq!(key_pair.public_key().jwk_thumbprint(), RFC7638_THUMBPRINT);

        let token = key_pair
            .sign(Claims::create(coarsetime::Duration::from_hours(1)))
            .unwrap();
        public_key
            .verify_token::<NoCustomClaims>(&token, None)
            .unwrap();

        let exported = value(&key_pair.to_jwk());
        let original = value(RFC7517_PRIVATE);
        for name in ["n", "e", "d", "p", "q", "dp", "dq", "qi", "kid", "alg"] {
            assert_eq!(exported[name], original[name], "{}", name);
        }
        assert_eq!(exported["use"], "sig");

        assert!(PS256PublicKey::from_jwk(&public_jwk).is_err());
        assert!(PS256KeyPair::from_jwk(RFC7517_PRIVATE).is_err());
        PS256PublicKey::from_jwk(&without(&public_jwk, &["alg"])).unwrap();
    }

    macro_rules! round_trip {
        ($key_pair:ident, $public_key:ident, $alg:expr) => {{
            let key = KEYS
                .iter()
                .find(|key| key.bits == 2560 && key.e == 65537)
                .unwrap();
            let key_pair = $key_pair::from_pem(key.private_pem)
                .unwrap()
                .with_key_id("rsa");
            let private_jwk = key_pair.to_jwk();
            let public_jwk = key_pair.public_key().to_jwk();
            let exported = value(&public_jwk);
            assert_eq!(exported["alg"], $alg);
            assert_eq!(exported["use"], "sig");
            assert_eq!(exported.as_object().unwrap().len(), 6);
            assert_eq!(value(&private_jwk).as_object().unwrap().len(), 12);

            let restored = $key_pair::from_jwk(&private_jwk).unwrap();
            let public_key = $public_key::from_jwk(&public_jwk).unwrap();
            assert_eq!(restored.to_jwk(), private_jwk);
            assert_eq!(public_key.to_jwk(), public_jwk);
            assert_eq!(restored.jwk_thumbprint(), public_key.jwk_thumbprint());
            assert_eq!(restored.to_der().unwrap(), key_pair.to_der().unwrap());
            let token = restored
                .sign(Claims::create(coarsetime::Duration::from_hours(1)))
                .unwrap();
            let options = VerificationOptions {
                required_key_id: Some("rsa".into()),
                ..Default::default()
            };
            public_key
                .verify_token::<NoCustomClaims>(&token, Some(options))
                .unwrap();
        }};
    }

    #[test]
    fn round_trips() {
        round_trip!(RS256KeyPair, RS256PublicKey, "RS256");
        round_trip!(RS384KeyPair, RS384PublicKey, "RS384");
        round_trip!(RS512KeyPair, RS512PublicKey, "RS512");
        round_trip!(PS256KeyPair, PS256PublicKey, "PS256");
        round_trip!(PS384KeyPair, PS384PublicKey, "PS384");
        round_trip!(PS512KeyPair, PS512PublicKey, "PS512");
    }

    #[test]
    fn modulus_sign_byte() {
        let public_jwk = rsa_2048().public_key().to_jwk();
        let n = member_bytes(&public_jwk, "n");
        assert!(n[0] & 0x80 != 0);

        let padded = with(&public_jwk, "n", b64(&[&[0][..], &n].concat()).into());
        let key = RS256PublicKey::from_jwk(&padded).unwrap();
        assert_eq!(key.to_jwk(), public_jwk);
        assert_eq!(
            key.jwk_thumbprint(),
            RS256PublicKey::from_jwk(&public_jwk)
                .unwrap()
                .jwk_thumbprint()
        );

        let mut low = n.clone();
        low[0] &= 0x7f;
        for (case, bad_n) in [
            ("two zero bytes", b64(&[&[0, 0][..], &n].concat())),
            ("unneeded zero byte", b64(&[&[0][..], &low].concat())),
            ("empty", "".into()),
            ("zero", "AA".into()),
            ("zero on two bytes", "AAA".into()),
        ] {
            let jwk = with(&public_jwk, "n", bad_n.into());
            assert!(
                matches!(
                    error_of(RS256PublicKey::from_jwk(&jwk)),
                    JWTError::InvalidPublicKey
                ),
                "{}",
                case
            );
        }
        let low = with(&public_jwk, "n", b64(&low).into());
        assert!(matches!(
            error_of(RS256PublicKey::from_jwk(&low)),
            JWTError::WeakKey
        ));

        let private_jwk = rsa_2048().to_jwk();
        let padded = with(&private_jwk, "n", b64(&[&[0][..], &n].concat()).into());
        let key_pair = RS256KeyPair::from_jwk(&padded).unwrap();
        assert_eq!(key_pair.to_jwk(), private_jwk);
    }

    #[test]
    fn exponent_must_be_65537() {
        let public_jwk = rsa_2048().public_key().to_jwk();
        for e in ["AAEAAQ", "Aw", "EQ", "AQAAAAE", "", "AQAB="] {
            let jwk = with(&public_jwk, "e", e.into());
            assert!(
                matches!(
                    error_of(RS256PublicKey::from_jwk(&jwk)),
                    JWTError::InvalidPublicKey
                ),
                "{}",
                e
            );
        }
        let jwk = with(&rsa_2048().to_jwk(), "e", "AAEAAQ".into());
        assert!(matches!(
            error_of(RS256KeyPair::from_jwk(&jwk)),
            JWTError::InvalidKeyPair
        ));
    }

    #[test]
    fn size_policy() {
        for key in KEYS.iter().filter(|key| key.e == 65537) {
            // The private key lets us test sizes the public key parser rejects.
            let rsa_sk = Rsa::<Private>::private_key_from_pem(key.private_pem.as_bytes());
            let n = rsa_sk.unwrap().n().to_vec();
            assert_eq!(bit_length(&n), key.bits);
            let jwk = format!(r#"{{"kty":"RSA","n":"{}","e":"AQAB"}}"#, b64(&n));
            let res = RS256PublicKey::from_jwk(&jwk);
            let as_expected = match key.bits {
                2048..=4096 => res.is_ok(),
                0..=2047 => matches!(error_of(res), JWTError::WeakKey),
                _ => matches!(error_of(res), JWTError::UnsupportedRSAModulus),
            };
            assert!(as_expected, "{}-bit", key.bits);
        }

        let too_long = format!(r#"{{"kty":"RSA","n":"{}","e":"AQAB"}}"#, "q".repeat(700));
        assert!(matches!(
            error_of(RS256PublicKey::from_jwk(&too_long)),
            JWTError::UnsupportedRSAModulus
        ));
    }

    #[test]
    fn the_largest_private_keys_fit_in_the_size_limit() {
        let key = KEYS
            .iter()
            .find(|key| key.bits == 4096 && key.e == 65537)
            .unwrap();
        let private_jwk = PS512KeyPair::from_pem(key.private_pem).unwrap().to_jwk();
        assert!(private_jwk.len() < 3300);

        let base = with(&private_jwk, "kid", "".into());
        let kid = "k".repeat(MAX_JWK_LENGTH - base.len());
        let largest = with(&private_jwk, "kid", kid.clone().into());
        assert_eq!(largest.len(), MAX_JWK_LENGTH);
        PS512KeyPair::from_jwk(&largest).unwrap();
        let too_large = with(&private_jwk, "kid", format!("{}k", kid).into());
        assert!(matches!(
            error_of(PS512KeyPair::from_jwk(&too_large)),
            JWTError::InvalidKeyPair
        ));
    }

    #[test]
    fn private_values_are_minimal_complete_and_consistent() {
        let private_jwk = rsa_2048().to_jwk();
        let rejected = |jwk: &str| {
            matches!(
                error_of(RS256KeyPair::from_jwk(jwk)),
                JWTError::InvalidKeyPair
            )
        };
        for name in PRIVATE_MEMBERS {
            let x = member_bytes(&private_jwk, name);
            let mut corrupted = x.clone();
            *corrupted.last_mut().unwrap() ^= 2;
            for (case, x) in [
                ("padded", b64(&[&[0][..], &x].concat()).into()),
                ("corrupted", b64(&corrupted).into()),
                ("oversized", b64(&[0x55u8; 513]).into()),
                ("null", serde_json::Value::Null),
            ] {
                assert!(rejected(&with(&private_jwk, name, x)), "{} {}", case, name);
            }
            assert!(
                rejected(&without(&private_jwk, &[name])),
                "missing {}",
                name
            );
        }

        // The other private values must agree with p and q.
        let p = value(&private_jwk)["p"].clone();
        let q = value(&private_jwk)["q"].clone();
        assert!(rejected(&with(&with(&private_jwk, "p", q), "q", p)));

        for oth in [serde_json::json!([]), serde_json::Value::Null] {
            let jwk = with(&private_jwk, "oth", oth.clone());
            assert!(rejected(&jwk), "oth: {}", oth);
        }

        let public_jwk = rsa_2048().public_key().to_jwk();
        for name in PRIVATE_MEMBERS {
            let jwk = with(&public_jwk, name, value(&private_jwk)[name].clone());
            assert!(
                matches!(
                    error_of(RS256PublicKey::from_jwk(&jwk)),
                    JWTError::InvalidPublicKey
                ),
                "{}",
                name
            );
        }
    }

    fn der_length(len: usize) -> Vec<u8> {
        match len {
            0..=0x7f => vec![len as u8],
            0x80..=0xff => vec![0x81, len as u8],
            _ => vec![0x82, (len >> 8) as u8, len as u8],
        }
    }

    fn der_integer(x: &[u8]) -> Vec<u8> {
        let x = if x[0] & 0x80 != 0 {
            [&[0][..], x].concat()
        } else {
            x.to_vec()
        };
        [&[0x02][..], &der_length(x.len()), &x].concat()
    }

    // Build malformed keys without the backend rejecting them first.
    fn pkcs1_der(values: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = std::iter::once(der_integer(&[0]))
            .chain(values.iter().map(|x| der_integer(x)))
            .flatten()
            .collect();
        [&[0x30][..], &der_length(body.len()), &body].concat()
    }

    #[test]
    fn der_and_pem_private_keys_are_checked() {
        let private_jwk = rsa_2048().to_jwk();
        let names = ["n", "e", "d", "p", "q", "dp", "dq", "qi"];
        let values: Vec<Vec<u8>> = names
            .iter()
            .map(|name| member_bytes(&private_jwk, name))
            .collect();
        let der = pkcs1_der(&values);
        RS256KeyPair::from_der(&der).unwrap();
        RS256KeyPair::from_pem(&pem("RSA PRIVATE KEY", &der)).unwrap();

        for (i, name) in names.iter().enumerate().skip(2) {
            let mut corrupted = values.clone();
            *corrupted[i].last_mut().unwrap() ^= 2;
            let der = pkcs1_der(&corrupted);
            assert!(RS256KeyPair::from_der(&der).is_err(), "{}", name);
            assert!(
                RS256KeyPair::from_pem(&pem("RSA PRIVATE KEY", &der)).is_err(),
                "{}",
                name
            );
        }

        assert!(RS256KeyPair::from_pem(THREE_PRIME_PEM).is_err());
        assert!(RS256KeyPair::from_der(&der_from_pem(THREE_PRIME_PEM)).is_err());
    }

    #[test]
    fn provider_keys() {
        let paypal = value(jwk_test_vectors::PAYPAL_JWKS);
        let keys = paypal["keys"].as_array().unwrap();
        let mut padded_moduli = 0;
        for jwk in keys.iter().filter(|jwk| jwk["kty"] == "RSA") {
            let text = jwk.to_string();
            let n = member_bytes(&text, "n");
            let exported = if jwk["alg"] == "PS256" {
                assert!(RS256PublicKey::from_jwk(&text).is_err());
                let key = PS256PublicKey::from_jwk(&text).unwrap();
                assert_eq!(key.key_id.as_deref(), jwk["kid"].as_str());
                key.to_jwk()
            } else {
                assert!(PS256PublicKey::from_jwk(&text).is_err());
                RS256PublicKey::from_jwk(&text).unwrap().to_jwk()
            };
            let exported_n = member_bytes(&exported, "n");
            if n.len() == 257 {
                padded_moduli += 1;
                assert_eq!(n[0], 0);
                assert_eq!(exported_n, n[1..]);
                let unpadded = with(&text, "n", b64(&n[1..]).into());
                let thumbprint = |jwk: &str| {
                    if jwk.contains("PS256") {
                        PS256PublicKey::from_jwk(jwk).unwrap().jwk_thumbprint()
                    } else {
                        RS256PublicKey::from_jwk(jwk).unwrap().jwk_thumbprint()
                    }
                };
                assert_eq!(thumbprint(&text), thumbprint(&unpadded));
            } else {
                assert_eq!(exported_n, n);
            }
        }
        assert_eq!(padded_moduli, 2);

        // Yahoo's RSA key is 1024 bits.
        let yahoo = value(jwk_test_vectors::YAHOO_JWKS);
        let rsa = yahoo["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|jwk| jwk["kty"] == "RSA")
            .unwrap();
        assert_eq!(member_bytes(&rsa.to_string(), "n").len(), 129);
        assert!(matches!(
            error_of(RS256PublicKey::from_jwk(&rsa.to_string())),
            JWTError::WeakKey
        ));
    }

    #[test]
    fn webcrypto_exports() {
        for export in jwk_test_vectors::ALL {
            let export = value(export);
            let entry = &export["keys"]["RS256"];
            let key_pair = RS256KeyPair::from_jwk(&entry["private"].to_string()).unwrap();
            let public_key = RS256PublicKey::from_jwk(&entry["public"].to_string()).unwrap();
            assert_eq!(key_pair.jwk_thumbprint(), public_key.jwk_thumbprint());
            public_key
                .verify_token::<NoCustomClaims>(entry["jwt"].as_str().unwrap(), None)
                .unwrap();
            assert!(PS256PublicKey::from_jwk(&entry["public"].to_string()).is_err());

            let entry = &export["keys"]["PS256"];
            let key_pair = PS256KeyPair::from_jwk(&entry["private"].to_string()).unwrap();
            let public_key = PS256PublicKey::from_jwk(&entry["public"].to_string()).unwrap();
            assert_eq!(key_pair.jwk_thumbprint(), public_key.jwk_thumbprint());
            public_key
                .verify_token::<NoCustomClaims>(entry["jwt"].as_str().unwrap(), None)
                .unwrap();

            let entry = &export["keys"]["RSA-OAEP"];
            assert!(RS256PublicKey::from_jwk(&entry["public"].to_string()).is_err());
            assert!(RS256KeyPair::from_jwk(&entry["private"].to_string()).is_err());
        }
    }
}
