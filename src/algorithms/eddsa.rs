use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use hmac_sha1_compact::Hash as SHA1;
use hmac_sha256::Hash as SHA256;
use serde::{de::DeserializeOwned, Serialize};

use crate::algorithms::jwk::{
    decode_fixed, decode_secret, is_encoding_of, okp_export, okp_thumbprint, Jwk, JwkDescriptor,
    KeyRole, KeyType,
};
use crate::claims::*;
use crate::common::*;
#[cfg(feature = "cwt")]
use crate::cwt_token::*;
use crate::error::*;
use crate::jwt_header::*;
use crate::token::*;

// Keep signing and exporting as "EdDSA" for existing verifiers.
const ED25519_ALGS: &[&str] = &["EdDSA", "Ed25519"];
const ED25519_ALG_ALIASES: &[&str] = &["Ed25519"];

const ED25519_PUBLIC_JWK: JwkDescriptor = JwkDescriptor::new(
    KeyType::Okp,
    Some("Ed25519"),
    "EdDSA",
    KeyRole::SignaturePublic,
)
.with_aliases(ED25519_ALG_ALIASES);

const ED25519_PRIVATE_JWK: JwkDescriptor = ED25519_PUBLIC_JWK.with_role(KeyRole::SignaturePrivate);

#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct Edwards25519PublicKey(ed25519_compact::PublicKey);

impl AsRef<ed25519_compact::PublicKey> for Edwards25519PublicKey {
    fn as_ref(&self) -> &ed25519_compact::PublicKey {
        &self.0
    }
}

impl Edwards25519PublicKey {
    // Parsing a public key alone doesn't reject weak keys.
    fn checked(
        ed25519_pk: Result<ed25519_compact::PublicKey, ed25519_compact::Error>,
    ) -> Result<Self, Error> {
        let ed25519_pk = ed25519_pk.map_err(|_| JWTError::InvalidPublicKey)?;
        ed25519_pk
            .validate()
            .map_err(|_| JWTError::InvalidPublicKey)?;
        Ok(Edwards25519PublicKey(ed25519_pk))
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Self::checked(ed25519_compact::PublicKey::from_slice(raw))
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Self::checked(ed25519_compact::PublicKey::from_der(der))
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Self::checked(ed25519_compact::PublicKey::from_pem(pem))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_ref().to_vec()
    }

    pub fn to_der(&self) -> Vec<u8> {
        self.0.to_der()
    }

    pub fn to_pem(&self) -> String {
        self.0.to_pem()
    }

    fn thumbprint(&self, hash: impl Fn(&[u8]) -> Vec<u8>) -> String {
        Base64UrlSafeNoPadding::encode_to_string(hash(&self.to_der())).unwrap()
    }

    pub(crate) fn from_jwk(jwk: &str) -> Result<(Self, Option<String>), Error> {
        let jwk = Jwk::parse(jwk, &ED25519_PUBLIC_JWK)?;
        let mut x = [0u8; ed25519_compact::PublicKey::BYTES];
        ensure!(decode_fixed(jwk.x(), &mut x), JWTError::InvalidPublicKey);
        Ok((Self::from_bytes(&x)?, jwk.kid().map(Into::into)))
    }

    pub(crate) fn to_jwk(&self, key_id: Option<&str>) -> String {
        okp_export(&ED25519_PUBLIC_JWK, &self.0[..], None, key_id)
    }

    pub(crate) fn jwk_thumbprint(&self) -> String {
        okp_thumbprint("Ed25519", &self.0[..])
    }
}

#[doc(hidden)]
#[derive(Clone)]
pub struct Edwards25519KeyPair {
    ed25519_kp: ed25519_compact::KeyPair,
    metadata: Option<KeyMetadata>,
}

impl std::fmt::Debug for Edwards25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PKey")
            .field("algorithm", &"Ed25519")
            .finish()
    }
}

impl AsRef<ed25519_compact::KeyPair> for Edwards25519KeyPair {
    fn as_ref(&self) -> &ed25519_compact::KeyPair {
        &self.ed25519_kp
    }
}

impl Edwards25519KeyPair {
    /// The bytes must contain a seed followed by its matching public key.
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let ed25519_kp = ed25519_compact::KeyPair::from_slice(raw)?;
        ed25519_kp
            .validate()
            .map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(Edwards25519KeyPair {
            ed25519_kp,
            metadata: None,
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let ed25519_kp = ed25519_compact::KeyPair::from_der(der)?;
        Ok(Edwards25519KeyPair {
            ed25519_kp,
            metadata: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let ed25519_kp = ed25519_compact::KeyPair::from_pem(pem)?;
        Ok(Edwards25519KeyPair {
            ed25519_kp,
            metadata: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.ed25519_kp.to_vec()
    }

    pub fn to_der(&self) -> Vec<u8> {
        self.ed25519_kp.sk.to_der()
    }

    pub fn to_pem(&self) -> String {
        self.ed25519_kp.to_pem()
    }

    pub fn public_key(&self) -> Edwards25519PublicKey {
        let ed25519_pk = self.ed25519_kp.pk;
        Edwards25519PublicKey(ed25519_pk)
    }

    pub fn generate() -> Self {
        let ed25519_kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::generate());
        Edwards25519KeyPair {
            ed25519_kp,
            metadata: None,
        }
    }

    pub(crate) fn from_jwk(jwk: &str) -> Result<(Self, Option<String>), Error> {
        let jwk = Jwk::parse(jwk, &ED25519_PRIVATE_JWK)?;
        let d =
            decode_secret(jwk.d(), ed25519_compact::Seed::BYTES).ok_or(JWTError::InvalidKeyPair)?;
        // Clear the seed copy because `Seed` isn't wiped on drop.
        let mut seed =
            ed25519_compact::Seed::from_slice(&d).map_err(|_| JWTError::InvalidKeyPair)?;
        let ed25519_kp = ed25519_compact::KeyPair::try_from_seed(seed);
        seed.wipe_mut();
        let ed25519_kp = ed25519_kp.map_err(|_| JWTError::InvalidKeyPair)?;
        ensure!(
            is_encoding_of(jwk.x(), &ed25519_kp.pk[..]),
            JWTError::InvalidKeyPair
        );
        let key_pair = Edwards25519KeyPair {
            ed25519_kp,
            metadata: None,
        };
        Ok((key_pair, jwk.kid().map(Into::into)))
    }

    pub(crate) fn to_jwk(&self, key_id: Option<&str>) -> String {
        let seed = &self.ed25519_kp.sk[..ed25519_compact::Seed::BYTES];
        okp_export(
            &ED25519_PRIVATE_JWK,
            &self.ed25519_kp.pk[..],
            Some(seed),
            key_id,
        )
    }
}

pub trait EdDSAKeyPairLike {
    fn jwt_alg_name() -> &'static str;
    fn key_pair(&self) -> &Edwards25519KeyPair;
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
            let noise = ed25519_compact::Noise::generate();
            let signature = self.key_pair().as_ref().sk.sign(authenticated, Some(noise));
            Ok(signature.to_vec())
        })
    }
}

fn verify_signature(
    public_key: &Edwards25519PublicKey,
    authenticated: &str,
    signature: &[u8],
) -> Result<(), Error> {
    let ed25519_signature = ed25519_compact::Signature::from_slice(signature)?;
    public_key
        .as_ref()
        .verify(authenticated, &ed25519_signature)
        .map_err(|_| JWTError::InvalidSignature)?;
    Ok(())
}

pub trait EdDSAPublicKeyLike {
    fn jwt_alg_name() -> &'static str;
    fn public_key(&self) -> &Edwards25519PublicKey;
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
                verify_signature(self.public_key(), authenticated, signature)
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
                verify_signature(self.public_key(), authenticated, signature)
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
pub struct Ed25519KeyPair {
    key_pair: Edwards25519KeyPair,
    key_id: Option<String>,
}

impl std::fmt::Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PKey")
            .field("algorithm", &"Ed25519")
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct Ed25519PublicKey {
    pk: Edwards25519PublicKey,
    key_id: Option<String>,
}

impl EdDSAKeyPairLike for Ed25519KeyPair {
    fn jwt_alg_name() -> &'static str {
        "EdDSA"
    }

    fn key_pair(&self) -> &Edwards25519KeyPair {
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

impl Ed25519KeyPair {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(Ed25519KeyPair {
            key_pair: Edwards25519KeyPair::from_bytes(raw)?,
            key_id: None,
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(Ed25519KeyPair {
            key_pair: Edwards25519KeyPair::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(Ed25519KeyPair {
            key_pair: Edwards25519KeyPair::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key_pair.to_bytes()
    }

    pub fn to_der(&self) -> Vec<u8> {
        self.key_pair.to_der()
    }

    pub fn to_pem(&self) -> String {
        self.key_pair.to_pem()
    }

    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey {
            pk: self.key_pair.public_key(),
            key_id: self.key_id.clone(),
        }
    }

    pub fn generate() -> Self {
        Ed25519KeyPair {
            key_pair: Edwards25519KeyPair::generate(),
            key_id: None,
        }
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }

    /// Import a key pair from a private JWK (`kty: OKP`, `crv: Ed25519`).
    ///
    /// `alg` can be either `EdDSA` or `Ed25519`.
    /// See [strict JWK validation](crate#strict-jwk-validation) for the other rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let (key_pair, key_id) = Edwards25519KeyPair::from_jwk(jwk)?;
        Ok(Ed25519KeyPair { key_pair, key_id })
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

impl EdDSAPublicKeyLike for Ed25519PublicKey {
    fn jwt_alg_name() -> &'static str {
        "EdDSA"
    }

    /// Accepts both `EdDSA` and `Ed25519` as the token algorithm.
    fn verify_token<CustomClaims: DeserializeOwned>(
        &self,
        token: &str,
        options: Option<VerificationOptions>,
    ) -> Result<JWTClaims<CustomClaims>, Error> {
        Token::verify_with_algorithms(
            ED25519_ALGS,
            token,
            options,
            |authenticated, signature| verify_signature(&self.pk, authenticated, signature),
            |_salt: Option<&[u8]>| Ok(()),
        )
    }

    fn public_key(&self) -> &Edwards25519PublicKey {
        &self.pk
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn set_key_id(&mut self, key_id: String) {
        self.key_id = Some(key_id);
    }
}

impl Ed25519PublicKey {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(Ed25519PublicKey {
            pk: Edwards25519PublicKey::from_bytes(raw)?,
            key_id: None,
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(Ed25519PublicKey {
            pk: Edwards25519PublicKey::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(Ed25519PublicKey {
            pk: Edwards25519PublicKey::from_pem(pem)?,
            key_id: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.pk.to_bytes()
    }

    pub fn to_der(&self) -> Vec<u8> {
        self.pk.to_der()
    }

    pub fn to_pem(&self) -> String {
        self.pk.to_pem()
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }

    pub fn sha1_thumbprint(&self) -> String {
        self.pk.thumbprint(|data| SHA1::hash(data).to_vec())
    }

    pub fn sha256_thumbprint(&self) -> String {
        self.pk.thumbprint(|data| SHA256::hash(data).to_vec())
    }

    /// Import a public key from a JWK (`kty: OKP`, `crv: Ed25519`).
    ///
    /// `alg` can be either `EdDSA` or `Ed25519`.
    /// See [strict JWK validation](crate#strict-jwk-validation) for the other rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let (pk, key_id) = Edwards25519PublicKey::from_jwk(jwk)?;
        Ok(Ed25519PublicKey { pk, key_id })
    }

    /// Export the public key as a JWK, with `alg: EdDSA` and `use: sig`.
    pub fn to_jwk(&self) -> String {
        self.pk.to_jwk(self.key_id.as_deref())
    }

    /// The JWK thumbprint of the key.
    pub fn jwk_thumbprint(&self) -> String {
        self.pk.jwk_thumbprint()
    }
}

#[cfg(test)]
mod tests {
    use ct_codecs::{Decoder, Hex};

    use super::*;
    use crate::algorithms::test_util::{b64, error_of, pem};

    const SPKI_PREFIX: [u8; 12] = [48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0];
    const PKCS8_PREFIX: [u8; 16] = [48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32];

    // All eight small-order points, then the invalid encodings y = p and y = p + 1.
    //
    // ed25519-compact before 2.6.0 missed half of the order-8 points.
    const WEAK_PUBLIC_KEYS: [&str; 10] = [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];

    #[test]
    fn weak_public_keys_are_rejected_by_every_constructor() {
        for pk in WEAK_PUBLIC_KEYS {
            let raw = Hex::decode_to_vec(pk, None).unwrap();
            let der = [&SPKI_PREFIX[..], &raw].concat();
            let jwk = format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#, b64(&raw));
            for (format, res) in [
                ("raw", Ed25519PublicKey::from_bytes(&raw)),
                ("DER", Ed25519PublicKey::from_der(&der)),
                ("PEM", Ed25519PublicKey::from_pem(&pem("PUBLIC KEY", &der))),
                ("JWK", Ed25519PublicKey::from_jwk(&jwk)),
            ] {
                assert!(
                    matches!(error_of(res), JWTError::InvalidPublicKey),
                    "{} as {}",
                    pk,
                    format
                );
            }
        }

        let public_key = Ed25519KeyPair::generate().public_key();
        assert_eq!(public_key.to_der()[..12], SPKI_PREFIX);
        Ed25519PublicKey::from_bytes(&public_key.to_bytes()).unwrap();
        Ed25519PublicKey::from_der(&public_key.to_der()).unwrap();
        Ed25519PublicKey::from_pem(&public_key.to_pem()).unwrap();
    }

    #[test]
    fn invalid_der_and_pem_keys_are_rejected() {
        let key_pair = Ed25519KeyPair::generate();
        let sk_der = key_pair.to_der();
        let pk_der = key_pair.public_key().to_der();
        let long_sk_der = [&sk_der[..], &[0]].concat();
        assert_eq!(sk_der[..16], PKCS8_PREFIX);
        // ed25519-compact before 2.6.0 panicked on an all-zero seed.
        let zero_seed_der = [&PKCS8_PREFIX[..], &[0u8; 32]].concat();

        for (case, der) in [
            ("empty", &sk_der[..0]),
            ("header only", &sk_der[..16]),
            ("truncated seed", &sk_der[..31]),
            ("one byte short", &sk_der[..47]),
            ("trailing byte", &long_sk_der[..]),
            ("zero seed", &zero_seed_der[..]),
        ] {
            assert!(Ed25519KeyPair::from_der(der).is_err(), "{}", case);
            assert!(
                Ed25519KeyPair::from_pem(&pem("PRIVATE KEY", der)).is_err(),
                "{}",
                case
            );
        }
        for (case, der) in [
            ("empty", &pk_der[..0]),
            ("header only", &pk_der[..12]),
            ("one byte short", &pk_der[..43]),
        ] {
            assert!(Ed25519PublicKey::from_der(der).is_err(), "{}", case);
            assert!(
                Ed25519PublicKey::from_pem(&pem("PUBLIC KEY", der)).is_err(),
                "{}",
                case
            );
        }

        let restored = Ed25519KeyPair::from_pem(&pem("PRIVATE KEY", &sk_der)).unwrap();
        assert_eq!(restored.to_bytes(), key_pair.to_bytes());
    }

    #[test]
    fn key_pairs_must_be_consistent() {
        let key_pair = Ed25519KeyPair::generate();
        let raw = key_pair.to_bytes();
        let (seed, public_key) = raw.split_at(32);
        let other_raw = Ed25519KeyPair::generate().to_bytes();
        let (other_seed, other_public_key) = other_raw.split_at(32);
        for (case, seed, public_key) in [
            ("other public key", seed, other_public_key),
            ("other seed", other_seed, public_key),
            ("zero seed", &[0u8; 32][..], public_key),
        ] {
            let raw = [seed, public_key].concat();
            let jwk = format!(
                r#"{{"kty":"OKP","crv":"Ed25519","x":"{}","d":"{}"}}"#,
                b64(public_key),
                b64(seed)
            );
            for (format, res) in [
                ("raw", Ed25519KeyPair::from_bytes(&raw)),
                ("JWK", Ed25519KeyPair::from_jwk(&jwk)),
            ] {
                assert!(
                    matches!(error_of(res), JWTError::InvalidKeyPair),
                    "{} as {}",
                    case,
                    format
                );
            }
        }

        let restored = Ed25519KeyPair::from_bytes(&raw).unwrap();
        let token = restored
            .sign(Claims::create(coarsetime::Duration::from_hours(1)))
            .unwrap();
        key_pair
            .public_key()
            .verify_token::<NoCustomClaims>(&token, None)
            .unwrap();
    }
}

#[cfg(test)]
mod jwk_tests {
    use super::*;
    use crate::algorithms::jwk_test_vectors;
    use crate::algorithms::test_util::{b64, error_of, json, member_bytes, unb64};

    const RFC8037_PRIVATE: &str = r#"{"kty":"OKP","crv":"Ed25519",
        "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
        "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
    const RFC8037_PUBLIC: &str = r#"{"kty":"OKP","crv":"Ed25519",
        "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;

    #[test]
    fn rfc8037_vectors() {
        let key_pair = Ed25519KeyPair::from_jwk(RFC8037_PRIVATE).unwrap();
        let public_key = Ed25519PublicKey::from_jwk(RFC8037_PUBLIC).unwrap();
        assert_eq!(key_pair.public_key().to_bytes(), public_key.to_bytes());

        let seed = member_bytes(RFC8037_PRIVATE, "d");
        let raw = [&seed[..], &public_key.to_bytes()].concat();
        assert_eq!(Ed25519KeyPair::from_bytes(&raw).unwrap().to_bytes(), raw);

        let thumbprint = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
        assert_eq!(public_key.jwk_thumbprint(), thumbprint);
        assert_eq!(key_pair.jwk_thumbprint(), thumbprint);

        let signing_input = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";
        let signature = "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";
        let computed = key_pair.key_pair().as_ref().sk.sign(signing_input, None);
        assert_eq!(b64(&computed[..]), signature);
        verify_signature(public_key.public_key(), signing_input, &unb64(signature)).unwrap();
    }

    #[test]
    fn round_trips_and_key_ids() {
        let key_pair = Ed25519KeyPair::generate().with_key_id("key \"1\"");
        let private_jwk = key_pair.to_jwk();
        let public_jwk = key_pair.public_key().to_jwk();

        let exported = json(&public_jwk);
        let members: Vec<&String> = exported.as_object().unwrap().keys().collect();
        assert_eq!(members, ["alg", "crv", "kid", "kty", "use", "x"]);
        assert_eq!(exported["alg"], "EdDSA");
        assert_eq!(exported["use"], "sig");
        assert_eq!(exported["kid"], "key \"1\"");
        let exported = json(&private_jwk);
        assert_eq!(exported.as_object().unwrap().len(), 7);
        assert!(exported["d"].is_string());

        let restored = Ed25519KeyPair::from_jwk(&private_jwk).unwrap();
        assert_eq!(restored.to_bytes(), key_pair.to_bytes());
        assert_eq!(restored.key_id.as_deref(), Some("key \"1\""));
        let public_key = Ed25519PublicKey::from_jwk(&public_jwk).unwrap();
        assert_eq!(public_key.key_id.as_deref(), Some("key \"1\""));
        assert_eq!(public_key.jwk_thumbprint(), restored.jwk_thumbprint());
        assert_eq!(public_key.to_jwk(), public_jwk);
        assert_eq!(restored.to_jwk(), private_jwk);

        let unnamed = Ed25519PublicKey::from_bytes(&public_key.to_bytes()).unwrap();
        assert_eq!(unnamed.jwk_thumbprint(), public_key.jwk_thumbprint());
        assert!(!unnamed.to_jwk().contains("kid"));

        let token = restored
            .sign(Claims::create(coarsetime::Duration::from_hours(1)))
            .unwrap();
        let options = VerificationOptions {
            required_key_id: Some("key \"1\"".into()),
            ..Default::default()
        };
        public_key
            .verify_token::<NoCustomClaims>(&token, Some(options.clone()))
            .unwrap();
        restored
            .public_key()
            .verify_token::<NoCustomClaims>(&token, Some(options))
            .unwrap();

        let mut public_key = public_key;
        let key_id = public_key.create_key_id().to_string();
        let raw_hash = hmac_sha256::Hash::hash(&public_key.to_bytes());
        assert_eq!(key_id, b64(&raw_hash));
    }

    #[test]
    fn webcrypto_exports() {
        for export in jwk_test_vectors::ALL {
            let export = json(export);
            let entry = &export["keys"]["Ed25519"];
            let key_pair = Ed25519KeyPair::from_jwk(&entry["private"].to_string()).unwrap();
            let public_key = Ed25519PublicKey::from_jwk(&entry["public"].to_string()).unwrap();
            assert_eq!(key_pair.jwk_thumbprint(), public_key.jwk_thumbprint());
            let jwt = entry["jwt"].as_str().unwrap();
            let claims = public_key
                .verify_token::<NoCustomClaims>(jwt, None)
                .unwrap();
            assert_eq!(claims.subject.as_deref(), Some("Ed25519"));

            for other in ["ES256", "X25519", "RS256", "ML-DSA-44"] {
                let other_key = &export["keys"][other]["public"];
                if !other_key.is_null() {
                    assert!(
                        Ed25519PublicKey::from_jwk(&other_key.to_string()).is_err(),
                        "{}",
                        other
                    );
                }
            }
        }
    }

    fn resign_with_alg(key_pair: &Ed25519KeyPair, token: &str, alg: &str) -> String {
        let mut parts = token.split('.');
        let mut header: serde_json::Value =
            serde_json::from_slice(&unb64(parts.next().unwrap())).unwrap();
        header["alg"] = alg.into();
        let claims = parts.next().unwrap();
        let signed = format!("{}.{}", b64(header.to_string().as_bytes()), claims);
        let signature = key_pair.key_pair().as_ref().sk.sign(&signed, None);
        format!("{}.{}", signed, b64(&signature[..]))
    }

    struct CustomVerifier {
        pk: Edwards25519PublicKey,
        key_id: Option<String>,
    }

    impl EdDSAPublicKeyLike for CustomVerifier {
        fn jwt_alg_name() -> &'static str {
            "EdDSA"
        }

        fn public_key(&self) -> &Edwards25519PublicKey {
            &self.pk
        }

        fn key_id(&self) -> &Option<String> {
            &self.key_id
        }

        fn set_key_id(&mut self, key_id: String) {
            self.key_id = Some(key_id);
        }
    }

    #[test]
    fn both_algorithm_names_verify() {
        let key_pair = Ed25519KeyPair::generate();
        let public_key = key_pair.public_key();
        let token = key_pair
            .sign(Claims::create(coarsetime::Duration::from_hours(1)))
            .unwrap();
        assert_eq!(Token::decode_metadata(&token).unwrap().algorithm(), "EdDSA");

        let ed25519_token = resign_with_alg(&key_pair, &token, "Ed25519");
        for token in [&token, &ed25519_token] {
            public_key
                .verify_token::<NoCustomClaims>(token, None)
                .unwrap();
        }
        for alg in ["ED25519", "Ed448", "ES256", "none"] {
            let token = resign_with_alg(&key_pair, &token, alg);
            assert!(
                matches!(
                    error_of(public_key.verify_token::<NoCustomClaims>(&token, None)),
                    JWTError::AlgorithmMismatch
                ),
                "{}",
                alg
            );
        }

        // Other implementations of the trait only accept `EdDSA`.
        let custom = CustomVerifier {
            pk: public_key.pk.clone(),
            key_id: None,
        };
        custom.verify_token::<NoCustomClaims>(&token, None).unwrap();
        assert!(matches!(
            error_of(custom.verify_token::<NoCustomClaims>(&ed25519_token, None)),
            JWTError::AlgorithmMismatch
        ));

        // Changing the algorithm name must invalidate the signature.
        let mut parts: Vec<&str> = ed25519_token.split('.').collect();
        let original_header = token.split('.').next().unwrap();
        parts[0] = original_header;
        assert!(public_key
            .verify_token::<NoCustomClaims>(&parts.join("."), None)
            .is_err());
    }
}
