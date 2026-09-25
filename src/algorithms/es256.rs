use std::convert::{TryFrom, TryInto};

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use p256::ecdsa::{self, signature::DigestVerifier as _, signature::RandomizedDigestSigner as _};
use p256::elliptic_curve::Generate as _;
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use p256::NonZeroScalar;
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

const ES256_PUBLIC_JWK: JwkDescriptor = JwkDescriptor::new(
    KeyType::Ec,
    Some("P-256"),
    "ES256",
    KeyRole::SignaturePublic,
);
const ES256_PRIVATE_JWK: JwkDescriptor = ES256_PUBLIC_JWK.with_role(KeyRole::SignaturePrivate);

#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct P256PublicKey(ecdsa::VerifyingKey);

impl AsRef<ecdsa::VerifyingKey> for P256PublicKey {
    fn as_ref(&self) -> &ecdsa::VerifyingKey {
        &self.0
    }
}

impl P256PublicKey {
    pub(crate) fn from_jwk(jwk: &str) -> Result<(Self, Option<String>), Error> {
        let jwk = Jwk::parse(jwk, &ES256_PUBLIC_JWK)?;
        let point = ec_point(&jwk, 32).ok_or(JWTError::InvalidPublicKey)?;
        let pk = Self::from_bytes(&point)?;
        Ok((pk, jwk.kid().map(Into::into)))
    }

    pub(crate) fn to_jwk(&self, key_id: Option<&str>) -> String {
        ec_export(
            &ES256_PUBLIC_JWK,
            &self.to_bytes_uncompressed(),
            None,
            key_id,
        )
    }

    pub(crate) fn jwk_thumbprint(&self) -> String {
        ec_thumbprint("P-256", &self.to_bytes_uncompressed())
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let p256_pk =
            ecdsa::VerifyingKey::from_sec1_bytes(raw).map_err(|_| JWTError::InvalidPublicKey)?;
        Ok(P256PublicKey(p256_pk))
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let p256_pk = ecdsa::VerifyingKey::from_public_key_der(der)
            .map_err(|_| JWTError::InvalidPublicKey)?;
        Ok(P256PublicKey(p256_pk))
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let p256_pk = ecdsa::VerifyingKey::from_public_key_pem(pem)
            .map_err(|_| JWTError::InvalidPublicKey)?;
        Ok(P256PublicKey(p256_pk))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_sec1_point(true).as_bytes().to_vec()
    }

    pub fn to_bytes_uncompressed(&self) -> Vec<u8> {
        self.0.to_sec1_point(false).as_bytes().to_vec()
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let p256_pk = p256::PublicKey::from(self.0);
        Ok(p256_pk
            .to_public_key_der()
            .map_err(|_| JWTError::InvalidPublicKey)?
            .as_ref()
            .to_vec())
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        let p256_pk = p256::PublicKey::from(self.0);
        Ok(p256_pk
            .to_public_key_pem(Default::default())
            .map_err(|_| JWTError::InvalidPublicKey)?)
    }
}

#[doc(hidden)]
pub struct P256KeyPair {
    p256_sk: ecdsa::SigningKey,
    metadata: Option<KeyMetadata>,
}

impl std::fmt::Debug for P256KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EcKey")
    }
}

impl AsRef<ecdsa::SigningKey> for P256KeyPair {
    fn as_ref(&self) -> &ecdsa::SigningKey {
        &self.p256_sk
    }
}

impl P256KeyPair {
    pub(crate) fn from_jwk(jwk: &str) -> Result<(Self, Option<String>), Error> {
        let jwk = Jwk::parse(jwk, &ES256_PRIVATE_JWK)?;
        let d = decode_secret(jwk.d(), 32).ok_or(JWTError::InvalidKeyPair)?;
        let key_pair = Self::from_bytes(&d)?;
        ensure!(
            ec_point_matches(&jwk, &key_pair.public_key().to_bytes_uncompressed()),
            JWTError::InvalidKeyPair
        );
        Ok((key_pair, jwk.kid().map(Into::into)))
    }

    pub(crate) fn to_jwk(&self, key_id: Option<&str>) -> String {
        let point = self.public_key().to_bytes_uncompressed();
        let d = zeroize::Zeroizing::new(self.p256_sk.to_bytes().to_vec());
        ec_export(&ES256_PRIVATE_JWK, &point, Some(&d), key_id)
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let raw: &p256::FieldBytes = raw.try_into().map_err(|_| JWTError::InvalidKeyPair)?;
        let p256_sk = ecdsa::SigningKey::from_bytes(raw).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(P256KeyPair {
            p256_sk,
            metadata: None,
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let p256_sk =
            ecdsa::SigningKey::from_pkcs8_der(der).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(P256KeyPair {
            p256_sk,
            metadata: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let p256_sk =
            ecdsa::SigningKey::from_pkcs8_pem(pem).map_err(|_| JWTError::InvalidKeyPair)?;
        Ok(P256KeyPair {
            p256_sk,
            metadata: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.p256_sk.to_bytes().to_vec()
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let scalar = NonZeroScalar::from_repr(self.p256_sk.to_bytes());
        if bool::from(scalar.is_none()) {
            return Err(JWTError::InvalidKeyPair.into());
        }
        let p256_sk =
            p256::SecretKey::from(NonZeroScalar::from_repr(scalar.unwrap().into()).unwrap());
        Ok(p256_sk
            .to_pkcs8_der()
            .map_err(|_| JWTError::InvalidKeyPair)?
            .as_bytes()
            .to_vec())
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        let scalar = NonZeroScalar::from_repr(self.p256_sk.to_bytes());
        if bool::from(scalar.is_none()) {
            return Err(JWTError::InvalidKeyPair.into());
        }
        let p256_sk =
            p256::SecretKey::from(NonZeroScalar::from_repr(scalar.unwrap().into()).unwrap());
        Ok(p256_sk
            .to_pkcs8_pem(Default::default())
            .map_err(|_| JWTError::InvalidKeyPair)?
            .to_string())
    }

    pub fn public_key(&self) -> P256PublicKey {
        let p256_pk = self.p256_sk.verifying_key();
        P256PublicKey(*p256_pk)
    }

    pub fn generate() -> Self {
        let mut rng = rand::rng();
        let p256_sk = ecdsa::SigningKey::generate_from_rng(&mut rng);
        P256KeyPair {
            p256_sk,
            metadata: None,
        }
    }
}

pub trait ECDSAP256KeyPairLike {
    fn jwt_alg_name() -> &'static str;
    fn key_pair(&self) -> &P256KeyPair;
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
                .sign_digest_with_rng(&mut rng, |digest: &mut hmac_sha256::Hash| {
                    digest.update(authenticated.as_bytes())
                });
            Ok(signature.to_vec())
        })
    }
}

pub trait ECDSAP256PublicKeyLike {
    fn jwt_alg_name() -> &'static str;
    fn public_key(&self) -> &P256PublicKey;
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
                        |digest: &mut hmac_sha256::Hash| {
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
                        |digest: &mut hmac_sha256::Hash| {
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

pub struct ES256KeyPair {
    key_pair: P256KeyPair,
    key_id: Option<String>,
}

impl std::fmt::Debug for ES256KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EcKey")
    }
}

#[derive(Debug, Clone)]
pub struct ES256PublicKey {
    pk: P256PublicKey,
    key_id: Option<String>,
}

impl ECDSAP256KeyPairLike for ES256KeyPair {
    fn jwt_alg_name() -> &'static str {
        "ES256"
    }

    fn key_pair(&self) -> &P256KeyPair {
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

impl ES256KeyPair {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(ES256KeyPair {
            key_pair: P256KeyPair::from_bytes(raw)?,
            key_id: None,
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(ES256KeyPair {
            key_pair: P256KeyPair::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(ES256KeyPair {
            key_pair: P256KeyPair::from_pem(pem)?,
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

    pub fn public_key(&self) -> ES256PublicKey {
        ES256PublicKey {
            pk: self.key_pair.public_key(),
            key_id: self.key_id.clone(),
        }
    }

    pub fn generate() -> Self {
        ES256KeyPair {
            key_pair: P256KeyPair::generate(),
            key_id: None,
        }
    }

    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }

    /// Import a key pair from a private JWK (`kty: EC`, `crv: P-256`).
    ///
    /// See [strict JWK validation](crate#strict-jwk-validation) for the rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let (key_pair, key_id) = P256KeyPair::from_jwk(jwk)?;
        Ok(ES256KeyPair { key_pair, key_id })
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

impl ECDSAP256PublicKeyLike for ES256PublicKey {
    fn jwt_alg_name() -> &'static str {
        "ES256"
    }

    fn public_key(&self) -> &P256PublicKey {
        &self.pk
    }

    fn key_id(&self) -> &Option<String> {
        &self.key_id
    }

    fn set_key_id(&mut self, key_id: String) {
        self.key_id = Some(key_id);
    }
}

impl ES256PublicKey {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        Ok(ES256PublicKey {
            pk: P256PublicKey::from_bytes(raw)?,
            key_id: None,
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Ok(ES256PublicKey {
            pk: P256PublicKey::from_der(der)?,
            key_id: None,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(ES256PublicKey {
            pk: P256PublicKey::from_pem(pem)?,
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

    /// Import a public key from a JWK (`kty: EC`, `crv: P-256`).
    ///
    /// See [strict JWK validation](crate#strict-jwk-validation) for the rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let (pk, key_id) = P256PublicKey::from_jwk(jwk)?;
        Ok(ES256PublicKey { pk, key_id })
    }

    /// Export the public key as a JWK, with `alg: ES256` and `use: sig`.
    pub fn to_jwk(&self) -> String {
        self.pk.to_jwk(self.key_id.as_deref())
    }

    /// The JWK thumbprint of the key.
    pub fn jwk_thumbprint(&self) -> String {
        self.pk.jwk_thumbprint()
    }
}

#[cfg(test)]
mod jwk_tests {
    use crate::algorithms::jwk_test_vectors;
    use crate::algorithms::test_util::{b64, error_of, json, member_bytes, unb64, with, without};
    use crate::prelude::*;
    use crate::JWTError;

    // Thumbprints computed with jwcrypto 1.5.6.
    const P256: &str = r#"{"kty":"EC","crv":"P-256",
        "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"}"#;
    const P256_THUMBPRINT: &str = "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s";
    const P384: &str = r#"{"kty":"EC","crv":"P-384",
        "x":"LUwGxVN6rAonzPWy9u0PjghkPwE4CHit0QJ5kGzDqg8oGYav-Ln8veWuBTIz0h-e",
        "y":"U-AWY87B3rceQqi6QYg8-RYj4LZsejs1NdqTD3ueSanvFGtPpBVpURzfFFhNstIt",
        "d":"t8OYG13e1MHzM_oUKHTPZtgc0Z8WHi95AB2XVcF3N27UelbAVnqKxERaNbsir7ec"}"#;
    const P384_THUMBPRINT: &str = "X87vqkTYo4hKc59UwU-zy0NKzDsrgMRum4flPbRwXVs";
    const K256: &str = r#"{"kty":"EC","crv":"secp256k1",
        "x":"EyvzgldJCeQIOPfRJ9oZO3rVVzS8ZlFtgToMR2OWSuE",
        "y":"JlvzSwhNHfvBwDiRfgsJuT1zjRSTDzZpASPlUSmi8tA",
        "d":"hwiWAz2LjbQMp9MEzs9YzNvmcPkvJt5i-fc7kgceObk"}"#;
    const K256_THUMBPRINT: &str = "sCqxz4FJp22HsNYDd_gawjMoBLsFAaQixbb8JSoXRrA";

    #[test]
    fn independent_thumbprints() {
        let key_pair = ES256KeyPair::from_jwk(P256).unwrap();
        assert_eq!(key_pair.jwk_thumbprint(), P256_THUMBPRINT);
        let public = ES256PublicKey::from_jwk(&without(P256, &["d"])).unwrap();
        assert_eq!(public.jwk_thumbprint(), P256_THUMBPRINT);

        let key_pair = ES384KeyPair::from_jwk(P384).unwrap();
        assert_eq!(key_pair.jwk_thumbprint(), P384_THUMBPRINT);
        assert_eq!(key_pair.public_key().jwk_thumbprint(), P384_THUMBPRINT);

        let key_pair = ES256kKeyPair::from_jwk(K256).unwrap();
        assert_eq!(key_pair.jwk_thumbprint(), K256_THUMBPRINT);
        assert_eq!(key_pair.public_key().jwk_thumbprint(), K256_THUMBPRINT);
    }

    macro_rules! round_trip {
        ($key_pair:ident, $public_key:ident, $crv:expr, $alg:expr, $size:expr) => {{
            let key_pair = $key_pair::generate().with_key_id("k1");
            let private_jwk = key_pair.to_jwk();
            let public_jwk = key_pair.public_key().to_jwk();
            let exported = json(&public_jwk);
            assert_eq!(exported["kty"], "EC");
            assert_eq!(exported["crv"], $crv);
            assert_eq!(exported["alg"], $alg);
            assert_eq!(exported["use"], "sig");
            assert_eq!(exported["kid"], "k1");
            assert!(exported.get("d").is_none());
            assert_eq!(member_bytes(&public_jwk, "x").len(), $size);
            assert_eq!(member_bytes(&public_jwk, "y").len(), $size);
            assert_eq!(member_bytes(&private_jwk, "d").len(), $size);

            let restored = $key_pair::from_jwk(&private_jwk).unwrap();
            let public_key = $public_key::from_jwk(&public_jwk).unwrap();
            assert_eq!(restored.to_bytes(), key_pair.to_bytes());
            assert_eq!(restored.to_jwk(), private_jwk);
            assert_eq!(public_key.to_jwk(), public_jwk);
            assert_eq!(restored.jwk_thumbprint(), public_key.jwk_thumbprint());

            let token = restored
                .sign(Claims::create(Duration::from_hours(1)))
                .unwrap();
            let options = VerificationOptions {
                required_key_id: Some("k1".into()),
                ..Default::default()
            };
            public_key
                .verify_token::<NoCustomClaims>(&token, Some(options))
                .unwrap();
        }};
    }

    #[test]
    fn round_trips() {
        round_trip!(ES256KeyPair, ES256PublicKey, "P-256", "ES256", 32);
        round_trip!(ES384KeyPair, ES384PublicKey, "P-384", "ES384", 48);
        round_trip!(ES256kKeyPair, ES256kPublicKey, "secp256k1", "ES256K", 32);
    }

    #[test]
    fn coordinates_are_full_size_and_checked_one_by_one() {
        let key_pair = (0..10_000)
            .map(|_| ES256KeyPair::generate())
            .find(|kp| kp.public_key().public_key().to_bytes_uncompressed()[1] == 0)
            .unwrap();
        let public_jwk = key_pair.public_key().to_jwk();
        let x = member_bytes(&public_jwk, "x");
        assert_eq!(x.len(), 32);
        assert_eq!(x[0], 0);
        ES256PublicKey::from_jwk(&public_jwk).unwrap();
        ES256KeyPair::from_jwk(&key_pair.to_jwk()).unwrap();

        let short = with(&public_jwk, "x", b64(&x[1..]).into());
        assert!(matches!(
            error_of(ES256PublicKey::from_jwk(&short)),
            JWTError::InvalidPublicKey
        ));

        let public_jwk = without(P256, &["d"]);
        let x = member_bytes(P256, "x");
        let y = member_bytes(P256, "y");
        let xy = [&x[..], &y[..]].concat();
        // A valid point must still have two full-length coordinates.
        for split in [31, 33] {
            let jwk = with(&public_jwk, "x", b64(&xy[..split]).into());
            let jwk = with(&jwk, "y", b64(&xy[split..]).into());
            assert!(
                matches!(
                    error_of(ES256PublicKey::from_jwk(&jwk)),
                    JWTError::InvalidPublicKey
                ),
                "{}",
                split
            );
        }
        let mut off_curve = y.clone();
        off_curve[31] ^= 1;
        let jwk = with(&public_jwk, "y", b64(&off_curve).into());
        assert!(ES256PublicKey::from_jwk(&jwk).is_err());
        assert!(ES256PublicKey::from_jwk(&without(&public_jwk, &["y"])).is_err());
    }

    #[test]
    fn private_scalar_must_be_valid_and_match() {
        let order = "_____wAAAAD__________7zm-q2nF56E87nKwvxjJVE";
        assert_eq!(unb64(order).len(), 32);
        let other = json(&ES256KeyPair::generate().to_jwk());
        for (case, d) in [
            ("zero", b64(&[0u8; 32])),
            ("group order", order.to_string()),
            ("other key", other["d"].as_str().unwrap().to_string()),
            ("short", b64(&member_bytes(P256, "d")[1..])),
        ] {
            let jwk = with(P256, "d", d.into());
            assert!(
                matches!(
                    error_of(ES256KeyPair::from_jwk(&jwk)),
                    JWTError::InvalidKeyPair
                ),
                "{}",
                case
            );
        }
        assert!(ES256KeyPair::from_jwk(&without(P256, &["y"])).is_err());
    }

    #[test]
    fn keys_only_load_into_their_own_type() {
        let p256_public = without(P256, &["d"]);
        assert!(ES384PublicKey::from_jwk(&p256_public).is_err());
        assert!(ES256kPublicKey::from_jwk(&p256_public).is_err());
        assert!(ES256KeyPair::from_jwk(&without(P384, &["d"])).is_err());

        ES256PublicKey::from_jwk(&with(&p256_public, "alg", "ES256".into())).unwrap();
        let mut rejected = vec![
            with(&p256_public, "crv", "secp256k1".into()),
            with(&p256_public, "use", "enc".into()),
            with(&p256_public, "key_ops", serde_json::json!(["deriveBits"])),
        ];
        for alg in [
            "ES384",
            "ES256K",
            "ECDH-ES+A256KW",
            "ECDH",
            "EdDSA",
            "RS256",
        ] {
            rejected.push(with(&p256_public, "alg", alg.into()));
        }
        for jwk in rejected {
            assert!(ES256PublicKey::from_jwk(&jwk).is_err(), "{}", jwk);
        }
    }

    #[test]
    fn webcrypto_exports() {
        for export in jwk_test_vectors::ALL {
            let export = json(export);
            let entry = &export["keys"]["ES256"];
            let key_pair = ES256KeyPair::from_jwk(&entry["private"].to_string()).unwrap();
            let public_key = ES256PublicKey::from_jwk(&entry["public"].to_string()).unwrap();
            assert_eq!(key_pair.jwk_thumbprint(), public_key.jwk_thumbprint());
            public_key
                .verify_token::<NoCustomClaims>(entry["jwt"].as_str().unwrap(), None)
                .unwrap();

            let entry = &export["keys"]["ES384"];
            let key_pair = ES384KeyPair::from_jwk(&entry["private"].to_string()).unwrap();
            let public_key = ES384PublicKey::from_jwk(&entry["public"].to_string()).unwrap();
            assert_eq!(key_pair.jwk_thumbprint(), public_key.jwk_thumbprint());
            public_key
                .verify_token::<NoCustomClaims>(entry["jwt"].as_str().unwrap(), None)
                .unwrap();

            // Without usage information, ECDH public keys look like signing keys.
            let ecdh = &export["keys"]["ECDH-P256"];
            let labeled = ecdh["public"].get("alg").is_some();
            assert_eq!(
                ES256PublicKey::from_jwk(&ecdh["public"].to_string()).is_err(),
                labeled
            );
            assert!(ES256KeyPair::from_jwk(&ecdh["private"].to_string()).is_err());
        }
    }
}
