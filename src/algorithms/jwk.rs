//! JSON Web Key import and export for every asymmetric key type.
//!
//! A JWK only loads into the type it describes.
//! Its metadata can limit the key's use, but cannot choose the algorithm.

use std::collections::HashSet;
use std::fmt;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Serialize;
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::error::*;

/// Largest JWK document accepted, in bytes, whitespace and unknown members included.
/// Larger documents are rejected before being parsed.
///
/// A complete 4096-bit RSA private key takes about 3.2 KB.
pub const MAX_JWK_LENGTH: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyType {
    Okp,
    Ec,
    Rsa,
    Akp,
}

impl KeyType {
    fn name(self) -> &'static str {
        match self {
            KeyType::Okp => "OKP",
            KeyType::Ec => "EC",
            KeyType::Rsa => "RSA",
            KeyType::Akp => "AKP",
        }
    }

    fn public_members(self) -> &'static [&'static str] {
        match self {
            KeyType::Okp => &["crv", "x"],
            KeyType::Ec => &["crv", "x", "y"],
            KeyType::Rsa => &["n", "e"],
            KeyType::Akp => &["pub"],
        }
    }

    fn private_members(self) -> &'static [&'static str] {
        match self {
            KeyType::Okp | KeyType::Ec => &["d"],
            KeyType::Rsa => &["d", "p", "q", "dp", "dq", "qi"],
            KeyType::Akp => &["priv"],
        }
    }
}

/// Used to reject key material belonging to another key type.
const MATERIAL_MEMBERS: [&str; 15] = [
    "crv", "x", "y", "d", "n", "e", "p", "q", "dp", "dq", "qi", "oth", "k", "pub", "priv",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyRole {
    SignaturePublic,
    SignaturePrivate,
    #[cfg(feature = "jwe")]
    AgreementPublic,
    #[cfg(feature = "jwe")]
    AgreementPrivate,
    #[cfg(feature = "jwe")]
    EncryptionPublic,
    #[cfg(feature = "jwe")]
    DecryptionPrivate,
}

impl KeyRole {
    fn is_private(self) -> bool {
        match self {
            KeyRole::SignaturePublic => false,
            KeyRole::SignaturePrivate => true,
            #[cfg(feature = "jwe")]
            KeyRole::AgreementPublic | KeyRole::EncryptionPublic => false,
            #[cfg(feature = "jwe")]
            KeyRole::AgreementPrivate | KeyRole::DecryptionPrivate => true,
        }
    }

    fn key_use(self) -> &'static str {
        match self {
            KeyRole::SignaturePublic | KeyRole::SignaturePrivate => "sig",
            #[cfg(feature = "jwe")]
            _ => "enc",
        }
    }

    fn allowed_operations(self) -> &'static [&'static str] {
        match self {
            KeyRole::SignaturePublic => &["verify"],
            KeyRole::SignaturePrivate => &["sign", "verify"],
            #[cfg(feature = "jwe")]
            KeyRole::AgreementPublic | KeyRole::AgreementPrivate => &["deriveKey", "deriveBits"],
            #[cfg(feature = "jwe")]
            KeyRole::EncryptionPublic => &["encrypt", "wrapKey"],
            #[cfg(feature = "jwe")]
            KeyRole::DecryptionPrivate => &["decrypt", "unwrapKey"],
        }
    }

    fn error(self) -> JWTError {
        if self.is_private() {
            JWTError::InvalidKeyPair
        } else {
            JWTError::InvalidPublicKey
        }
    }
}

/// What a concrete key type accepts and exports.
#[derive(Clone, Copy)]
pub(crate) struct JwkDescriptor {
    pub kty: KeyType,
    pub crv: Option<&'static str>,
    /// Algorithm name written on export, and accepted on import.
    pub alg: &'static str,
    /// Other names accepted on import for the same algorithm.
    pub alg_aliases: &'static [&'static str],
    pub role: KeyRole,
}

impl JwkDescriptor {
    pub(crate) const fn new(
        kty: KeyType,
        crv: Option<&'static str>,
        alg: &'static str,
        role: KeyRole,
    ) -> Self {
        JwkDescriptor {
            kty,
            crv,
            alg,
            alg_aliases: &[],
            role,
        }
    }

    pub(crate) const fn with_aliases(mut self, alg_aliases: &'static [&'static str]) -> Self {
        self.alg_aliases = alg_aliases;
        self
    }

    pub(crate) const fn with_role(mut self, role: KeyRole) -> Self {
        self.role = role;
        self
    }

    pub(crate) fn error(&self) -> JWTError {
        self.role.error()
    }

    /// Reserves enough space to avoid leaving secret copies behind when the buffer grows.
    pub(crate) fn export<'a>(&self, mut members: JwkMembers<'a>, kid: Option<&'a str>) -> String {
        members.kty = Some(self.kty.name());
        members.crv = self.crv;
        members.alg = Some(self.alg);
        members.key_use = Some(self.role.key_use());
        members.kid = kid;
        let capacity = MAX_JWK_LENGTH + 6 * kid.map_or(0, str::len);
        let mut out = Vec::with_capacity(capacity);
        serde_json::to_writer(&mut out, &members).expect("JWK serialization");
        String::from_utf8(out).expect("JWK serialization")
    }
}

/// Key material is borrowed from the document, so that secret values are not copied.
#[derive(Default)]
struct Members<'a> {
    names: HashSet<String>,
    kty: Option<String>,
    crv: Option<String>,
    alg: Option<String>,
    key_use: Option<String>,
    kid: Option<String>,
    key_ops: Option<Vec<String>>,
    x: Option<&'a str>,
    y: Option<&'a str>,
    d: Option<&'a str>,
    n: Option<&'a str>,
    e: Option<&'a str>,
    p: Option<&'a str>,
    q: Option<&'a str>,
    dp: Option<&'a str>,
    dq: Option<&'a str>,
    qi: Option<&'a str>,
    public: Option<&'a str>,
    private: Option<&'a str>,
}

/// Rejects duplicate names so parsers cannot disagree about which value to use.
///
/// `deserialize_any` keeps serde_json's nesting limit in force, even for ignored fields.
pub(crate) struct UniqueMembers(pub Value);

impl<'de> Deserialize<'de> for UniqueMembers {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueMembersVisitor)
    }
}

struct UniqueMembersVisitor;

impl<'de> Visitor<'de> for UniqueMembersVisitor {
    type Value = UniqueMembers;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<UniqueMembers, E> {
        Ok(UniqueMembers(Value::Bool(v)))
    }

    fn visit_i64<E>(self, v: i64) -> Result<UniqueMembers, E> {
        Ok(UniqueMembers(Value::from(v)))
    }

    fn visit_u64<E>(self, v: u64) -> Result<UniqueMembers, E> {
        Ok(UniqueMembers(Value::from(v)))
    }

    fn visit_f64<E>(self, v: f64) -> Result<UniqueMembers, E> {
        Ok(UniqueMembers(Value::from(v)))
    }

    fn visit_str<E>(self, v: &str) -> Result<UniqueMembers, E> {
        Ok(UniqueMembers(Value::String(v.to_string())))
    }

    fn visit_string<E>(self, v: String) -> Result<UniqueMembers, E> {
        Ok(UniqueMembers(Value::String(v)))
    }

    fn visit_unit<E>(self) -> Result<UniqueMembers, E> {
        Ok(UniqueMembers(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<UniqueMembers, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element::<UniqueMembers>()? {
            values.push(value.0);
        }
        Ok(UniqueMembers(Value::Array(values)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<UniqueMembers, A::Error> {
        let mut members = Map::new();
        while let Some(name) = map.next_key::<String>()? {
            if members.contains_key(&name) {
                return Err(de::Error::custom("duplicate member"));
            }
            let value = map.next_value::<UniqueMembers>()?;
            members.insert(name, value.0);
        }
        Ok(UniqueMembers(Value::Object(members)))
    }
}

impl<'de> Deserialize<'de> for Members<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(MembersVisitor)
    }
}

struct MembersVisitor;

impl<'de> Visitor<'de> for MembersVisitor {
    type Value = Members<'de>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JWK object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Members<'de>, A::Error> {
        let mut members = Members::default();
        while let Some(name) = map.next_key::<String>()? {
            // Borrowing rejects escaped key material, which base64url never needs.
            match name.as_str() {
                "kty" => members.kty = Some(map.next_value()?),
                "crv" => members.crv = Some(map.next_value()?),
                "alg" => members.alg = Some(map.next_value()?),
                "use" => members.key_use = Some(map.next_value()?),
                "kid" => members.kid = Some(map.next_value()?),
                "key_ops" => members.key_ops = Some(map.next_value()?),
                "x" => members.x = Some(map.next_value()?),
                "y" => members.y = Some(map.next_value()?),
                "d" => members.d = Some(map.next_value()?),
                "n" => members.n = Some(map.next_value()?),
                "e" => members.e = Some(map.next_value()?),
                "p" => members.p = Some(map.next_value()?),
                "q" => members.q = Some(map.next_value()?),
                "dp" => members.dp = Some(map.next_value()?),
                "dq" => members.dq = Some(map.next_value()?),
                "qi" => members.qi = Some(map.next_value()?),
                "pub" => members.public = Some(map.next_value()?),
                "priv" => members.private = Some(map.next_value()?),
                _ => {
                    map.next_value::<UniqueMembers>()?;
                }
            }
            // Names are compared after unescaping, so "k\u0074y" is a duplicate of "kty".
            if !members.names.insert(name) {
                return Err(de::Error::custom("duplicate JWK member"));
            }
        }
        Ok(members)
    }
}

/// A JWK that passed the checks shared by every key type, for a given descriptor.
pub(crate) struct Jwk<'a> {
    members: Members<'a>,
}

impl<'a> Jwk<'a> {
    pub(crate) fn parse(json: &'a str, descriptor: &JwkDescriptor) -> Result<Self, Error> {
        ensure!(json.len() <= MAX_JWK_LENGTH, descriptor.error());
        let members: Members<'a> = serde_json::from_str(json).map_err(|_| descriptor.error())?;
        Self::check(members, descriptor)
    }

    /// The caller must reject duplicate members before building the `Value`.
    #[cfg(feature = "jwe")]
    pub(crate) fn from_value(
        value: &'a serde_json::Value,
        descriptor: &JwkDescriptor,
    ) -> Result<Self, Error> {
        let members = Members::deserialize(value).map_err(|_| descriptor.error())?;
        Self::check(members, descriptor)
    }

    fn check(members: Members<'a>, descriptor: &JwkDescriptor) -> Result<Self, Error> {
        let error = || descriptor.error();
        let kty = descriptor.kty;
        let private = descriptor.role.is_private();

        ensure!(members.kty.as_deref() == Some(kty.name()), error());
        ensure!(members.crv.as_deref() == descriptor.crv, error());

        let public_members = kty.public_members();
        let private_members = kty.private_members();
        for name in &members.names {
            if !MATERIAL_MEMBERS.contains(&name.as_str()) {
                continue;
            }
            let own_public = public_members.contains(&name.as_str());
            let own_private = private_members.contains(&name.as_str());
            ensure!(own_public || (private && own_private), error());
        }
        let present = |name: &&str| members.names.contains(*name);
        ensure!(public_members.iter().all(present), error());
        if private {
            ensure!(private_members.iter().all(present), error());
        }

        match &members.alg {
            Some(alg) => ensure!(
                alg == descriptor.alg || descriptor.alg_aliases.contains(&alg.as_str()),
                error()
            ),
            None => ensure!(kty != KeyType::Akp, error()),
        }
        if let Some(key_use) = &members.key_use {
            ensure!(key_use == descriptor.role.key_use(), error());
        }
        if let Some(key_ops) = &members.key_ops {
            let allowed = descriptor.role.allowed_operations();
            let mut seen = HashSet::new();
            for op in key_ops {
                ensure!(allowed.contains(&op.as_str()), error());
                ensure!(seen.insert(op.as_str()), error());
            }
            // WebCrypto exports public ECDH keys with an empty operation list.
            if private {
                ensure!(!key_ops.is_empty(), error());
            }
            if descriptor.role == KeyRole::SignaturePrivate {
                ensure!(seen.contains("sign"), error());
            }
        }
        Ok(Jwk { members })
    }

    pub(crate) fn kid(&self) -> Option<&str> {
        self.members.kid.as_deref()
    }

    pub(crate) fn x(&self) -> &'a str {
        self.members.x.unwrap_or_default()
    }

    pub(crate) fn y(&self) -> &'a str {
        self.members.y.unwrap_or_default()
    }

    pub(crate) fn d(&self) -> &'a str {
        self.members.d.unwrap_or_default()
    }

    pub(crate) fn n(&self) -> &'a str {
        self.members.n.unwrap_or_default()
    }

    pub(crate) fn e(&self) -> &'a str {
        self.members.e.unwrap_or_default()
    }

    pub(crate) fn p(&self) -> &'a str {
        self.members.p.unwrap_or_default()
    }

    pub(crate) fn q(&self) -> &'a str {
        self.members.q.unwrap_or_default()
    }

    pub(crate) fn dp(&self) -> &'a str {
        self.members.dp.unwrap_or_default()
    }

    pub(crate) fn dq(&self) -> &'a str {
        self.members.dq.unwrap_or_default()
    }

    pub(crate) fn qi(&self) -> &'a str {
        self.members.qi.unwrap_or_default()
    }

    pub(crate) fn public(&self) -> &'a str {
        self.members.public.unwrap_or_default()
    }

    pub(crate) fn private(&self) -> &'a str {
        self.members.private.unwrap_or_default()
    }
}

/// Decodes a fixed-size value, accepting only its canonical unpadded base64url encoding.
pub(crate) fn decode_fixed(b64: &str, out: &mut [u8]) -> bool {
    match Base64UrlSafeNoPadding::encoded_len(out.len()) {
        Ok(len) if len == b64.len() => {}
        _ => return false,
    }
    let expected = out.len();
    matches!(
        Base64UrlSafeNoPadding::decode(out, b64, None),
        Ok(decoded) if decoded.len() == expected
    )
}

/// Builds an uncompressed EC point, checking each coordinate's size separately.
pub(crate) fn ec_point(jwk: &Jwk<'_>, size: usize) -> Option<Vec<u8>> {
    let mut point = vec![0u8; 1 + 2 * size];
    point[0] = 0x04;
    let (x, y) = point[1..].split_at_mut(size);
    if decode_fixed(jwk.x(), x) && decode_fixed(jwk.y(), y) {
        Some(point)
    } else {
        None
    }
}

pub(crate) fn decode_secret(b64: &str, size: usize) -> Option<Zeroizing<Vec<u8>>> {
    let mut secret = Zeroizing::new(vec![0u8; size]);
    if decode_fixed(b64, &mut secret) {
        Some(secret)
    } else {
        None
    }
}

/// Comparing the encodings also rejects alternate spellings of the same value.
pub(crate) fn is_encoding_of(b64: &str, derived: &[u8]) -> bool {
    b64 == encode(derived)
}

pub(crate) fn ec_point_matches(jwk: &Jwk<'_>, point: &[u8]) -> bool {
    let (x, y) = ec_coordinates(point);
    jwk.x() == x && jwk.y() == y
}

fn ec_coordinates(point: &[u8]) -> (String, String) {
    let size = (point.len() - 1) / 2;
    (encode(&point[1..1 + size]), encode(&point[1 + size..]))
}

/// `point` must be an uncompressed EC point.
pub(crate) fn ec_export(
    descriptor: &JwkDescriptor,
    point: &[u8],
    d: Option<&[u8]>,
    kid: Option<&str>,
) -> String {
    let (x, y) = ec_coordinates(point);
    let d = d.map(encode_secret);
    let members = JwkMembers {
        x: Some(&x),
        y: Some(&y),
        d: d.as_deref().map(String::as_str),
        ..Default::default()
    };
    descriptor.export(members, kid)
}

pub(crate) fn okp_export(
    descriptor: &JwkDescriptor,
    x: &[u8],
    d: Option<&[u8]>,
    kid: Option<&str>,
) -> String {
    let x = encode(x);
    let d = d.map(encode_secret);
    let members = JwkMembers {
        x: Some(&x),
        d: d.as_deref().map(String::as_str),
        ..Default::default()
    };
    descriptor.export(members, kid)
}

pub(crate) fn okp_thumbprint(crv: &str, x: &[u8]) -> String {
    thumbprint(&[("crv", crv), ("kty", "OKP"), ("x", &encode(x))])
}

pub(crate) fn ec_thumbprint(crv: &str, point: &[u8]) -> String {
    let (x, y) = ec_coordinates(point);
    thumbprint(&[("crv", crv), ("kty", "EC"), ("x", &x), ("y", &y)])
}

/// Largest RSA modulus or private value accepted from a JWK, in bytes (4096 bits).
const MAX_RSA_INTEGER_BYTES: usize = 512;

fn decode_bounded(b64: &str, max_len: usize) -> Result<Zeroizing<Vec<u8>>, DecodeError> {
    let max_encoded_len =
        Base64UrlSafeNoPadding::encoded_len(max_len).map_err(|_| DecodeError::Invalid)?;
    if b64.len() > max_encoded_len {
        return Err(DecodeError::TooLong);
    }
    let mut buf = Zeroizing::new(vec![0u8; max_len]);
    let len = Base64UrlSafeNoPadding::decode(&mut buf, b64, None)
        .map_err(|_| DecodeError::Invalid)?
        .len();
    buf.truncate(len);
    Ok(buf)
}

enum DecodeError {
    Invalid,
    TooLong,
}

/// Accepts the leading sign byte added by Java's BigInteger, used by PayPal and Yahoo.
/// All other leading zeros are rejected.
pub(crate) fn rsa_modulus(b64: &str, descriptor: &JwkDescriptor) -> Result<Vec<u8>, Error> {
    let n = decode_bounded(b64, MAX_RSA_INTEGER_BYTES + 1).map_err(|e| match e {
        DecodeError::TooLong => JWTError::UnsupportedRSAModulus,
        DecodeError::Invalid => descriptor.error(),
    })?;
    let n = match n.as_slice() {
        [0, top, ..] if top & 0x80 != 0 => &n[1..],
        n => n,
    };
    ensure!(n.first().is_some_and(|&top| top != 0), descriptor.error());
    Ok(n.to_vec())
}

pub(crate) fn rsa_private_integer(
    b64: &str,
    descriptor: &JwkDescriptor,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let x = decode_bounded(b64, MAX_RSA_INTEGER_BYTES).map_err(|_| descriptor.error())?;
    ensure!(x.first().is_some_and(|&top| top != 0), descriptor.error());
    Ok(x)
}

pub(crate) fn rsa_thumbprint(n: &[u8], e: &[u8]) -> String {
    thumbprint(&[("e", &encode(e)), ("kty", "RSA"), ("n", &encode(n))])
}

pub(crate) fn encode(bin: &[u8]) -> String {
    Base64UrlSafeNoPadding::encode_to_string(bin).unwrap()
}

pub(crate) fn encode_secret(bin: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(encode(bin))
}

#[derive(Default, Serialize)]
pub(crate) struct JwkMembers<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kty: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<&'a str>,
    #[serde(rename = "pub", skip_serializing_if = "Option::is_none")]
    pub public: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dp: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dq: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qi: Option<&'a str>,
    #[serde(rename = "priv", skip_serializing_if = "Option::is_none")]
    pub private: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<&'a str>,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<&'a str>,
}

/// Members must be sorted by name, with no extra whitespace.
/// The caller must sort them and provide values that need no JSON escaping.
pub(crate) fn thumbprint(members: &[(&str, &str)]) -> String {
    let mut canonical = String::from("{");
    for (i, (name, value)) in members.iter().enumerate() {
        if i > 0 {
            canonical.push(',');
        }
        canonical.push('"');
        canonical.push_str(name);
        canonical.push_str("\":\"");
        canonical.push_str(value);
        canonical.push('"');
    }
    canonical.push('}');
    encode(&hmac_sha256::Hash::hash(canonical.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::MAX_JWK_LENGTH;
    use crate::prelude::*;
    use crate::JWTError;

    const X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    const D: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";

    fn public_jwk(extra: &str) -> String {
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"{}}}"#, X, extra)
    }

    fn private_jwk(extra: &str) -> String {
        format!(
            r#"{{"kty":"OKP","crv":"Ed25519","x":"{}","d":"{}"{}}}"#,
            X, D, extra
        )
    }

    fn public_rejected(jwk: &str) -> bool {
        let err = Ed25519PublicKey::from_jwk(jwk).err();
        matches!(
            err.as_ref().and_then(|err| err.downcast_ref::<JWTError>()),
            Some(JWTError::InvalidPublicKey)
        )
    }

    fn private_rejected(jwk: &str) -> bool {
        let err = Ed25519KeyPair::from_jwk(jwk).err();
        matches!(
            err.as_ref().and_then(|err| err.downcast_ref::<JWTError>()),
            Some(JWTError::InvalidKeyPair)
        )
    }

    #[test]
    fn metadata_must_match_the_key_type() {
        for extra in [
            r#","alg":"EdDSA""#,
            r#","alg":"Ed25519""#,
            r#","use":"sig""#,
            r#","key_ops":["verify"]"#,
            r#","key_ops":[]"#,
            r#","kid":"key 1""#,
            r#","ext":true,"x5c":["MIIB"],"x5t":"abc","other":{"nested":[1,2,{"a":null}]}"#,
        ] {
            let jwk = public_jwk(extra);
            assert!(Ed25519PublicKey::from_jwk(&jwk).is_ok(), "{}", jwk);
        }
        for extra in [
            r#","alg":"ES256""#,
            r#","alg":"eddsa""#,
            r#","alg":"none""#,
            r#","use":"enc""#,
            r#","key_ops":["sign"]"#,
            r#","key_ops":["verify","verify"]"#,
            r#","key_ops":["verify","encrypt"]"#,
            r#","key_ops":["deriveBits"]"#,
            r#","key_ops":"verify""#,
            r#","key_ops":[1]"#,
        ] {
            assert!(public_rejected(&public_jwk(extra)), "{}", extra);
        }

        for extra in [
            "",
            r#","key_ops":["sign"]"#,
            r#","key_ops":["sign","verify"]"#,
            r#","key_ops":["verify","sign"]"#,
        ] {
            let jwk = private_jwk(extra);
            assert!(Ed25519KeyPair::from_jwk(&jwk).is_ok(), "{}", jwk);
        }
        for extra in [
            r#","key_ops":[]"#,
            r#","key_ops":["verify"]"#,
            r#","key_ops":["sign","sign"]"#,
            r#","key_ops":["sign","decrypt"]"#,
            r#","use":"enc""#,
            r#","alg":"RS256""#,
        ] {
            assert!(private_rejected(&private_jwk(extra)), "{}", extra);
        }
    }

    #[test]
    fn members_must_match_the_key_type() {
        for jwk in [
            format!(r#"{{"kty":"EC","crv":"Ed25519","x":"{}"}}"#, X),
            format!(r#"{{"kty":"okp","crv":"Ed25519","x":"{}"}}"#, X),
            format!(r#"{{"kty":"OKP","crv":"X25519","x":"{}"}}"#, X),
            format!(r#"{{"kty":"OKP","crv":"Ed448","x":"{}"}}"#, X),
            format!(r#"{{"kty":"OKP","x":"{}"}}"#, X),
            format!(r#"{{"crv":"Ed25519","x":"{}"}}"#, X),
            r#"{"kty":"OKP","crv":"Ed25519"}"#.to_string(),
            format!(r#"{{"kty":"oct","k":"{}"}}"#, X),
        ] {
            assert!(public_rejected(&jwk), "{}", jwk);
        }
        assert!(private_rejected(&public_jwk("")));

        for extra in [
            r#","y":"AAAA""#,
            r#","n":"AAAA""#,
            r#","e":"AQAB""#,
            r#","pub":"AAAA""#,
            r#","priv":"AAAA""#,
            r#","k":"AAAA""#,
            r#","oth":[]"#,
            r#","oth":null"#,
            r#","p":"AAAA""#,
        ] {
            assert!(public_rejected(&public_jwk(extra)), "{}", extra);
            assert!(private_rejected(&private_jwk(extra)), "{}", extra);
        }
        for extra in [
            format!(r#","d":"{}""#, D),
            r#","d":"""#.to_string(),
            r#","d":null"#.to_string(),
        ] {
            assert!(public_rejected(&public_jwk(&extra)), "{}", extra);
        }
    }

    #[test]
    fn duplicate_members_and_malformed_documents_are_rejected() {
        for jwk in [
            format!(r#"{{"kty":"OKP","kty":"OKP","crv":"Ed25519","x":"{}"}}"#, X),
            format!(
                r#"{{"kty":"OKP","k\u0074y":"OKP","crv":"Ed25519","x":"{}"}}"#,
                X
            ),
            format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{0}","x":"{0}"}}"#, X),
            format!(
                r#"{{"kty":"OKP","crv":"Ed25519","x":"{0}","\u0078":"{0}"}}"#,
                X
            ),
            public_jwk(r#","foo":1,"foo":1"#),
            public_jwk(r#","foo":{"a":1,"a":1}"#),
            public_jwk(r#","foo":[{"b":{"a":1,"\u0061":1}}]"#),
            public_jwk(r#","kid":"a","kid":"a""#),
            public_jwk(r#","kid":null"#),
            public_jwk(r#","alg":null"#),
            public_jwk(r#","use":null"#),
            public_jwk(r#","key_ops":null"#),
            public_jwk(r#","kid":1"#),
            public_jwk(r#","alg":true"#),
            r#"{"kty":"OKP","crv":"Ed25519","x":null}"#.to_string(),
            r#"{"kty":"OKP","crv":"Ed25519","x":42}"#.to_string(),
            format!(r#"{{"kty":["OKP"],"crv":"Ed25519","x":"{}"}}"#, X),
            format!("{} {{}}", public_jwk("")),
            format!("{}x", public_jwk("")),
            format!("[{}]", public_jwk("")),
            "null".to_string(),
            "\"\"".to_string(),
            String::new(),
        ] {
            assert!(public_rejected(&jwk), "{}", jwk);
        }
        Ed25519PublicKey::from_jwk(&format!(" \n\t{}\r\n ", public_jwk(""))).unwrap();
    }

    #[test]
    fn material_must_be_canonical_base64url() {
        assert!(X.ends_with('o'));
        for bad_x in [
            format!("{}=", X),
            X.replace('_', "/"),
            X[..42].to_string(),
            format!("{}A", X),
            // The same bytes as X, with a nonzero trailing bit.
            format!("{}p", &X[..42]),
            format!("{} {}", &X[..20], &X[20..]),
            // X itself, with its last character escaped.
            format!("{}\\u006f", &X[..42]),
            String::new(),
        ] {
            let jwk = format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#, bad_x);
            assert!(public_rejected(&jwk), "{}", jwk);
        }
    }

    #[test]
    fn document_size_and_nesting_depth_are_limited() {
        let base = public_jwk(r#","pad":"""#);
        let fill = MAX_JWK_LENGTH - base.len();
        let exact = public_jwk(&format!(r#","pad":"{}""#, "a".repeat(fill)));
        assert_eq!(exact.len(), MAX_JWK_LENGTH);
        Ed25519PublicKey::from_jwk(&exact).unwrap();

        let over = public_jwk(&format!(r#","pad":"{}""#, "a".repeat(fill + 1)));
        assert!(public_rejected(&over));
        let whitespace = format!("{}{}", public_jwk(""), " ".repeat(MAX_JWK_LENGTH));
        assert!(public_rejected(&whitespace));

        let nested = |depth: usize| {
            public_jwk(&format!(
                r#","ignored":{}{}"#,
                "[".repeat(depth),
                "]".repeat(depth)
            ))
        };
        Ed25519PublicKey::from_jwk(&nested(100)).unwrap();
        assert!(public_rejected(&nested(200)));
    }

    #[test]
    fn errors_and_debug_output_do_not_contain_secrets() {
        let mismatched_x = "Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4";
        let jwk = format!(
            r#"{{"kty":"OKP","crv":"Ed25519","x":"{}","d":"{}"}}"#,
            mismatched_x, D
        );
        let err = Ed25519KeyPair::from_jwk(&jwk).unwrap_err();
        for text in [format!("{}", err), format!("{:?}", err)] {
            assert!(!text.contains(D));
        }
        let key_pair = Ed25519KeyPair::from_jwk(&private_jwk("")).unwrap();
        assert!(!format!("{:?}", key_pair).contains(D));
        assert!(key_pair.to_jwk().contains(D));
        assert!(!key_pair.public_key().to_jwk().contains(D));
    }
}
