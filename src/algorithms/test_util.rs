//! Helpers shared by the JWK and JWE tests.

use ct_codecs::{Base64, Base64UrlSafeNoPadding, Decoder, Encoder};

use crate::{Error, JWTError};

pub(crate) fn b64(bin: &[u8]) -> String {
    Base64UrlSafeNoPadding::encode_to_string(bin).unwrap()
}

pub(crate) fn unb64(s: &str) -> Vec<u8> {
    Base64UrlSafeNoPadding::decode_to_vec(s, None).unwrap()
}

pub(crate) fn error_of<T: std::fmt::Debug>(res: Result<T, Error>) -> JWTError {
    res.unwrap_err().downcast::<JWTError>().unwrap()
}

pub(crate) fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap()
}

pub(crate) fn with(jwk: &str, name: &str, value: serde_json::Value) -> String {
    let mut jwk = json(jwk);
    jwk[name] = value;
    jwk.to_string()
}

pub(crate) fn without(jwk: &str, names: &[&str]) -> String {
    let mut jwk = json(jwk);
    for name in names {
        jwk.as_object_mut().unwrap().remove(*name);
    }
    jwk.to_string()
}

pub(crate) fn member_bytes(jwk: &str, name: &str) -> Vec<u8> {
    unb64(json(jwk)[name].as_str().unwrap())
}

/// Wraps base64 at 64 characters for strict PEM readers.
pub(crate) fn pem(label: &str, der: &[u8]) -> String {
    let b64 = Base64::encode_to_string(der).unwrap();
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect();
    format!(
        "-----BEGIN {}-----\n{}\n-----END {}-----\n",
        label,
        lines.join("\n"),
        label
    )
}

/// Changes the header without updating the tag, so decryption will fail.
#[cfg(feature = "jwe")]
pub(crate) fn with_header_change(
    token: &str,
    change: impl FnOnce(&mut serde_json::Value),
) -> String {
    let mut parts: Vec<String> = token.split('.').map(Into::into).collect();
    let mut header: serde_json::Value = serde_json::from_slice(&unb64(&parts[0])).unwrap();
    change(&mut header);
    parts[0] = b64(header.to_string().as_bytes());
    parts.join(".")
}

/// Raw JSON lets tests supply duplicate members that a `Value` cannot hold.
#[cfg(feature = "jwe")]
pub(crate) fn with_epk(token: &str, epk: &str) -> String {
    let mut parts: Vec<String> = token.split('.').map(Into::into).collect();
    let header = String::from_utf8(unb64(&parts[0])).unwrap();
    let start = header.find(r#""epk":"#).unwrap() + 6;
    let end = start + header[start..].find('}').unwrap() + 1;
    let header = format!("{}{}{}", &header[..start], epk, &header[end..]);
    parts[0] = b64(header.as_bytes());
    parts.join(".")
}
