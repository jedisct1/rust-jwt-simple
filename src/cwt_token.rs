use std::convert::{TryFrom, TryInto};
use std::io::Cursor;

use anyhow::ensure;
use binstring::*;
use ciborium::de::from_reader_with_recursion_limit;
use ciborium::ser::into_writer as to_cbor;
use ciborium::value::Value as CBORValue;
use coarsetime::Duration;
use serde::de::DeserializeOwned;

use crate::claims::*;
use crate::common::*;
use crate::error::*;
use crate::jwt_header::*;
use crate::token::TokenMetadata;

pub const MAX_CWT_HEADER_LENGTH: usize = 4096;
pub const MAX_CUSTOM_CLAIMS_COUNT: usize = 64;
pub const MAX_CUSTOM_CLAIMS_SIZE: usize = 16384;

/// Nesting depth accepted in a CWT, shared by the pre-scan and the decoder so neither can
/// reject what the other would have taken.
const MAX_CWT_DEPTH: usize = 16;

fn from_cbor<T: DeserializeOwned, R: std::io::Read>(reader: R) -> Result<T, Error> {
    from_reader_with_recursion_limit(reader, MAX_CWT_DEPTH).map_err(Error::new)
}

/// Utilities to get information about a CWT token
///
/// This struct provides functionality for working with CBOR Web Tokens (CWT),
/// including decoding metadata and verifying tokens.
///
/// CWT tokens use CBOR (Concise Binary Object Representation) instead of JSON,
/// making them more compact than JWTs, which is beneficial for constrained environments.
///
/// # Custom Claims in CWT
///
/// CWT differs from JWT in several ways, including how claims are represented.
/// Most notably, CWT uses integer claim keys instead of string keys. When working
/// with custom claims in CWT, you need to account for this difference.
///
/// ## Integer Keys in Custom Claims
///
/// When the library processes CWT tokens with custom claims that have integer keys:
///
/// 1. Integer keys within the i32 range are converted to string representations
///    (e.g., integer `123` becomes string `"123"`)
/// 2. Integer keys outside the i32 range have the prefix "int_" added
///    (e.g., large integer becomes `"int_<value>"`)
///
/// To define a custom claims struct that properly maps these keys:
///
/// ```
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
/// struct CustomCWTClaims {
///     // For claim with key "123" (integer 123 in CWT)
///     #[serde(rename = "123")]
///     claim_123: Option<String>,
///
///     // For claim with key "456" (integer 456 in CWT)
///     #[serde(rename = "456")]
///     claim_456: Option<u64>
/// }
/// ```
pub struct CWTToken;

struct CBORHead {
    major: u8,
    argument: u64,
    indefinite: bool,
    /// Offset of the first byte after the head.
    body: usize,
}

fn read_cbor_head(cbor: &[u8], offset: usize) -> Result<CBORHead, Error> {
    let initial = *cbor.get(offset).ok_or(JWTError::CWTDecodingError)?;
    let major = initial >> 5;
    let (argument, indefinite, body) = match initial & 0x1f {
        info @ 0..=23 => (info as u64, false, offset + 1),
        info @ 24..=27 => {
            let width = 1usize << (info - 24);
            let end = offset + 1 + width;
            let encoded = cbor
                .get(offset + 1..end)
                .ok_or(JWTError::CWTDecodingError)?;
            let mut buf = [0u8; 8];
            buf[8 - width..].copy_from_slice(encoded);
            (u64::from_be_bytes(buf), false, end)
        }
        // Only strings, arrays and maps may be indefinite-length.
        31 if (2..=5).contains(&major) => (0, true, offset + 1),
        _ => bail!(JWTError::CWTDecodingError),
    };
    Ok(CBORHead {
        major,
        argument,
        indefinite,
        body,
    })
}

/// Offset just past a definite-length string, checked against the end of the buffer.
fn end_of_cbor_string(cbor: &[u8], head: &CBORHead) -> Result<usize, Error> {
    let len = usize::try_from(head.argument).map_err(|_| JWTError::CWTDecodingError)?;
    let end = head
        .body
        .checked_add(len)
        .ok_or(JWTError::CWTDecodingError)?;
    ensure!(end <= cbor.len(), JWTError::CWTDecodingError);
    Ok(end)
}

fn at_cbor_break(cbor: &[u8], offset: usize) -> Result<bool, Error> {
    Ok(*cbor.get(offset).ok_or(JWTError::CWTDecodingError)? == 0xff)
}

/// Offset just past the break of an indefinite-length string, and its total content length.
///
/// `max_overhead` caps the bytes spent on chunk heads, which is what stops a string split
/// into millions of one-byte chunks from turning the walk into a whole-token scan.
fn walk_cbor_string_chunks(
    cbor: &[u8],
    start: usize,
    major: u8,
    max_overhead: usize,
) -> Result<(usize, usize), Error> {
    let mut at = start;
    let mut content = 0usize;
    let mut overhead = 0usize;
    while !at_cbor_break(cbor, at)? {
        let chunk = read_cbor_head(cbor, at)?;
        ensure!(
            chunk.major == major && !chunk.indefinite,
            JWTError::CWTDecodingError
        );
        overhead += chunk.body - at;
        ensure!(overhead <= max_overhead, JWTError::CWTDecodingError);
        let end = end_of_cbor_string(cbor, &chunk)?;
        content += end - chunk.body;
        at = end;
    }
    Ok((at + 1, content))
}

/// Offset just past the CBOR item starting at `offset`, without decoding or allocating.
///
/// Announced element counts are not trusted; the walk just runs out of input and fails.
/// Every item it accepts costs at least one byte, so it can never visit more items than
/// `cbor` has bytes, which is what makes it safe on a truncated view of a hostile token.
fn skip_cbor_item(cbor: &[u8], offset: usize, depth: usize) -> Result<usize, Error> {
    ensure!(depth <= MAX_CWT_DEPTH, JWTError::CWTDecodingError);
    let head = read_cbor_head(cbor, offset)?;
    match head.major {
        2 | 3 if !head.indefinite => end_of_cbor_string(cbor, &head),
        2 | 3 => Ok(walk_cbor_string_chunks(cbor, head.body, head.major, cbor.len())?.0),
        4 | 5 if !head.indefinite => {
            let items = if head.major == 5 {
                head.argument
                    .checked_mul(2)
                    .ok_or(JWTError::CWTDecodingError)?
            } else {
                head.argument
            };
            let mut at = head.body;
            for _ in 0..items {
                at = skip_cbor_item(cbor, at, depth + 1)?;
            }
            Ok(at)
        }
        4 | 5 => {
            let mut at = head.body;
            while !at_cbor_break(cbor, at)? {
                at = skip_cbor_item(cbor, at, depth + 1)?;
                if head.major == 5 {
                    ensure!(!at_cbor_break(cbor, at)?, JWTError::CWTDecodingError);
                    at = skip_cbor_item(cbor, at, depth + 1)?;
                }
            }
            Ok(at + 1)
        }
        6 => skip_cbor_item(cbor, head.body, depth + 1),
        _ => Ok(head.body),
    }
}

/// Length of the payload byte string, after checking the COSE framing around it.
///
/// Runs before the decoder, which would otherwise materialize an announced array of
/// millions of one-byte elements before anything got to reject it. Payload size stays
/// unbounded: CWT is binary and a token carrying gigabytes of claims is legitimate.
fn scan_cwt_envelope(token: &[u8]) -> Result<usize, Error> {
    let outer = read_cbor_head(token, 0)?;
    ensure!(outer.major == 6, JWTError::CWTDecodingError);
    let (tag, tagged_at) = if outer.argument == 61 {
        let inner = read_cbor_head(token, outer.body)?;
        ensure!(inner.major == 6, JWTError::CWTDecodingError);
        (inner.argument, inner.body)
    } else {
        (outer.argument, outer.body)
    };
    ensure!(tag == 17 || tag == 18, JWTError::CWTDecodingError);

    let array = read_cbor_head(token, tagged_at)?;
    ensure!(
        array.major == 4 && (array.indefinite || array.argument == 4),
        JWTError::CWTDecodingError
    );

    // Everything but the payload has to fit in the header budget, so walking the slots
    // around it through windows of that size is lossless for well-formed tokens and caps
    // the walk for everything else, however large the token is.
    let header_window = window_from(token, tagged_at);
    let after_protected = skip_cbor_item(header_window, array.body, 0)?;
    let payload_at = skip_cbor_item(header_window, after_protected, 0)?;

    let payload = read_cbor_head(token, payload_at)?;
    ensure!(payload.major == 2, JWTError::CWTDecodingError);
    let (payload_end, payload_len) = if payload.indefinite {
        walk_cbor_string_chunks(token, payload.body, 2, MAX_CWT_HEADER_LENGTH)?
    } else {
        let end = end_of_cbor_string(token, &payload)?;
        (end, end - payload.body)
    };

    // The budget is computed by subtracting the payload from the token, so it only sees
    // bytes that are present. Walk the signature slot too, or a ten-byte token announcing
    // millions of absent elements sails past it.
    skip_cbor_item(window_from(token, payload_end), payload_end, 0)?;

    Ok(payload_len)
}

fn window_from(token: &[u8], offset: usize) -> &[u8] {
    &token[..offset
        .saturating_add(MAX_CWT_HEADER_LENGTH)
        .min(token.len())]
}

/// Reject a hostile envelope before the decoder is handed the token.
fn ensure_cwt_header_budget(token: &[u8]) -> Result<(), Error> {
    let header_len = token.len().saturating_sub(scan_cwt_envelope(token)?);
    ensure!(header_len > 0 && header_len <= MAX_CWT_HEADER_LENGTH);
    Ok(())
}

fn header_buckets_collide(
    protected: &[(CBORValue, CBORValue)],
    unprotected: &[(CBORValue, CBORValue)],
) -> bool {
    protected.iter().any(|(protected_key, _)| {
        unprotected
            .iter()
            .any(|(unprotected_key, _)| unprotected_key == protected_key)
    })
}

impl CWTToken {
    /// Decode CWT token metadata that can be useful prior to signature/tag verification
    ///
    /// Similar to `Token::decode_metadata` but for CWT tokens.
    pub fn decode_metadata(token: impl AsRef<[u8]>) -> Result<TokenMetadata, Error> {
        let token = token.as_ref();
        ensure_cwt_header_budget(token)?;

        let mut parts_reader = Cursor::new(token);
        let parts_cbor_tagged = from_cbor(&mut parts_reader)?;

        let parts_cbor: &[CBORValue] = match &parts_cbor_tagged {
            ciborium::tag::Captured::<CBORValue>(Some(tag), x) if *tag == 17 || *tag == 18 => {
                x.as_array().ok_or(JWTError::CWTDecodingError)?
            }
            ciborium::tag::Captured::<CBORValue>(Some(61), x) => {
                // Handle tag 61 (CWT tag) wrapping a COSE tag (17 or 18)
                match x {
                    CBORValue::Tag(inner_tag, inner_value) => {
                        // The inner_tag should be 17 or 18 for MAC0 or Signature1
                        ensure!(
                            *inner_tag == 17 || *inner_tag == 18,
                            JWTError::CWTDecodingError
                        );

                        // Extract the array inside the inner tag
                        match inner_value.as_ref() {
                            CBORValue::Array(arr) => arr,
                            _ => bail!(JWTError::CWTDecodingError),
                        }
                    }
                    _ => bail!(JWTError::CWTDecodingError),
                }
            }
            _ => {
                bail!(JWTError::CWTDecodingError)
            }
        };

        ensure!(parts_cbor.len() == 4, JWTError::CWTDecodingError);

        let mut jwt_header = JWTHeader::default();

        // Parse protected header
        let mut protected_reader =
            Cursor::new(parts_cbor[0].as_bytes().ok_or(JWTError::CWTDecodingError)?);
        let protected_cbor: CBORValue = from_cbor(&mut protected_reader)?;
        let protected = protected_cbor.as_map().ok_or(JWTError::CWTDecodingError)?;

        // Parse unprotected header
        let unprotected = parts_cbor[1].as_map().ok_or(JWTError::CWTDecodingError)?;
        ensure!(
            !header_buckets_collide(protected, unprotected),
            JWTError::CWTDecodingError
        );
        jwt_header.mix_cwt(protected)?;
        jwt_header.mix_cwt(unprotected)?;

        Ok(TokenMetadata { jwt_header })
    }

    pub(crate) fn verify<CustomClaims, AuthenticationOrSignatureFn>(
        jwt_alg_name: &'static str,
        token: impl AsRef<[u8]>,
        options: Option<VerificationOptions>,
        authentication_or_signature_fn: AuthenticationOrSignatureFn,
    ) -> Result<JWTClaims<CustomClaims>, Error>
    where
        CustomClaims: DeserializeOwned + Default,
        AuthenticationOrSignatureFn: FnOnce(&str, &[u8]) -> Result<(), Error>,
    {
        let options = options.unwrap_or_default();
        let token = token.as_ref();
        let token_len = token.len();

        // cwt doesn't have a typ field, so specifying a signature type in
        // options triggers an immediate mismatch.
        if options.required_signature_type.is_some() {
            bail!(JWTError::RequiredSignatureTypeMismatch);
        }

        if let Some(max_token_length) = options.max_token_length {
            ensure!(token_len <= max_token_length, JWTError::TokenTooLong);
        }

        ensure_cwt_header_budget(token)?;

        let mut parts_reader = Cursor::new(token);
        let parts_cbor_tagged = from_cbor(&mut parts_reader)?;

        let (tag, parts_cbor): (u64, &[CBORValue]) = match &parts_cbor_tagged {
            ciborium::tag::Captured::<CBORValue>(Some(tag), x) if *tag == 17 || *tag == 18 => {
                (*tag, x.as_array().ok_or(JWTError::CWTDecodingError)?)
            }
            ciborium::tag::Captured::<CBORValue>(Some(61), x) => {
                // Handle tag 61 (CWT tag) wrapping a COSE tag (17 or 18)
                match x {
                    CBORValue::Tag(inner_tag, inner_value) => {
                        // The inner_tag should be 17 or 18 for MAC0 or Signature1
                        ensure!(
                            *inner_tag == 17 || *inner_tag == 18,
                            JWTError::CWTDecodingError
                        );

                        // Extract the array inside the inner tag
                        match inner_value.as_ref() {
                            CBORValue::Array(arr) => (*inner_tag, arr),
                            _ => bail!(JWTError::CWTDecodingError),
                        }
                    }
                    _ => bail!(JWTError::CWTDecodingError),
                }
            }
            _ => {
                bail!(JWTError::CWTDecodingError)
            }
        };
        ensure!(parts_cbor.len() == 4, JWTError::CWTDecodingError);

        let mut jwt_header = JWTHeader::default();
        let mut claims = JWTClaims::<CustomClaims>::new();

        let mut protected_reader =
            Cursor::new(parts_cbor[0].as_bytes().ok_or(JWTError::CWTDecodingError)?);
        let protected_cbor: CBORValue = from_cbor(&mut protected_reader)?;
        let protected = protected_cbor.as_map().ok_or(JWTError::CWTDecodingError)?;

        let unprotected = parts_cbor[1].as_map().ok_or(JWTError::CWTDecodingError)?;
        ensure!(
            !header_buckets_collide(protected, unprotected),
            JWTError::CWTDecodingError
        );
        jwt_header.mix_cwt(protected)?;
        jwt_header.mix_cwt(unprotected)?;

        // Reject unsupported critical header extensions before accepting the token.
        if let Some(ref crit) = jwt_header.critical {
            if !crit.is_empty() {
                bail!(JWTError::UnknownCriticalExtension);
            }
        }

        ensure!(
            jwt_header.algorithm == jwt_alg_name,
            JWTError::AlgorithmMismatch
        );

        if let Some(required_key_id) = &options.required_key_id {
            if let Some(key_id) = &jwt_header.key_id {
                ensure!(key_id == required_key_id, JWTError::KeyIdentifierMismatch);
            } else {
                bail!(JWTError::MissingJWTKeyIdentifier)
            }
        }

        if let Some(required_content_type) = &options.required_content_type {
            let required_content_type_uc = required_content_type.to_uppercase();
            let content_type_uc = jwt_header
                .content_type
                .ok_or(JWTError::RequiredContentTypeMismatch)?
                .to_uppercase();
            ensure!(
                content_type_uc == required_content_type_uc,
                JWTError::RequiredContentTypeMismatch
            )
        }

        let authentication_tag_or_signature =
            parts_cbor[3].as_bytes().ok_or(JWTError::CWTDecodingError)?;

        let domain_cbor = match tag {
            17 => CBORValue::Text("MAC0".into()),
            18 => CBORValue::Text("Signature1".into()),
            _ => bail!(JWTError::CWTDecodingError),
        };
        let aad_cbor = CBORValue::Bytes(vec![]);
        let authenticated = vec![
            domain_cbor,
            parts_cbor[0].clone(),
            aad_cbor,
            parts_cbor[2].clone(),
        ];
        let authenticated_cbor = CBORValue::Array(authenticated);
        let mut authenticated_cbor_bytes = vec![];

        to_cbor(&authenticated_cbor, &mut authenticated_cbor_bytes)?;

        authentication_or_signature_fn(
            BinString::from(authenticated_cbor_bytes).as_str(),
            authentication_tag_or_signature,
        )?;

        let mut claims_reader =
            Cursor::new(parts_cbor[2].as_bytes().ok_or(JWTError::CWTDecodingError)?);
        let claims_cbor: CBORValue = from_cbor(&mut claims_reader)?;
        let claims_ = claims_cbor.as_map().ok_or(JWTError::CWTDecodingError)?;
        claims.mix_cwt(claims_)?;

        claims.validate(&options)?;
        Ok(claims)
    }
}

/// Helper function to deserialize custom claims
///
/// This function converts a map of custom claims from the CWT token into the custom claims type.
///
/// # Integer-based Claim Keys in CWT
///
/// In CWT, claim keys can be integers rather than strings (unlike in JWT which uses string keys).
/// When a CWT token has integer keys for custom claims, they are converted to strings in the following way:
///
/// 1. Regular integer claim IDs (i32 values) are converted to their string representation (e.g., `123` becomes `"123"`)
/// 2. Large integers that can't fit in i32 are prefixed with "int_" (e.g., a larger integer becomes `"int_<value>"`)
///
/// ## Defining Custom Claims Struct for CWT Integer Keys
///
/// When creating a custom claims struct for CWT tokens with integer keys, you should:
///
/// ```
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
/// struct CustomCWTClaims {
///     // For claim with key "123" (integer 123 in CWT)
///     #[serde(rename = "123")]
///     claim_123: Option<String>,
///
///     // For claim with key "456" (integer 456 in CWT)
///     #[serde(rename = "456")]
///     claim_456: Option<u64>,
///
///     // For large integers beyond i32 range with prefix
///     #[serde(rename = "int_79228162514264337593543950336")]
///     large_int_claim: Option<bool>,
/// }
/// ```
///
/// # Handling Duplicate Keys
///
/// Since CWT 1.0, the library will return a `DuplicateCWTClaimKey` error if a claim with the same key
/// is encountered more than once in a token.
fn deserialize_custom_claims<T: DeserializeOwned + Default>(
    custom_claims: &std::collections::HashMap<String, CBORValue>,
) -> Result<T, Error> {
    // Add size limits
    if custom_claims.len() > MAX_CUSTOM_CLAIMS_COUNT {
        bail!(JWTError::CWTDecodingError);
    }

    // Create a CBOR map value from the custom claims
    // with all nested integer keys converted to strings
    let custom_cbor = CBORValue::Map(
        custom_claims
            .iter()
            .map(|(k, v)| {
                (
                    CBORValue::Text(k.clone()),
                    convert_integer_keys_to_strings(v.clone()),
                )
            })
            .collect(),
    );

    // Serialize to bytes
    let mut bytes = Vec::new();
    to_cbor(&custom_cbor, &mut bytes).map_err(|_| JWTError::CWTDecodingError)?;

    // Check size limits for serialized data
    if bytes.len() > MAX_CUSTOM_CLAIMS_SIZE {
        bail!(JWTError::CWTDecodingError);
    }

    from_cbor::<T, _>(std::io::Cursor::new(bytes)).map_err(|_| JWTError::CWTDecodingError.into())
}

/// Recursively convert all integer keys in CBOR maps to string keys
/// This function walks through nested CBOR structures and converts any integer
/// keys to their string representation, which is necessary for proper deserialization
/// into Rust structs that use #[serde(rename = "...")] with string keys.
fn convert_integer_keys_to_strings(value: CBORValue) -> CBORValue {
    match value {
        CBORValue::Map(map) => {
            // Create a new map with converted keys
            let converted_map = map
                .into_iter()
                .map(|(k, v)| {
                    // Convert the key if it's an integer
                    let new_key = if let Some(int_key) = k.as_integer() {
                        // Try converting to i32 for simpler representation
                        if let Ok(i32_key) = TryInto::<i32>::try_into(int_key) {
                            CBORValue::Text(format!("{}", i32_key))
                        } else {
                            // Use a prefix for integers outside i32 range
                            CBORValue::Text(format!("int_{:?}", int_key))
                        }
                    } else {
                        // Keep non-integer keys as they are
                        k
                    };

                    // Recursively convert nested values
                    let new_value = convert_integer_keys_to_strings(v);

                    (new_key, new_value)
                })
                .collect();

            CBORValue::Map(converted_map)
        }
        CBORValue::Array(arr) => {
            // Process arrays recursively
            let converted_arr = arr
                .into_iter()
                .map(convert_integer_keys_to_strings)
                .collect();

            CBORValue::Array(converted_arr)
        }
        // All other value types are returned unchanged
        _ => value,
    }
}

impl<CustomClaims> JWTClaims<CustomClaims>
where
    CustomClaims: DeserializeOwned + Default,
{
    fn mix_cwt(&mut self, cwt: &[(CBORValue, CBORValue)]) -> Result<(), Error> {
        // Collection for non-standard claims
        let mut custom_claims_map = std::collections::HashMap::new();

        for (key, value) in cwt {
            if let Some(key_int) = key.as_integer() {
                // Try converting to i32 to match against known claim IDs
                if let Ok(key_id) = TryInto::<i32>::try_into(key_int) {
                    match key_id {
                        I_IAT => {
                            let ts: u64 = if let Some(ts) = value.as_integer() {
                                ts.try_into().map_err(|_| JWTError::CWTDecodingError)?
                            } else if let Some(ts) = value.as_float() {
                                let f: f64 =
                                    ts.try_into().map_err(|_| JWTError::CWTDecodingError)?;
                                f.round() as _
                            } else {
                                bail!(JWTError::CWTDecodingError)
                            };
                            self.issued_at = Some(Duration::from_secs(ts));
                        }
                        I_EXP => {
                            let ts: u64 = if let Some(ts) = value.as_integer() {
                                ts.try_into().map_err(|_| JWTError::CWTDecodingError)?
                            } else if let Some(ts) = value.as_float() {
                                let f: f64 =
                                    ts.try_into().map_err(|_| JWTError::CWTDecodingError)?;
                                f.round() as _
                            } else {
                                bail!(JWTError::CWTDecodingError)
                            };
                            self.expires_at = Some(Duration::from_secs(ts));
                        }
                        I_NBF => {
                            let ts: u64 = if let Some(ts) = value.as_integer() {
                                ts.try_into().map_err(|_| JWTError::CWTDecodingError)?
                            } else if let Some(ts) = value.as_float() {
                                let f: f64 =
                                    ts.try_into().map_err(|_| JWTError::CWTDecodingError)?;
                                f.round() as _
                            } else {
                                bail!(JWTError::CWTDecodingError)
                            };
                            self.invalid_before = Some(Duration::from_secs(ts));
                        }
                        I_ISS => {
                            self.issuer =
                                Some(value.as_text().ok_or(JWTError::CWTDecodingError)?.into());
                        }
                        I_SUB => {
                            self.subject =
                                Some(value.as_text().ok_or(JWTError::CWTDecodingError)?.into());
                        }
                        I_AUD => {
                            let audiences =
                                value.as_text().ok_or(JWTError::CWTDecodingError)?.into();
                            self.audiences = Some(Audiences::AsString(audiences));
                        }
                        I_CTI => {
                            let v = value.as_bytes().ok_or(JWTError::CWTDecodingError)?;
                            let v = BinString::from(v).into();
                            self.jwt_id = Some(v);
                        }
                        I_NONCE => {
                            let v = value.as_bytes().ok_or(JWTError::CWTDecodingError)?;
                            let v = BinString::from(v).into();
                            self.nonce = Some(v);
                        }
                        _ => {
                            // This is a custom claim with integer key, store it
                            let claim_key = format!("{}", key_id);
                            if custom_claims_map.contains_key(&claim_key) {
                                bail!(JWTError::DuplicateCWTClaimKey(claim_key));
                            }
                            custom_claims_map.insert(claim_key, value.clone());
                        }
                    }
                } else {
                    // Integer that couldn't fit in i32 - treat as custom claim
                    // Convert Integer to string representation
                    let key_str = format!("int_{:?}", key_int);
                    if custom_claims_map.contains_key(&key_str) {
                        bail!(JWTError::DuplicateCWTClaimKey(key_str));
                    }
                    custom_claims_map.insert(key_str, value.clone());
                }
            } else if let Some(key_text) = key.as_text() {
                // Custom claim with text key
                let key_str = key_text.to_string();
                if custom_claims_map.contains_key(&key_str) {
                    bail!(JWTError::DuplicateCWTClaimKey(key_str));
                }
                custom_claims_map.insert(key_str, value.clone());
            } else {
                // Non-integer/text key - treat as custom claim with a special prefix
                let key_str = format!("custom_{}", custom_claims_map.len());
                if custom_claims_map.contains_key(&key_str) {
                    bail!(JWTError::DuplicateCWTClaimKey(key_str));
                }
                custom_claims_map.insert(key_str, value.clone());
            }
        }

        // Process custom claims if any were found
        if !custom_claims_map.is_empty() {
            let custom: CustomClaims = deserialize_custom_claims(&custom_claims_map)?;
            self.custom = custom;
        }

        Ok(())
    }
}

impl JWTHeader {
    fn mix_cwt(&mut self, cwt: &[(CBORValue, CBORValue)]) -> Result<(), Error> {
        for (key, value) in cwt {
            let key_id: i32 = key
                .as_integer()
                .ok_or(JWTError::CWTDecodingError)?
                .try_into()
                .map_err(|_| JWTError::CWTDecodingError)?;
            match key_id {
                I_ALG => {
                    let alg_id = value
                        .as_integer()
                        .ok_or(JWTError::CWTDecodingError)?
                        .try_into()
                        .map_err(|_| JWTError::CWTDecodingError)?;
                    self.algorithm = match alg_id {
                        I_EDDSA => "EdDSA",
                        I_RS512 => "RS512",
                        I_RS384 => "RS384",
                        I_RS256 => "RS256",
                        I_ES256K => "ES256K",
                        I_PS512 => "PS512",
                        I_PS384 => "PS384",
                        I_PS256 => "PS256",
                        I_ES256 => "ES256",
                        I_ES384 => "ES384",
                        I_ES512 => "ES512",
                        I_HS256 => "HS256",
                        I_HS384 => "HS384",
                        I_HS512 => "HS512",
                        _ => bail!(JWTError::AlgorithmMismatch),
                    }
                    .into();
                }
                I_CTY => {
                    let content_type = value.as_text().ok_or(JWTError::CWTDecodingError)?;
                    self.content_type = Some(content_type.into());
                }
                I_KID => {
                    if let Some(key_id) = value.as_text() {
                        self.key_id = Some(key_id.into());
                    } else if let Some(key_id) = value.as_bytes() {
                        let key_id = BinString::from(key_id).into();
                        self.key_id = Some(key_id);
                    } else {
                        bail!(JWTError::CWTDecodingError)
                    }
                }
                I_CRIT => {
                    let crit_cbor = value.as_array().ok_or(JWTError::CWTDecodingError)?;
                    let mut crit = Vec::new();
                    for v in crit_cbor {
                        let crit_str = v.as_text().ok_or(JWTError::CWTDecodingError)?;
                        crit.push(crit_str.into());
                    }
                    self.critical = Some(crit);
                }
                I_X5C => {
                    let x5c_cbor = value.as_array().ok_or(JWTError::CWTDecodingError)?;
                    let mut x5c = Vec::new();
                    for v in x5c_cbor {
                        let crit_str = v.as_text().ok_or(JWTError::CWTDecodingError)?;
                        x5c.push(crit_str.into());
                    }
                    self.certificate_chain = Some(x5c);
                }
                I_X5U => {
                    let x5u_str = value.as_text().ok_or(JWTError::CWTDecodingError)?;
                    self.certificate_url = Some(x5u_str.into());
                }
                I_X5T => {
                    let x5t_cbor = value.as_text().ok_or(JWTError::CWTDecodingError)?;
                    self.certificate_sha1_thumbprint = Some(x5t_cbor.into());
                }
                _ => {}
            }
        }
        Ok(())
    }
}

const I_ALG: i32 = 1;
const I_CRIT: i32 = 2;
const I_CTY: i32 = 3;
const I_KID: i32 = 4;
const I_X5C: i32 = 33;
const I_X5T: i32 = 34;
const I_X5U: i32 = 35;

const I_RS512: i32 = -259;
const I_RS384: i32 = -258;
const I_RS256: i32 = -257;
const I_ES256K: i32 = -47;
const I_PS512: i32 = -39;
const I_PS384: i32 = -38;
const I_PS256: i32 = -37;
const I_ES512: i32 = -36;
const I_ES384: i32 = -35;
const I_EDDSA: i32 = -8;
const I_ES256: i32 = -7;
const I_HS256: i32 = 5;
const I_HS384: i32 = 6;
const I_HS512: i32 = 7;

const I_ISS: i32 = 1;
const I_SUB: i32 = 2;
const I_AUD: i32 = 3;
const I_EXP: i32 = 4;
const I_NBF: i32 = 5;
const I_IAT: i32 = 6;
const I_CTI: i32 = 7;
const I_NONCE: i32 = 10;

#[test]
fn should_verify_token() {
    use ct_codecs::{Decoder, Hex};

    use crate::prelude::*;

    let k_hex = "e176d07d2a9f8b73553487d0b41ef9294873512c62a0471439a758420097e589";
    let k = Hex::decode_to_vec(k_hex, None).unwrap();
    let key = HS256Key::from_bytes(&k);

    let token_hex = "d18443a10105a05835a60172636f6170733a2f2f61732e6578616d706c65026764616a69616a690743313233041a6296121f051a6296040f061a6296040f58206b310798de7f6b2aeff832344c2ea37674807b72a8a2cc263f1d31b1eb86139b";
    let token = Hex::decode_to_vec(token_hex, None).unwrap();
    let mut options = VerificationOptions::default();
    options.time_tolerance = Some(Duration::from_days(20000));
    let _ = key.verify_cwt_token(token, Some(options)).unwrap();
}

#[test]
fn verify_content_type() {
    use ct_codecs::{Decoder, Hex};

    use crate::prelude::*;

    let k_hex = "e176d07d2a9f8b73553487d0b41ef9294873512c62a0471439a758420097e589";
    let k = Hex::decode_to_vec(k_hex, None).unwrap();
    let key = HS256Key::from_bytes(&k);

    let token_hex = "d18443a10105a05835a60172636f6170733a2f2f61732e6578616d706c65026764616a69616a690743313233041a6296121f051a6296040f061a6296040f58206b310798de7f6b2aeff832344c2ea37674807b72a8a2cc263f1d31b1eb86139b";
    let token = Hex::decode_to_vec(token_hex, None).unwrap();
    let mut options = VerificationOptions::default();
    options.time_tolerance = Some(Duration::from_days(20000));
    options.required_content_type = Some("JWT".into());
    let res = key.verify_cwt_token(token, Some(options));
    assert!(res.is_err());
}

#[test]
fn verify_with_tag_61_wrapper() {
    use ct_codecs::{Decoder, Hex};

    use crate::prelude::*;

    let k_hex = "e176d07d2a9f8b73553487d0b41ef9294873512c62a0471439a758420097e589";
    let k = Hex::decode_to_vec(k_hex, None).unwrap();
    let key = HS256Key::from_bytes(&k);

    // Same token as should_verify_token but wrapped in tag 61
    // d83d - Tag 61, followed by the original token
    let token_hex = "d83dd18443a10105a05835a60172636f6170733a2f2f61732e6578616d706c65026764616a69616a690743313233041a6296121f051a6296040f061a6296040f58206b310798de7f6b2aeff832344c2ea37674807b72a8a2cc263f1d31b1eb86139b";
    let token = Hex::decode_to_vec(token_hex, None).unwrap();
    let mut options = VerificationOptions::default();
    options.time_tolerance = Some(Duration::from_days(20000));
    let _ = key.verify_cwt_token(token, Some(options)).unwrap();
}

#[test]
fn decode_cwt_metadata() {
    use ct_codecs::{Decoder, Hex};

    use crate::prelude::*;

    let k_hex = "e176d07d2a9f8b73553487d0b41ef9294873512c62a0471439a758420097e589";
    let k = Hex::decode_to_vec(k_hex, None).unwrap();
    let key = HS256Key::from_bytes(&k);

    // Token from should_verify_token test
    let token_hex = "d18443a10105a05835a60172636f6170733a2f2f61732e6578616d706c65026764616a69616a690743313233041a6296121f051a6296040f061a6296040f58206b310798de7f6b2aeff832344c2ea37674807b72a8a2cc263f1d31b1eb86139b";
    let token = Hex::decode_to_vec(token_hex, None).unwrap();

    // First check the verification works
    let mut options = VerificationOptions::default();
    options.time_tolerance = Some(Duration::from_days(20000));
    let _ = key.verify_cwt_token(token.clone(), Some(options)).unwrap();

    // Now test metadata extraction
    let metadata = key.decode_cwt_metadata(token).unwrap();
    assert_eq!(metadata.algorithm(), "HS256");

    // Same token as above but wrapped in tag 61
    let token_hex = "d83dd18443a10105a05835a60172636f6170733a2f2f61732e6578616d706c65026764616a69616a690743313233041a6296121f051a6296040f061a6296040f58206b310798de7f6b2aeff832344c2ea37674807b72a8a2cc263f1d31b1eb86139b";
    let token = Hex::decode_to_vec(token_hex, None).unwrap();

    // Test metadata extraction for tag 61 wrapped token
    let metadata = key.decode_cwt_metadata(token).unwrap();
    assert_eq!(metadata.algorithm(), "HS256");
}

#[cfg(test)]
fn encode_cbor(value: &CBORValue) -> Vec<u8> {
    let mut encoded = vec![];
    to_cbor(value, &mut encoded).unwrap();
    encoded
}

/// A COSE_Mac0 CWT carrying `issuer` as its only claim.
#[cfg(test)]
fn hs256_cwt(key: &crate::algorithms::HS256Key, issuer: &str) -> Vec<u8> {
    hs256_cwt_with_claims(
        key,
        vec![(
            CBORValue::Integer(I_ISS.into()),
            CBORValue::Text(issuer.to_string()),
        )],
    )
}

#[cfg(test)]
fn hs256_cwt_with_claims(
    key: &crate::algorithms::HS256Key,
    claims: Vec<(CBORValue, CBORValue)>,
) -> Vec<u8> {
    use crate::algorithms::MACLike;

    let protected = encode_cbor(&CBORValue::Map(vec![(
        CBORValue::Integer(I_ALG.into()),
        CBORValue::Integer(I_HS256.into()),
    )]));
    let payload = encode_cbor(&CBORValue::Map(claims));
    let mac_structure = encode_cbor(&CBORValue::Array(vec![
        CBORValue::Text("MAC0".into()),
        CBORValue::Bytes(protected.clone()),
        CBORValue::Bytes(vec![]),
        CBORValue::Bytes(payload.clone()),
    ]));
    let tag = key.authentication_tag(&mac_structure);

    let mut token = vec![0xd1];
    token.extend_from_slice(&encode_cbor(&CBORValue::Array(vec![
        CBORValue::Bytes(protected),
        CBORValue::Map(vec![]),
        CBORValue::Bytes(payload),
        CBORValue::Bytes(tag),
    ])));
    token
}

#[test]
fn large_cwt_payload_is_accepted() {
    use crate::prelude::*;

    // CWT is binary and its payload is legitimately unbounded, so a token past
    // DEFAULT_MAX_TOKEN_LENGTH still has to decode and verify.
    let key = HS256Key::generate();
    let issuer = "i".repeat(1_100_000);
    let token = hs256_cwt(&key, &issuer);
    assert!(token.len() > DEFAULT_MAX_TOKEN_LENGTH);

    assert_eq!(
        CWTToken::decode_metadata(&token).unwrap().algorithm(),
        "HS256"
    );

    let options = VerificationOptions {
        max_token_length: None,
        ..Default::default()
    };
    let claims = key.verify_cwt_token(&token, Some(options)).unwrap();
    assert_eq!(claims.issuer.unwrap(), issuer);
}

#[test]
fn envelope_scan_rejects_hostile_shapes() {
    // One shape per guard in the scan. Each announces far more than it carries, so a scan
    // that took announced counts at their word would walk millions of items for a handful
    // of bytes.

    // Five million elements claimed by the outer array, settled from its head alone.
    let mut arity = vec![0xd2, 0x9a];
    arity.extend_from_slice(&5_000_000u32.to_be_bytes());

    // The same trick in the unprotected header, where the window runs out instead.
    let mut header_count = vec![0xd2, 0x84, 0x40, 0x9b];
    header_count.extend_from_slice(&u64::MAX.to_be_bytes());
    header_count.resize(header_count.len() + 2 * MAX_CWT_HEADER_LENGTH, 0xf6);

    // Nested arrays, one per byte. Well-formed and complete, so only the depth limit
    // stands between it and acceptance.
    let mut header_depth = vec![0xd2, 0x84, 0x40, 0xa1, 0x18, 0x63];
    header_depth.resize(header_depth.len() + 2 * MAX_CWT_DEPTH, 0x81);
    header_depth.extend_from_slice(&[0xf6, 0x41, 0x2a, 0x40]);

    // An indefinite payload chopped fine enough that its chunk heads blow the budget.
    let mut payload_chunks = vec![0xd2, 0x84, 0x40, 0xa0, 0x5f];
    for _ in 0..2 * MAX_CWT_HEADER_LENGTH {
        payload_chunks.extend_from_slice(&[0x41, 0x2a]);
    }
    payload_chunks.extend_from_slice(&[0xff, 0x40]);

    // Ten bytes announcing five million absent elements in the signature slot. Subtracting
    // the payload from the token length cannot catch this: those elements never reach the
    // wire, so they cost the sender nothing.
    let mut trailing_slot = vec![0xd2, 0x84, 0x40, 0xa0, 0x40, 0x9a];
    trailing_slot.extend_from_slice(&5_000_000u32.to_be_bytes());

    for (guard, token) in [
        ("outer array arity", arity),
        ("announced header count", header_count),
        ("header nesting depth", header_depth),
        ("chunked payload overhead", payload_chunks),
        ("announced count after the payload", trailing_slot),
    ] {
        assert!(scan_cwt_envelope(&token).is_err(), "accepted {}", guard);
    }
}

#[test]
fn envelope_scan_depth_limit_matches_the_decoder() {
    // A token the scan rejects but the decoder would have taken is a regression, whatever
    // the nesting depth.
    let deeply_nested = |levels: usize| {
        let mut token = vec![0xd2, 0x84, 0x43, 0xa1, 0x01, 0x05, 0xa1, 0x18, 0x63];
        token.resize(token.len() + levels, 0x81);
        token.extend_from_slice(&[0xf6, 0x41, 0x2a, 0x40]);
        token
    };

    for levels in [2, 8, 11, 12, 13, 14, 16, 20, 40] {
        let token = deeply_nested(levels);
        let decoded: Result<ciborium::tag::Captured<CBORValue>, _> =
            from_cbor(Cursor::new(token.as_slice()));
        if decoded.is_ok() {
            assert!(
                scan_cwt_envelope(&token).is_ok(),
                "the scan rejected {} levels, which the decoder accepts",
                levels
            );
        }
    }
    assert!(CWTToken::decode_metadata(deeply_nested(4)).is_ok());
}

#[test]
fn envelope_scan_accepts_indefinite_length_encodings() {
    use ct_codecs::{Decoder, Hex};

    use crate::prelude::*;

    // The token from should_verify_token: d1 84 43a10105 a0 5835<53 bytes> 5820<32 bytes>
    let token_hex = "d18443a10105a05835a60172636f6170733a2f2f61732e6578616d706c65026764616a69616a690743313233041a6296121f051a6296040f061a6296040f58206b310798de7f6b2aeff832344c2ea37674807b72a8a2cc263f1d31b1eb86139b";
    let definite = Hex::decode_to_vec(token_hex, None).unwrap();
    let payload = &definite[9..9 + 53];
    let tag = &definite[9 + 53 + 2..];

    // Re-encoded with an indefinite-length outer array and a payload split in two chunks.
    // Unusual, but legal CBOR, and the scan has to keep accepting it.
    let mut token = vec![0xd1, 0x9f, 0x43, 0xa1, 0x01, 0x05, 0xa0, 0x5f, 0x58, 26];
    token.extend_from_slice(&payload[..26]);
    token.extend_from_slice(&[0x58, 27]);
    token.extend_from_slice(&payload[26..]);
    token.extend_from_slice(&[0xff, 0x58, 32]);
    token.extend_from_slice(tag);
    token.push(0xff);

    assert_eq!(scan_cwt_envelope(&token).unwrap(), 53);
    assert_eq!(
        CWTToken::decode_metadata(&token).unwrap().algorithm(),
        "HS256"
    );
}

#[test]
fn verify_cwt_with_custom_claims() {
    use ct_codecs::{Decoder, Hex};
    use serde::{Deserialize, Serialize};

    use crate::prelude::*;

    // Define a custom claims structure that matches what's in our test token
    #[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
    struct CustomData {
        // We'll define fields that might match custom claims in our test token
        // In a real case, you'd define fields that match your application's custom claims
        #[serde(skip_serializing_if = "Option::is_none")]
        coap_uri: Option<String>,
    }

    let k_hex = "e176d07d2a9f8b73553487d0b41ef9294873512c62a0471439a758420097e589";
    let k = Hex::decode_to_vec(k_hex, None).unwrap();
    let key = HS256Key::from_bytes(&k);

    // Use an existing test token
    let token_hex = "d18443a10105a05835a60172636f6170733a2f2f61732e6578616d706c65026764616a69616a690743313233041a6296121f051a6296040f061a6296040f58206b310798de7f6b2aeff832344c2ea37674807b72a8a2cc263f1d31b1eb86139b";
    let token = Hex::decode_to_vec(token_hex, None).unwrap();

    let mut options = VerificationOptions::default();
    options.time_tolerance = Some(Duration::from_days(20000));

    // Verify with custom claims
    let claims = key
        .verify_cwt_token_with_custom_claims::<CustomData>(token.clone(), Some(options.clone()))
        .unwrap();

    // Check standard claims
    assert!(claims.issuer.is_some());

    // The standard claims should be there
    assert_eq!(claims.issuer.unwrap(), "coaps://as.example");

    // HS384 verification
    let key384 = HS384Key::from_bytes(&k);
    let claims384 = key384
        .verify_cwt_token_with_custom_claims::<CustomData>(token.clone(), Some(options.clone()));
    // This should fail since token was created with HS256, not HS384
    assert!(claims384.is_err());

    // Test with other algorithms
    let key512 = HS512Key::from_bytes(&k);
    let claims512 = key512
        .verify_cwt_token_with_custom_claims::<CustomData>(token.clone(), Some(options.clone()));
    // This should fail since token was created with HS256, not HS512
    assert!(claims512.is_err());

    // Test with Blake2b
    let blake2b = Blake2bKey::from_bytes(&k);
    let claims_blake = blake2b
        .verify_cwt_token_with_custom_claims::<CustomData>(token.clone(), Some(options.clone()));
    // This should fail since token was created with HS256, not Blake2b
    assert!(claims_blake.is_err());

    #[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
    struct ComplexCustomData {
        required_field: String,
    }

    // This token carries no custom claim, so nothing is deserialized into `ComplexCustomData`.
    let complex_claims = key
        .verify_cwt_token_with_custom_claims::<ComplexCustomData>(token, Some(options))
        .unwrap();
    assert_eq!(complex_claims.custom, ComplexCustomData::default());
}

#[test]
fn custom_claims_incompatible_with_the_token_fail_closed() {
    use serde::Deserialize;

    use crate::prelude::*;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Authz {
        #[serde(rename = "500")]
        is_admin: bool,
    }

    impl Default for Authz {
        fn default() -> Self {
            Authz { is_admin: true }
        }
    }

    let key = HS256Key::from_bytes(&[0x42u8; 32]);
    let token = hs256_cwt_with_claims(
        &key,
        vec![
            (
                CBORValue::Integer(I_ISS.into()),
                CBORValue::Text("issuer".into()),
            ),
            (
                CBORValue::Integer(500.into()),
                CBORValue::Text("not-a-bool".into()),
            ),
        ],
    );

    let err = key
        .verify_cwt_token_with_custom_claims::<Authz>(&token, None)
        .unwrap_err();
    match err.downcast::<JWTError>() {
        Ok(JWTError::CWTDecodingError) => {}
        Ok(err) => panic!("Expected CWTDecodingError, got: {:?}", err),
        Err(err) => panic!("Expected JWTError, got: {:?}", err),
    }

    // `NoCustomClaims` asks for no custom claim, so the same token has to keep verifying.
    let claims = key.verify_cwt_token(&token, None).unwrap();
    assert_eq!(claims.issuer.unwrap(), "issuer");
}

#[test]
fn compatible_custom_claims_still_deserialize() {
    use serde::Deserialize;

    use crate::prelude::*;

    #[derive(Debug, Default, Deserialize, PartialEq)]
    struct Authz {
        #[serde(rename = "500")]
        is_admin: bool,
        #[serde(rename = "501")]
        scope: Option<String>,
    }

    let key = HS256Key::from_bytes(&[0x42u8; 32]);
    let token = hs256_cwt_with_claims(
        &key,
        vec![(CBORValue::Integer(500.into()), CBORValue::Bool(true))],
    );

    let claims = key
        .verify_cwt_token_with_custom_claims::<Authz>(&token, None)
        .unwrap();
    assert_eq!(
        claims.custom,
        Authz {
            is_admin: true,
            scope: None
        }
    );
}

#[test]
fn test_duplicate_cwt_claim_key() {
    use ciborium::value::Value as CBORValue;

    // Create duplicate keys in the CBOR map
    let mut claims = JWTClaims::<NoCustomClaims>::new();

    // Create a CBOR map with duplicate keys
    let mut cwt = Vec::new();

    // Standard claim key
    cwt.push((
        CBORValue::Integer(123.into()),
        CBORValue::Text("value1".into()),
    ));

    // Duplicate claim key (same integer key)
    cwt.push((
        CBORValue::Integer(123.into()),
        CBORValue::Text("value2".into()),
    ));

    // Attempt to mix the claims - should return a DuplicateCWTClaimKey error
    let result = claims.mix_cwt(&cwt);

    assert!(result.is_err());
    match result.unwrap_err().downcast::<JWTError>() {
        Ok(jwt_error) => match jwt_error {
            JWTError::DuplicateCWTClaimKey(key) => {
                assert_eq!(key, "123");
            }
            err => panic!("Expected DuplicateCWTClaimKey error, got: {:?}", err),
        },
        Err(err) => panic!("Expected JWTError, got: {:?}", err),
    }

    // Test with duplicate text keys
    let mut cwt = Vec::new();
    cwt.push((
        CBORValue::Text("test_key".into()),
        CBORValue::Text("value1".into()),
    ));
    cwt.push((
        CBORValue::Text("test_key".into()),
        CBORValue::Text("value2".into()),
    ));

    let result = claims.mix_cwt(&cwt);

    assert!(result.is_err());
    match result.unwrap_err().downcast::<JWTError>() {
        Ok(jwt_error) => match jwt_error {
            JWTError::DuplicateCWTClaimKey(key) => {
                assert_eq!(key, "test_key");
            }
            err => panic!("Expected DuplicateCWTClaimKey error, got: {:?}", err),
        },
        Err(err) => panic!("Expected JWTError, got: {:?}", err),
    }

    // Test with non-duplicate keys (should succeed)
    let mut cwt = Vec::new();
    cwt.push((
        CBORValue::Integer(123.into()),
        CBORValue::Text("value1".into()),
    ));
    cwt.push((
        CBORValue::Integer(124.into()),
        CBORValue::Text("value2".into()),
    ));

    let result = claims.mix_cwt(&cwt);
    assert!(result.is_ok());
}

#[cfg(test)]
mod cwt_catu_tests {
    use crate::prelude::{Duration, HS256Key, VerificationOptions};
    use ct_codecs::{Base64, Decoder};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
    struct CATMatch {
        #[serde(rename = "0")]
        exact: Option<String>,
        #[serde(rename = "1")]
        prefix: Option<String>,
        #[serde(rename = "2")]
        suffix: Option<String>,
        #[serde(rename = "3")]
        contains: Option<String>,
        #[serde(rename = "4")]
        regular_expression: Option<String>,
        #[serde(rename = "-1")]
        sha_256: Option<String>,
        #[serde(rename = "-2")]
        sha_512_256: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
    struct CATUClaims {
        #[serde(rename = "0")]
        scheme: Option<CATMatch>,
        #[serde(rename = "1")]
        host: Option<CATMatch>,
        #[serde(rename = "2")]
        port: Option<CATMatch>,
        #[serde(rename = "3")]
        path: Option<CATMatch>,
        #[serde(rename = "4")]
        query: Option<CATMatch>,
        #[serde(rename = "5")]
        parent_path: Option<CATMatch>,
        #[serde(rename = "6")]
        filename: Option<CATMatch>,
        #[serde(rename = "7")]
        stem: Option<CATMatch>,
        #[serde(rename = "8")]
        extension: Option<CATMatch>,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    enum RenewalType {
        Automatic = 0,
        Cookie = 1,
        Header = 2,
        Redirect = 3,
    }

    // Rust enums are not constants. If we want to use them like regular
    // values, a custom deserializer needs to be registered.
    // Custom deserializer for RenewalType
    fn deserialize_renewal_type<'de, D>(deserializer: D) -> Result<Option<RenewalType>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        // First try to deserialize as u64
        let value_opt: Option<u64> = Option::deserialize(deserializer)?;

        match value_opt {
            None => Ok(None),
            Some(value) => match value {
                0 => Ok(Some(RenewalType::Automatic)),
                1 => Ok(Some(RenewalType::Cookie)),
                2 => Ok(Some(RenewalType::Header)),
                3 => Ok(Some(RenewalType::Redirect)),
                _ => Err(D::Error::custom(format!(
                    "Invalid RenewalType value: {}",
                    value
                ))),
            },
        }
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    enum RenewalCodeLabel {
        RenewalType = 0,
        ExpirationExtension = 1,
        RenewalDeadline = 2,
        NameForCookie = 3,
        NameForHeader = 4,
        AdditionalCookieParameters = 5,
        AdditionalHeaderParameters = 6,
        StatusCodeForRedirects = 7,
    }

    #[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
    struct CATRClaims {
        #[serde(rename = "0")]
        #[serde(deserialize_with = "deserialize_renewal_type")]
        renewal_type: Option<RenewalType>, // Using RenewalType enum instead of directly a u64 requires a custom deserializer. It would probably easier to just use Option<u64>, but this is for the example.
        #[serde(rename = "1")]
        renewal_expadd: Option<u64>, // Value is 900 in the CBOR data
        #[serde(rename = "4")]
        header_name: Option<String>, // Value is "X-PV-CDN-Access-Token" in the CBOR data

        // These fields are not present in the actual CBOR data, but keep them as Optional
        #[serde(rename = "2")]
        renewal_deadline: Option<u64>,
        #[serde(rename = "3")]
        renewal_cookie_name: Option<String>,
        #[serde(rename = "5")]
        renewal_cookie_params: Option<Vec<String>>,
        #[serde(rename = "6")]
        renewal_header_params: Option<Vec<String>>,
        #[serde(rename = "7")]
        renewal_code_label: Option<RenewalCodeLabel>,
    }

    #[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
    struct ZonRefreshTokenClaims {
        #[serde(rename = "312")]
        catu: Option<CATUClaims>,
        #[serde(rename = "323")]
        catr: Option<CATRClaims>,
    }

    /// Test that verifies proper deserialization of CWT tokens with nested CBOR structures
    ///
    /// This test ensures that CWT tokens with nested structure and integer keys
    /// (like the "catu" claim with key 312) are properly deserialized.
    #[test]
    fn test_cwt_custom_claims_deserialization() {
        let raw_key = "testKey-cwt-hs256";
        let raw_key_bytes = raw_key.as_bytes();
        let key = HS256Key::from_bytes(raw_key_bytes);
        let base64_token_str = "2D3RhEOhAQWhBExTeW1tZXRyaWMyNTZYzqYBanByaW1ldmlkZW8CeCxBNXMyRnptNUI5UG5EVEVmS3VybGxMdnJUelJLSWl4ZERsMWI0TEZzZlB3PQQaaIqyAAdQc0VLLhieQT2r7LtqnxPAihkBOKIFoQJ4Ji9lMDU5Lzc4MTEvMTY0MC80N2UxLTk5MzAtMmE0MzQxZWE4YjEwBqEBeCUvMWJkMWUyNmUtMzQwNy00ODA1LWI4MDYtMTMyMTZiMzRkNGJmGQFDowACARkDhAR1WC1QVi1DRE4tQWNjZXNzLVRva2VuWCBNrpmVZ6A+aoENB0JxTPRqDRLWewqOapypw99WpP7HMw==";
        let input = Base64::decode_to_vec(base64_token_str, None).unwrap();

        let mut options = VerificationOptions::default();
        options.time_tolerance = Some(Duration::from_days(20000));

        // Verify the token and extract claims
        let claims = key
            .verify_cwt_token_with_custom_claims::<ZonRefreshTokenClaims>(&input, Some(options))
            .unwrap();

        // Verify standard claims are extracted correctly
        assert!(claims.issuer.is_some());
        assert_eq!(claims.issuer.unwrap(), "primevideo");
        assert!(claims.subject.is_some());
        assert!(claims.jwt_id.is_some());

        // Verify the custom claim structure was properly deserialized
        assert!(
            claims.custom.catu.is_some(),
            "catu property should be present in verified token"
        );

        // Check that the catu structure contains the expected nested fields
        let catu = claims.custom.catu.unwrap();

        // Verify parent_path field (key 5) is properly deserialized
        assert!(catu.parent_path.is_some(), "parent_path should be present");
        let parent_path = catu.parent_path.unwrap();
        assert!(
            parent_path.suffix.is_some(),
            "suffix should be present in parent_path"
        );
        assert_eq!(
            parent_path.suffix.unwrap(),
            "/e059/7811/1640/47e1-9930-2a4341ea8b10",
            "parent_path.suffix should have the expected value"
        );

        // Verify filename field (key 6) is properly deserialized
        assert!(catu.filename.is_some(), "filename should be present");
        let filename = catu.filename.unwrap();
        assert!(
            filename.prefix.is_some(),
            "prefix should be present in filename"
        );
        assert_eq!(
            filename.prefix.unwrap(),
            "/1bd1e26e-3407-4805-b806-13216b34d4bf",
            "filename.prefix should have the expected value"
        );
    }
}
