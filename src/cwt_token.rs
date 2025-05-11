use std::convert::TryInto;
use std::io::Cursor;

use anyhow::ensure;
use binstring::*;
use ciborium::de::from_reader as from_cbor;
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

impl CWTToken {
    /// Decode CWT token metadata that can be useful prior to signature/tag verification
    ///
    /// Similar to `Token::decode_metadata` but for CWT tokens.
    pub fn decode_metadata(token: impl AsRef<[u8]>) -> Result<TokenMetadata, Error> {
        let token = token.as_ref();
        let token_len = token.len();

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
        let header_len = token_len.saturating_sub(
            parts_cbor[2]
                .as_bytes()
                .ok_or(JWTError::CWTDecodingError)?
                .len(),
        );
        ensure!(header_len > 0 && header_len <= MAX_CWT_HEADER_LENGTH);

        let mut jwt_header = JWTHeader::default();

        // Parse protected header
        let mut protected_reader =
            Cursor::new(parts_cbor[0].as_bytes().ok_or(JWTError::CWTDecodingError)?);
        let protected_cbor: CBORValue = from_cbor(&mut protected_reader)?;
        let protected = protected_cbor.as_map().ok_or(JWTError::CWTDecodingError)?;
        jwt_header.mix_cwt(protected)?;

        // Parse unprotected header
        let unprotected = parts_cbor[1].as_map().ok_or(JWTError::CWTDecodingError)?;
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
        CustomClaims: DeserializeOwned + Default + 'static,
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
        let header_len = token_len.saturating_sub(
            parts_cbor[2]
                .as_bytes()
                .ok_or(JWTError::CWTDecodingError)?
                .len(),
        );
        ensure!(header_len > 0 && header_len <= MAX_CWT_HEADER_LENGTH);

        let mut jwt_header = JWTHeader::default();
        let mut claims = JWTClaims::<CustomClaims>::new();

        let mut protected_reader =
            Cursor::new(parts_cbor[0].as_bytes().ok_or(JWTError::CWTDecodingError)?);
        let protected_cbor: CBORValue = from_cbor(&mut protected_reader)?;
        let protected = protected_cbor.as_map().ok_or(JWTError::CWTDecodingError)?;
        jwt_header.mix_cwt(protected)?;

        let unprotected = parts_cbor[1].as_map().ok_or(JWTError::CWTDecodingError)?;
        jwt_header.mix_cwt(unprotected)?;

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
        claims.mix_cwt::<CustomClaims>(claims_)?;

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
    let custom_cbor = CBORValue::Map(
        custom_claims
            .iter()
            .map(|(k, v)| (CBORValue::Text(k.clone()), v.clone()))
            .collect(),
    );

    // Serialize to bytes
    let mut bytes = Vec::new();
    to_cbor(&custom_cbor, &mut bytes).map_err(|_| JWTError::CWTDecodingError)?;

    // Check size limits for serialized data
    if bytes.len() > MAX_CUSTOM_CLAIMS_SIZE {
        bail!(JWTError::CWTDecodingError);
    }

    // Deserialize into the custom type
    let result = from_cbor::<T, _>(std::io::Cursor::new(bytes));
    match result {
        Ok(custom) => Ok(custom),
        Err(_) => Ok(T::default()), // Fall back to default on deserialization errors
    }
}

impl<CustomClaims> JWTClaims<CustomClaims>
where
    CustomClaims: DeserializeOwned + Default,
{
    fn mix_cwt<T: DeserializeOwned + Default + 'static>(
        &mut self,
        cwt: &[(CBORValue, CBORValue)],
    ) -> Result<(), Error>
    where
        CustomClaims: 'static,
    {
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
        if !custom_claims_map.is_empty()
            && std::any::TypeId::of::<T>() == std::any::TypeId::of::<CustomClaims>()
        {
            // Only set custom claims if the type parameter matches
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

    // Create a more complex custom claims type that should fail
    #[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
    struct ComplexCustomData {
        required_field: String,
    }

    // Trying to parse as a different custom claims type should give default values (fail gracefully)
    let complex_claims = key
        .verify_cwt_token_with_custom_claims::<ComplexCustomData>(token, Some(options))
        .unwrap();
    assert_eq!(complex_claims.custom, ComplexCustomData::default());
}

#[test]
fn test_duplicate_cwt_claim_key() {
    use ciborium::value::Value as CBORValue;

    // Create duplicate keys in the CBOR map
    let mut claims = JWTClaims::<NoCustomClaims>::new();

    // Create a CBOR map with duplicate keys
    let mut cwt = Vec::new();

    // Standard claim key
    cwt.push((CBORValue::Integer(123.into()), CBORValue::Text("value1".into())));

    // Duplicate claim key (same integer key)
    cwt.push((CBORValue::Integer(123.into()), CBORValue::Text("value2".into())));

    // Attempt to mix the claims - should return a DuplicateCWTClaimKey error
    let result = claims.mix_cwt::<NoCustomClaims>(&cwt);

    assert!(result.is_err());
    match result.unwrap_err().downcast::<JWTError>() {
        Ok(jwt_error) => {
            match jwt_error {
                JWTError::DuplicateCWTClaimKey(key) => {
                    assert_eq!(key, "123");
                },
                err => panic!("Expected DuplicateCWTClaimKey error, got: {:?}", err),
            }
        },
        Err(err) => panic!("Expected JWTError, got: {:?}", err),
    }

    // Test with duplicate text keys
    let mut cwt = Vec::new();
    cwt.push((CBORValue::Text("test_key".into()), CBORValue::Text("value1".into())));
    cwt.push((CBORValue::Text("test_key".into()), CBORValue::Text("value2".into())));

    let result = claims.mix_cwt::<NoCustomClaims>(&cwt);

    assert!(result.is_err());
    match result.unwrap_err().downcast::<JWTError>() {
        Ok(jwt_error) => {
            match jwt_error {
                JWTError::DuplicateCWTClaimKey(key) => {
                    assert_eq!(key, "test_key");
                },
                err => panic!("Expected DuplicateCWTClaimKey error, got: {:?}", err),
            }
        },
        Err(err) => panic!("Expected JWTError, got: {:?}", err),
    }

    // Test with non-duplicate keys (should succeed)
    let mut cwt = Vec::new();
    cwt.push((CBORValue::Integer(123.into()), CBORValue::Text("value1".into())));
    cwt.push((CBORValue::Integer(124.into()), CBORValue::Text("value2".into())));

    let result = claims.mix_cwt::<NoCustomClaims>(&cwt);
    assert!(result.is_ok());
}
