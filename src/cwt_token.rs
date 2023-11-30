use std::convert::TryInto;
use std::io::Cursor;

use binstring::*;
use ciborium::de::from_reader as from_cbor;
use ciborium::ser::into_writer as to_cbor;
use ciborium::value::Value as CBORValue;
use coarsetime::Duration;

use crate::claims::*;
use crate::common::*;
use crate::error::*;
use crate::jwt_header::*;

pub const MAX_CWT_HEADER_LENGTH: usize = 4096;

/// Utilities to get information about a CWT token
pub struct CWTToken;

impl CWTToken {
    pub(crate) fn verify<AuthenticationOrSignatureFn>(
        jwt_alg_name: &'static str,
        token: impl AsRef<[u8]>,
        options: Option<VerificationOptions>,
        authentication_or_signature_fn: AuthenticationOrSignatureFn,
    ) -> Result<JWTClaims<NoCustomClaims>, Error>
    where
        AuthenticationOrSignatureFn: FnOnce(&str, &[u8]) -> Result<(), Error>,
    {
        let options = options.unwrap_or_default();
        let token = token.as_ref();
        let token_len = token.len();
        if let Some(max_token_length) = options.max_token_length {
            ensure!(token_len <= max_token_length, JWTError::TokenTooLong);
        }

        let mut parts_reader = Cursor::new(token);
        let parts_cbor_tagged = from_cbor(&mut parts_reader)?;

        let (tag, parts_cbor): (u64, &[CBORValue]) = match &parts_cbor_tagged {
            ciborium::tag::Captured::<CBORValue>(Some(tag), x) => {
                ensure!(*tag == 17 || *tag == 18, JWTError::CWTDecodingError);
                (*tag, x.as_array().ok_or(JWTError::CWTDecodingError)?)
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
        let mut claims: JWTClaims<NoCustomClaims> = Claims::create(Default::default());

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

impl<CustomClaims> JWTClaims<CustomClaims> {
    fn mix_cwt(&mut self, cwt: &[(CBORValue, CBORValue)]) -> Result<(), Error> {
        for (key, value) in cwt {
            let key_id: i32 = key
                .as_integer()
                .ok_or(JWTError::CWTDecodingError)?
                .try_into()
                .map_err(|_| JWTError::CWTDecodingError)?;
            match key_id {
                I_IAT => {
                    let ts: u64 = if let Some(ts) = value.as_integer() {
                        ts.try_into().map_err(|_| JWTError::CWTDecodingError)?
                    } else if let Some(ts) = value.as_float() {
                        let f: f64 = ts.try_into().map_err(|_| JWTError::CWTDecodingError)?;
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
                        let f: f64 = ts.try_into().map_err(|_| JWTError::CWTDecodingError)?;
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
                        let f: f64 = ts.try_into().map_err(|_| JWTError::CWTDecodingError)?;
                        f.round() as _
                    } else {
                        bail!(JWTError::CWTDecodingError)
                    };
                    self.invalid_before = Some(Duration::from_secs(ts));
                }
                I_ISS => {
                    self.issuer = Some(value.as_text().ok_or(JWTError::CWTDecodingError)?.into());
                }
                I_SUB => {
                    self.subject = Some(value.as_text().ok_or(JWTError::CWTDecodingError)?.into());
                }
                I_AUD => {
                    let audiences = value.as_text().ok_or(JWTError::CWTDecodingError)?.into();
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
                _ => {}
            }
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
    options.time_tolerance = Some(Duration::from_days(100000));
    let _ = key.verify_cwt_token(token, Some(options)).unwrap();
}
