//! Concat KDF shared by the ECDH-ES key agreement modes.

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use hmac_sha256::Hash as SHA256;
use zeroize::Zeroizing;

use crate::error::*;
use crate::jwe_header::JWEHeader;

/// Derive the wrapping key from the shared secret and token header.
///
/// Callers must check the header's algorithm against the key type first.
pub(crate) fn derive_kek(
    shared_secret: &[u8],
    key_len: usize,
    header: &JWEHeader,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let (apu, apv) = party_info(header)?;
    let kek = concat_kdf(shared_secret, key_len, &header.algorithm, &apu, &apv);
    Ok(Zeroizing::new(kek))
}

/// Derive a key using Concat KDF as specified in NIST SP 800-56A.
fn concat_kdf(shared_secret: &[u8], key_len: usize, alg: &str, apu: &[u8], apv: &[u8]) -> Vec<u8> {
    let alg_bytes = alg.as_bytes();
    let alg_len = (alg_bytes.len() as u32).to_be_bytes();
    let apu_len = (apu.len() as u32).to_be_bytes();
    let apv_len = (apv.len() as u32).to_be_bytes();
    let key_bits = ((key_len * 8) as u32).to_be_bytes();

    let mut derived_key = Vec::with_capacity(key_len);
    let mut counter: u32 = 1;

    while derived_key.len() < key_len {
        let counter_bytes = counter.to_be_bytes();

        let mut hasher = SHA256::new();
        hasher.update(counter_bytes);
        hasher.update(shared_secret);
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

/// A missing parameter counts as empty.
/// The values must differ when both are present, even if both are empty.
fn party_info(header: &JWEHeader) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let decode = |value: &Option<String>| -> Result<Vec<u8>, Error> {
        match value {
            None => Ok(Vec::new()),
            Some(value) => Ok(Base64UrlSafeNoPadding::decode_to_vec(value, None)
                .map_err(|_| JWTError::InvalidJWEFormat)?),
        }
    };
    let apu = decode(&header.apu)?;
    let apv = decode(&header.apv)?;
    if header.apu.is_some() && header.apv.is_some() {
        ensure!(apu != apv, JWTError::InvalidJWEFormat);
    }
    Ok((apu, apv))
}

#[cfg(test)]
mod tests {
    use super::*;

    // This example uses direct key agreement, without key wrapping.
    #[test]
    fn concat_kdf_matches_rfc7518_appendix_c() {
        let z = [
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
            110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
        ];
        let derived = concat_kdf(&z, 16, "A128GCM", b"Alice", b"Bob");
        assert_eq!(
            derived,
            [86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26]
        );
    }

    fn header(apu: Option<&str>, apv: Option<&str>) -> JWEHeader {
        let mut header = JWEHeader::new("ECDH-ES+A256KW", "A256GCM");
        header.apu = apu.map(Into::into);
        header.apv = apv.map(Into::into);
        header
    }

    #[test]
    fn party_info_decoding() {
        for (apu, apv, expected_apu, expected_apv) in [
            (None, None, "", ""),
            (Some("QWxpY2U"), None, "Alice", ""),
            (None, Some("Qm9i"), "", "Bob"),
            (Some(""), None, "", ""),
            (Some("QWxpY2U"), Some(""), "Alice", ""),
            (Some("QWxpY2U"), Some("Qm9i"), "Alice", "Bob"),
        ] {
            let (decoded_apu, decoded_apv) = party_info(&header(apu, apv)).unwrap();
            assert_eq!(decoded_apu, expected_apu.as_bytes(), "apu: {:?}", apu);
            assert_eq!(decoded_apv, expected_apv.as_bytes(), "apv: {:?}", apv);
        }

        for (apu, apv) in [
            (Some("Qm9i"), Some("Qm9i")),
            (Some(""), Some("")),
            (Some("Qm9i="), None),
            (None, Some("QWxpY2U=")),
            (Some("Qm+i"), None),
            (None, Some("QWxpY2V")),
            (Some("Q"), None),
            (Some("Qm9i "), None),
        ] {
            assert!(
                matches!(
                    party_info(&header(apu, apv))
                        .unwrap_err()
                        .downcast_ref::<JWTError>(),
                    Some(JWTError::InvalidJWEFormat)
                ),
                "apu: {:?}, apv: {:?}",
                apu,
                apv
            );
        }
    }
}
