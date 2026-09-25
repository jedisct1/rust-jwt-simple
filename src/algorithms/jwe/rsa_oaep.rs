//! RSA-OAEP key management algorithm for JWE.
//!
//! Implements RSA-OAEP (RSA with OAEP using SHA-1).
//!
//! Note: RSA-OAEP-256 (with SHA-256) is not currently supported because the underlying
//! boring/superboring crates do not expose the API to specify the OAEP hash function.

#[cfg(any(feature = "pure-rust", target_arch = "wasm32", target_arch = "wasm64"))]
use superboring as boring;

use boring::pkey::{Private, Public};
use boring::rsa::{Padding, Rsa};
use serde::{de::DeserializeOwned, Serialize};

use crate::algorithms::jwk::{JwkDescriptor, KeyRole};
use crate::algorithms::rsa::{
    check_rsa_private_key, check_rsa_public_key, rsa_jwk_descriptor, rsa_private_key_from_jwk,
    rsa_private_key_thumbprint, rsa_private_key_to_jwk, rsa_public_key_from_jwk,
    rsa_public_key_thumbprint, rsa_public_key_to_jwk,
};
use crate::claims::*;
use crate::error::*;
use crate::jwe_header::JWEHeader;
use crate::jwe_token::{DecryptionOptions, EncryptionOptions, JWEToken, JWETokenMetadata};

const RSA_OAEP_PUBLIC_JWK: JwkDescriptor =
    rsa_jwk_descriptor("RSA-OAEP", KeyRole::EncryptionPublic);

const RSA_OAEP_PRIVATE_JWK: JwkDescriptor =
    rsa_jwk_descriptor("RSA-OAEP", KeyRole::DecryptionPrivate);

/// RSA public key for encryption (RSA-OAEP with SHA-1).
#[derive(Debug, Clone)]
pub struct RsaOaepEncryptionKey {
    pk: Rsa<Public>,
    key_id: Option<String>,
}

impl RsaOaepEncryptionKey {
    /// Create an encryption key from a DER-encoded public key.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let pk = Rsa::<Public>::public_key_from_der(der)
            .or_else(|_| Rsa::<Public>::public_key_from_der_pkcs1(der))?;
        check_rsa_public_key(&pk)?;
        Ok(RsaOaepEncryptionKey { pk, key_id: None })
    }

    /// Create an encryption key from a PEM-encoded public key.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let pem = pem.trim();
        let pk = Rsa::<Public>::public_key_from_pem(pem.as_bytes())
            .or_else(|_| Rsa::<Public>::public_key_from_pem_pkcs1(pem.as_bytes()))?;
        check_rsa_public_key(&pk)?;
        Ok(RsaOaepEncryptionKey { pk, key_id: None })
    }

    /// Export the key as DER.
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.pk.public_key_to_der().map_err(Into::into)
    }

    /// Export the key as PEM.
    pub fn to_pem(&self) -> Result<String, Error> {
        let bytes = self.pk.public_key_to_pem()?;
        Ok(String::from_utf8(bytes)?)
    }

    /// Import an encryption key from a public RSA JWK.
    ///
    /// The modulus must be 2048 to 4096 bits long, and the exponent 65537.
    /// See [strict JWK validation](crate#strict-jwk-validation) for the other rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let (pk, key_id) = rsa_public_key_from_jwk(jwk, &RSA_OAEP_PUBLIC_JWK)?;
        Ok(RsaOaepEncryptionKey { pk, key_id })
    }

    /// Export the key as a JWK, with `alg: RSA-OAEP` and `use: enc`.
    pub fn to_jwk(&self) -> String {
        rsa_public_key_to_jwk(&self.pk, &RSA_OAEP_PUBLIC_JWK, self.key_id.as_deref())
    }

    /// The JWK thumbprint of the key.
    pub fn jwk_thumbprint(&self) -> String {
        rsa_public_key_thumbprint(&self.pk)
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

    fn wrap_key(&self, cek: &[u8]) -> Result<Vec<u8>, Error> {
        let mut encrypted = vec![0u8; self.pk.size() as usize];
        let encrypted_len = self
            .pk
            .public_encrypt(cek, &mut encrypted, Padding::PKCS1_OAEP)
            .map_err(|_| JWTError::InvalidEncryptionKey)?;
        encrypted.truncate(encrypted_len);

        Ok(encrypted)
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
        let content_encryption = options.content_encryption;
        let mut header = JWEHeader::new("RSA-OAEP", content_encryption.alg_name());

        if let Some(key_id) = &self.key_id {
            header.key_id = Some(key_id.clone());
        }
        if let Some(key_id) = &options.key_id {
            header.key_id = Some(key_id.clone());
        }
        if let Some(cty) = &options.content_type {
            header.content_type = Some(cty.clone());
        }

        JWEToken::build_from_claims(&header, &claims, content_encryption, |cek| {
            self.wrap_key(cek)
        })
    }
}

/// RSA key pair for decryption (RSA-OAEP with SHA-1).
#[derive(Clone)]
pub struct RsaOaepDecryptionKey {
    sk: Rsa<Private>,
    key_id: Option<String>,
}

impl std::fmt::Debug for RsaOaepDecryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaOaepDecryptionKey")
            .field("key_id", &self.key_id)
            .field("modulus_bits", &self.sk.n().num_bits())
            .finish_non_exhaustive()
    }
}

impl RsaOaepDecryptionKey {
    /// Create a decryption key from a DER-encoded private key.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let sk = Rsa::<Private>::private_key_from_der(der)?;
        check_rsa_private_key(&sk)?;
        Ok(RsaOaepDecryptionKey { sk, key_id: None })
    }

    /// Create a decryption key from a PEM-encoded private key.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let pem = pem.trim();
        let sk = Rsa::<Private>::private_key_from_pem(pem.as_bytes())?;
        check_rsa_private_key(&sk)?;
        Ok(RsaOaepDecryptionKey { sk, key_id: None })
    }

    /// Generate a new RSA key pair.
    pub fn generate(modulus_bits: usize) -> Result<Self, Error> {
        match modulus_bits {
            2048 | 3072 | 4096 => {}
            _ => bail!(JWTError::UnsupportedRSAModulus),
        };
        let sk = Rsa::<Private>::generate(modulus_bits as u32)?;
        check_rsa_private_key(&sk)?;
        Ok(RsaOaepDecryptionKey { sk, key_id: None })
    }

    /// Import a decryption key from a private RSA JWK.
    ///
    /// The modulus must be 2048 to 4096 bits long, and the exponent 65537.
    /// See [strict JWK validation](crate#strict-jwk-validation) for the other rules.
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let (sk, key_id) = rsa_private_key_from_jwk(jwk, &RSA_OAEP_PRIVATE_JWK)?;
        Ok(RsaOaepDecryptionKey { sk, key_id })
    }

    /// Export the key as a JWK, private key included.
    /// Use `encryption_key().to_jwk()` to share the public key.
    pub fn to_jwk(&self) -> String {
        rsa_private_key_to_jwk(&self.sk, &RSA_OAEP_PRIVATE_JWK, self.key_id.as_deref())
    }

    /// The JWK thumbprint of the public key.
    pub fn jwk_thumbprint(&self) -> String {
        rsa_private_key_thumbprint(&self.sk)
    }

    /// Export the private key as DER.
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.sk.private_key_to_der().map_err(Into::into)
    }

    /// Export the private key as PEM.
    pub fn to_pem(&self) -> Result<String, Error> {
        let bytes = self.sk.private_key_to_pem()?;
        Ok(String::from_utf8(bytes)?)
    }

    /// Get the public encryption key.
    pub fn encryption_key(&self) -> RsaOaepEncryptionKey {
        let pk = Rsa::<Public>::from_public_components(
            self.sk.n().to_owned().expect("failed to get modulus"),
            self.sk.e().to_owned().expect("failed to get exponent"),
        )
        .expect("failed to create public key");
        RsaOaepEncryptionKey {
            pk,
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

    fn unwrap_key(&self, encrypted_key: &[u8]) -> Result<Vec<u8>, Error> {
        let mut cek = vec![0u8; self.sk.size() as usize];
        let cek_len = self
            .sk
            .private_decrypt(encrypted_key, &mut cek, Padding::PKCS1_OAEP)
            .map_err(|_| JWTError::KeyUnwrapFailed)?;
        cek.truncate(cek_len);

        Ok(cek)
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
    /// Decryption does not authenticate the sender: the encryption key is public,
    /// so anyone can mint a token that decrypts successfully, with any claims.
    /// Do not treat the result as trusted input without a separate signature check.
    pub fn decrypt_token<CustomClaims: DeserializeOwned>(
        &self,
        token: &str,
        options: Option<DecryptionOptions>,
    ) -> Result<JWTClaims<CustomClaims>, Error> {
        JWEToken::decrypt("RSA-OAEP", token, options, |_header, encrypted_key| {
            self.unwrap_key(encrypted_key)
        })
    }

    /// Decode token metadata without decrypting.
    pub fn decode_metadata(token: &str) -> Result<JWETokenMetadata, Error> {
        JWEToken::decode_metadata(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::jwe::ContentEncryption;
    use crate::algorithms::rsa_test_keys::{der_from_pem, key_2048, KEYS};
    use crate::algorithms::test_util::{error_of, unb64};
    use crate::claims::NoCustomClaims;

    #[test]
    fn jwk_round_trip() {
        let key = key_2048();
        let decryption_key = RsaOaepDecryptionKey::from_pem(key.private_pem)
            .unwrap()
            .with_key_id("oaep");
        let private_jwk = decryption_key.to_jwk();
        let public_jwk = decryption_key.encryption_key().to_jwk();
        let exported: serde_json::Value = serde_json::from_str(&public_jwk).unwrap();
        assert_eq!(exported["alg"], "RSA-OAEP");
        assert_eq!(exported["use"], "enc");

        let restored = RsaOaepDecryptionKey::from_jwk(&private_jwk).unwrap();
        let encryption_key = RsaOaepEncryptionKey::from_jwk(&public_jwk).unwrap();
        assert_eq!(restored.key_id(), Some("oaep"));
        assert_eq!(restored.to_jwk(), private_jwk);
        assert_eq!(restored.jwk_thumbprint(), encryption_key.jwk_thumbprint());
        let token = encryption_key
            .encrypt(Claims::create(coarsetime::Duration::from_hours(1)))
            .unwrap();
        restored
            .decrypt_token::<NoCustomClaims>(&token, None)
            .unwrap();

        let rs256 = crate::algorithms::RS256KeyPair::from_pem(key.private_pem).unwrap();
        let wrong_ops = public_jwk.replace(r#""use":"enc""#, r#""key_ops":["verify"]"#);
        assert!(matches!(
            error_of(RsaOaepEncryptionKey::from_jwk(&rs256.public_key().to_jwk())),
            JWTError::InvalidPublicKey
        ));
        assert!(matches!(
            error_of(RsaOaepDecryptionKey::from_jwk(&rs256.to_jwk())),
            JWTError::InvalidKeyPair
        ));
        assert!(matches!(
            error_of(crate::algorithms::RS256PublicKey::from_jwk(&public_jwk)),
            JWTError::InvalidPublicKey
        ));
        assert!(matches!(
            error_of(RsaOaepEncryptionKey::from_jwk(&wrong_ops)),
            JWTError::InvalidPublicKey
        ));
    }

    #[test]
    fn webcrypto_exports() {
        use crate::algorithms::jwk_test_vectors;

        for export in jwk_test_vectors::ALL {
            let export: serde_json::Value = serde_json::from_str(export).unwrap();
            let entry = &export["keys"]["RSA-OAEP"];
            let decryption_key =
                RsaOaepDecryptionKey::from_jwk(&entry["private"].to_string()).unwrap();
            let encryption_key =
                RsaOaepEncryptionKey::from_jwk(&entry["public"].to_string()).unwrap();
            assert_eq!(
                decryption_key.jwk_thumbprint(),
                encryption_key.jwk_thumbprint()
            );
            let token = encryption_key
                .encrypt(Claims::create(coarsetime::Duration::from_hours(1)))
                .unwrap();
            decryption_key
                .decrypt_token::<NoCustomClaims>(&token, None)
                .unwrap();

            let rs256 = &export["keys"]["RS256"];
            assert!(RsaOaepEncryptionKey::from_jwk(&rs256["public"].to_string()).is_err());
        }
    }

    #[test]
    fn policy_applies_to_every_format() {
        for key in KEYS {
            let private_der = der_from_pem(key.private_pem);
            let public_der = der_from_pem(key.public_pem);
            if !key.is_allowed() {
                let case = format!("{}-bit e={}", key.bits, key.e);
                for res in [
                    RsaOaepDecryptionKey::from_pem(key.private_pem),
                    RsaOaepDecryptionKey::from_der(&private_der),
                ] {
                    let error = error_of(res);
                    assert!(key.is_policy_error(&error, true), "{}: {:?}", case, error);
                }
                for res in [
                    RsaOaepEncryptionKey::from_pem(key.public_pem),
                    RsaOaepEncryptionKey::from_der(&public_der),
                ] {
                    if key.backend_rejects_public_key() {
                        assert!(res.is_err(), "{}", case);
                    } else {
                        let error = error_of(res);
                        assert!(key.is_policy_error(&error, false), "{}: {:?}", case, error);
                    }
                }
                continue;
            }

            let decryption_key = RsaOaepDecryptionKey::from_pem(key.private_pem).unwrap();
            let decryption_key_der = RsaOaepDecryptionKey::from_der(&private_der).unwrap();
            for encryption_key in [
                decryption_key.encryption_key(),
                RsaOaepEncryptionKey::from_pem(key.public_pem).unwrap(),
                RsaOaepEncryptionKey::from_der(&public_der).unwrap(),
            ] {
                let token = encryption_key
                    .encrypt(Claims::create(coarsetime::Duration::from_hours(1)))
                    .unwrap();
                for key in [&decryption_key, &decryption_key_der] {
                    key.decrypt_token::<NoCustomClaims>(&token, None).unwrap();
                }
            }
        }
    }

    // Made with the 2048-bit test key by jose 6.2.12 (Node.js v26.10.0)
    // and jwcrypto 1.5.6.
    // Each token was also decrypted by the library that created it.
    const JOSE: &str = concat!(
        "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.J6VjtYUrReEaSvD3eeUUMHrxssRTEM0jNmNIeHSnTKk",
        "clbDVgNGQVNJSo3w6hd6fx5V7Pdlxsb01ztHHQE83L43BbDCar0GwBM7sxA1ZzDeb_MnTKHvGFqWw_ecSzuavice7L",
        "Y4Jkl5XqOKOSOExDCk_Y8G8TXgEjY1boHk2zXSCuOAYaaB17o52xFKV4q65JKr1FogjMcsC-pgjYvqpZUz3FPHin1f",
        "paQHk779js29i5NOPdMyHq_r8DdYdI-yCyCezk4HFTfszz9YZWbIqGsplM7pt1w0CQjPEg348WzJq5qJl8YTj0Mige",
        "LRvFyigMp0SQXXy69q9PJoVksYAAA.mZ4xZwHW6rNRtIZU.m_ZKKUhmylm5mpPOlDQ.W1gZNuotAaRlu2Nb6i3Ihg",
    );
    const JWCRYPTO: &str = concat!(
        "eyJhbGciOiAiUlNBLU9BRVAiLCAiZW5jIjogIkEyNTZHQ00ifQ.LtkcqwrK8FOkLVNQr4fKXvNOlNlym74qIbr60hM",
        "zO4Xml1ywztx0ztUnISZvaorejrGCye6PYZi8QGnWzLha5vguodZiESsD1_BdKJ5sAqu8cpG74KPWks9xgWgsOJ5vx",
        "hiKz7bZtb0noFqNt9vpp79ka4BsZax4SsT8Esxfo6hMgWzOl0MjsIBFhNQbcWXg01Xb63NMbck4HcAtRK9oBMIK010",
        "inMBR6SSEJYXmQNpIIRt99v-akoceQnQ7YsMjS0wklJT8OQTty825GBL2r3RSVG2JDitkVITmu17Bcs-QTdQ_MYC5T",
        "0l9ZH3-EIR1YY69CaXbONly6FgiQOPKgQ.XRo4r-Vrp9wkmGB1.LCEw2AcSJ84VOcnaERVjGWSF.F1ZLn1BazdohgB",
        "oJ-DqQ2Q",
    );

    // jwt-simple 0.14.0 with superboring 0.1.16 used SHA-256 here instead of SHA-1.
    // OpenSSL confirmed that this token requires SHA-256.
    const LEGACY_SHA256: &str = concat!(
        "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.I9W_c3vfDLvw-RhkTOZNRvCTbbNgBFMcFTk_XGa1D0j",
        "6rZyNvCp4IS4DsWaF07ewca5YTeuCHbVi8zkCvm7kv96cYd6plRmCd7VsntiF9HSKp7bjGW2L18yCeJUna1Bx2R9yh",
        "YrX3qw_4jZsVM9zv3tnPoit8SnYKOybTJnONOxFqRYSB5QdOMZYwNewkjqdCIN4I-Bt5Q5FWHupLWEKfxILAmdnTMo",
        "VxT-nS0K0vTmUZl4PqGN51JfCrrIi2mcEwnkiLndRujAQ4433iG1GtcIeVyFxGXQfVMnE9peRMGbxtM2TdfGj-t-qJ",
        "APqqqsZaldxwZpMBvh-eqweJH_F3A.triWZnnV1xMa2aSL.7L9pFBvVGD3jluxcLGLIJSxXXoOiqSAvdr5f.O7JBPf",
        "ciEiiIs3B7osx-FQ",
    );

    #[test]
    fn decrypts_other_implementations_but_not_sha256_tokens() {
        let key = RsaOaepDecryptionKey::from_pem(key_2048().private_pem).unwrap();
        for (token, issuer) in [(JOSE, "jose"), (JWCRYPTO, "jwcrypto")] {
            let claims = key.decrypt_token::<NoCustomClaims>(token, None).unwrap();
            assert_eq!(claims.issuer.as_deref(), Some(issuer));
        }
        assert!(matches!(
            error_of(key.decrypt_token::<NoCustomClaims>(LEGACY_SHA256, None)),
            JWTError::KeyUnwrapFailed
        ));
    }

    /// Check for SHA-1 and an empty OAEP label without either backend's OAEP code.
    fn unwrap_with_oaep_sha1(private_pem: &str, token: &str) -> Vec<u8> {
        use hmac_sha1_compact::Hash as SHA1;
        use superboring::reexports::rsa::pkcs1::DecodeRsaPrivateKey;
        use superboring::reexports::rsa::traits::{PrivateKeyParts, PublicKeyParts};
        use superboring::reexports::rsa::{BigUint, RsaPrivateKey};

        let mgf1 = |seed: &[u8], len: usize| -> Vec<u8> {
            (0u32..)
                .flat_map(|counter| {
                    let mut h = SHA1::new();
                    h.update(seed);
                    h.update(counter.to_be_bytes());
                    h.finalize()
                })
                .take(len)
                .collect()
        };
        let xor =
            |a: &[u8], b: Vec<u8>| -> Vec<u8> { a.iter().zip(b).map(|(x, y)| x ^ y).collect() };

        let key = RsaPrivateKey::from_pkcs1_pem(private_pem).unwrap();
        let encrypted_key = unb64(token.split('.').nth(1).unwrap());
        let m = BigUint::from_bytes_be(&encrypted_key)
            .modpow(key.d(), key.n())
            .to_bytes_be();
        let mut em = vec![0u8; key.size()];
        em[key.size() - m.len()..].copy_from_slice(&m);

        assert_eq!(em[0], 0);
        let (masked_seed, masked_db) = em[1..].split_at(20);
        let seed = xor(masked_seed, mgf1(masked_db, 20));
        let db = xor(masked_db, mgf1(&seed, masked_db.len()));
        assert_eq!(db[..20], SHA1::hash(b""));
        let separator = 20 + db[20..].iter().position(|&x| x != 0).unwrap();
        assert_eq!(db[separator], 1);
        db[separator + 1..].to_vec()
    }

    #[test]
    fn encrypts_with_oaep_sha1() {
        let pem = key_2048().private_pem;
        let encryption_key = RsaOaepDecryptionKey::from_pem(pem)
            .unwrap()
            .encryption_key();
        for (content_encryption, cek_len) in [
            (ContentEncryption::A128GCM, 16),
            (ContentEncryption::A256GCM, 32),
        ] {
            let options = EncryptionOptions {
                content_encryption,
                ..Default::default()
            };
            let token = encryption_key
                .encrypt_with_options(
                    Claims::create(coarsetime::Duration::from_hours(1)),
                    &options,
                )
                .unwrap();
            assert_eq!(unwrap_with_oaep_sha1(pem, &token).len(), cek_len);
        }
        assert_eq!(unwrap_with_oaep_sha1(pem, JOSE).len(), 16);
        assert_eq!(unwrap_with_oaep_sha1(pem, JWCRYPTO).len(), 32);
    }
}
