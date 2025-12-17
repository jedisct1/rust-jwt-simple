//! Content encryption algorithms for JWE.
//!
//! This module implements the content encryption algorithms specified in RFC 7518.
//! Currently supported: A256GCM, A128GCM.

#[cfg(any(feature = "pure-rust", target_arch = "wasm32", target_arch = "wasm64"))]
use superboring as boring;

use boring::symm::{Cipher, Crypter, Mode};
use rand::RngCore;
use zeroize::Zeroize;

use crate::error::*;

/// Content encryption algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContentEncryption {
    /// AES-256-GCM (recommended default)
    #[default]
    A256GCM,
    /// AES-128-GCM
    A128GCM,
}

impl ContentEncryption {
    /// Get the JWE "enc" header value for this algorithm.
    pub fn alg_name(&self) -> &'static str {
        match self {
            ContentEncryption::A256GCM => "A256GCM",
            ContentEncryption::A128GCM => "A128GCM",
        }
    }

    /// Parse a content encryption algorithm from its JWE name.
    pub fn from_alg_name(name: &str) -> Result<Self, Error> {
        match name {
            "A256GCM" => Ok(ContentEncryption::A256GCM),
            "A128GCM" => Ok(ContentEncryption::A128GCM),
            _ => bail!(JWTError::UnsupportedContentEncryption(name.to_string())),
        }
    }

    /// Get the required key size in bytes.
    pub fn key_size(&self) -> usize {
        match self {
            ContentEncryption::A256GCM => 32,
            ContentEncryption::A128GCM => 16,
        }
    }

    /// Get the IV size in bytes.
    pub fn iv_size(&self) -> usize {
        12 // GCM uses 96-bit IV
    }

    /// Get the authentication tag size in bytes.
    pub fn tag_size(&self) -> usize {
        16 // GCM uses 128-bit tag
    }

    /// Generate a random Content Encryption Key (CEK) for this algorithm.
    pub fn generate_cek(&self) -> Vec<u8> {
        let mut cek = vec![0u8; self.key_size()];
        rand::thread_rng().fill_bytes(&mut cek);
        cek
    }

    /// Generate a random IV for this algorithm.
    pub fn generate_iv(&self) -> Vec<u8> {
        let mut iv = vec![0u8; self.iv_size()];
        rand::thread_rng().fill_bytes(&mut iv);
        iv
    }

    fn cipher(&self) -> Cipher {
        match self {
            ContentEncryption::A256GCM => Cipher::aes_256_gcm(),
            ContentEncryption::A128GCM => Cipher::aes_128_gcm(),
        }
    }

    /// Encrypt plaintext using the content encryption algorithm.
    ///
    /// Returns (ciphertext, authentication_tag).
    pub fn encrypt(
        &self,
        cek: &[u8],
        iv: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        ensure!(cek.len() == self.key_size(), JWTError::InvalidEncryptionKey);
        ensure!(iv.len() == self.iv_size(), JWTError::InvalidIV);

        let cipher = self.cipher();

        let mut crypter = Crypter::new(cipher, Mode::Encrypt, cek, Some(iv))?;
        crypter.aad_update(aad)?;

        let mut ciphertext = vec![0u8; plaintext.len() + cipher.block_size()];
        let mut count = crypter.update(plaintext, &mut ciphertext)?;
        count += crypter.finalize(&mut ciphertext[count..])?;
        ciphertext.truncate(count);

        let mut tag = vec![0u8; self.tag_size()];
        crypter.get_tag(&mut tag)?;

        Ok((ciphertext, tag))
    }

    /// Decrypt ciphertext using the content encryption algorithm.
    ///
    /// Returns the plaintext.
    pub fn decrypt(
        &self,
        cek: &[u8],
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        ensure!(cek.len() == self.key_size(), JWTError::InvalidEncryptionKey);
        ensure!(iv.len() == self.iv_size(), JWTError::InvalidIV);
        ensure!(tag.len() == self.tag_size(), JWTError::InvalidJWEAuthTag);

        let cipher = self.cipher();

        let mut crypter = Crypter::new(cipher, Mode::Decrypt, cek, Some(iv))?;
        crypter.aad_update(aad)?;
        crypter.set_tag(tag)?;

        let mut plaintext = vec![0u8; ciphertext.len() + cipher.block_size()];
        let mut count = crypter.update(ciphertext, &mut plaintext)?;
        count += crypter
            .finalize(&mut plaintext[count..])
            .map_err(|_| JWTError::DecryptionFailed)?;
        plaintext.truncate(count);

        Ok(plaintext)
    }
}

/// A Content Encryption Key (CEK) that is zeroized on drop.
#[derive(Clone)]
pub struct CEK {
    key: Vec<u8>,
}

impl CEK {
    /// Create a new CEK from bytes.
    pub fn new(key: Vec<u8>) -> Self {
        CEK { key }
    }

    /// Get the key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

impl Drop for CEK {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl AsRef<[u8]> for CEK {
    fn as_ref(&self) -> &[u8] {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a256gcm_roundtrip() {
        let enc = ContentEncryption::A256GCM;
        let cek = enc.generate_cek();
        let iv = enc.generate_iv();
        let aad = b"additional authenticated data";
        let plaintext = b"Hello, World!";

        let (ciphertext, tag) = enc.encrypt(&cek, &iv, aad, plaintext).unwrap();
        let decrypted = enc.decrypt(&cek, &iv, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_a128gcm_roundtrip() {
        let enc = ContentEncryption::A128GCM;
        let cek = enc.generate_cek();
        let iv = enc.generate_iv();
        let aad = b"additional authenticated data";
        let plaintext = b"Hello, World!";

        let (ciphertext, tag) = enc.encrypt(&cek, &iv, aad, plaintext).unwrap();
        let decrypted = enc.decrypt(&cek, &iv, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let enc = ContentEncryption::A256GCM;
        let cek = enc.generate_cek();
        let iv = enc.generate_iv();
        let aad = b"additional authenticated data";
        let plaintext = b"Hello, World!";

        let (mut ciphertext, tag) = enc.encrypt(&cek, &iv, aad, plaintext).unwrap();

        // Tamper with ciphertext
        ciphertext[0] ^= 0xff;

        let result = enc.decrypt(&cek, &iv, aad, &ciphertext, &tag);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_aad_fails() {
        let enc = ContentEncryption::A256GCM;
        let cek = enc.generate_cek();
        let iv = enc.generate_iv();
        let aad = b"additional authenticated data";
        let plaintext = b"Hello, World!";

        let (ciphertext, tag) = enc.encrypt(&cek, &iv, aad, plaintext).unwrap();

        // Use different AAD for decryption
        let wrong_aad = b"wrong aad";
        let result = enc.decrypt(&cek, &iv, wrong_aad, &ciphertext, &tag);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let enc = ContentEncryption::A256GCM;
        let cek = enc.generate_cek();
        let wrong_cek = enc.generate_cek();
        let iv = enc.generate_iv();
        let aad = b"additional authenticated data";
        let plaintext = b"Hello, World!";

        let (ciphertext, tag) = enc.encrypt(&cek, &iv, aad, plaintext).unwrap();
        let result = enc.decrypt(&wrong_cek, &iv, aad, &ciphertext, &tag);
        assert!(result.is_err());
    }
}
