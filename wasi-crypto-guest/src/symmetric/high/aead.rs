use std::ops::Deref;

use super::low::*;
use crate::error::*;

#[derive(Debug)]
pub struct AeadKey(SymmetricKey);

impl Deref for AeadKey {
    type Target = SymmetricKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<SymmetricKey> for AeadKey {
    fn from(symmetric_key: SymmetricKey) -> Self {
        Self(symmetric_key)
    }
}

impl AeadKey {
    pub fn generate(alg: &'static str) -> Result<Self, Error> {
        SymmetricKey::generate(alg, None).map(Self)
    }

    pub fn from_raw(alg: &'static str, encoded: impl AsRef<[u8]>) -> Result<Self, Error> {
        SymmetricKey::from_raw(alg, encoded).map(Self)
    }
}

#[derive(Debug)]
pub struct Aead {
    state: SymmetricState,
}

impl Aead {
    pub fn new(key: &AeadKey, nonce: Option<&[u8]>, ad: Option<&[u8]>) -> Result<Self, Error> {
        let options = if let Some(nonce) = nonce {
            let mut options = SymmetricOptions::new();
            options.set("nonce", nonce)?;
            Some(options)
        } else {
            None
        };
        let mut state = SymmetricState::new(key.alg, Some(key), options.as_ref())?;
        if let Some(ad) = ad {
            state.absorb(ad)?;
        }
        Ok(Aead { state })
    }

    pub fn encrypt(&mut self, data: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
        self.state.encrypt(data)
    }

    pub fn decrypt(&mut self, ciphertext: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
        self.state.decrypt(ciphertext)
    }
}
