use std::ops::Deref;

use super::low::*;
use crate::error::*;

#[derive(Debug)]
pub struct HkdfKey(SymmetricKey);

impl Deref for HkdfKey {
    type Target = SymmetricKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<SymmetricKey> for HkdfKey {
    fn from(symmetric_key: SymmetricKey) -> Self {
        Self(symmetric_key)
    }
}

impl HkdfKey {
    pub fn generate(alg: &'static str) -> Result<Self, Error> {
        SymmetricKey::generate(alg, None).map(Self)
    }

    pub fn from_raw(alg: &'static str, encoded: impl AsRef<[u8]>) -> Result<Self, Error> {
        SymmetricKey::from_raw(alg, encoded).map(Self)
    }
}

#[derive(Debug)]
pub struct HkdfPrk(SymmetricKey);

impl Deref for HkdfPrk {
    type Target = SymmetricKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<SymmetricKey> for HkdfPrk {
    fn from(symmetric_key: SymmetricKey) -> Self {
        Self(symmetric_key)
    }
}

impl HkdfPrk {
    pub fn from_raw(alg: &'static str, encoded: impl AsRef<[u8]>) -> Result<Self, Error> {
        SymmetricKey::from_raw(alg, encoded).map(Self)
    }
}

#[derive(Debug)]
pub struct Hkdf {
    prk: HkdfPrk,
    exp_alg: &'static str,
}

impl Hkdf {
    pub fn new(exp_alg: &'static str, key: &HkdfKey, salt: Option<&[u8]>) -> Result<Self, Error> {
        let salt = salt.as_ref();
        let mut state = SymmetricState::new(key.alg, Some(key), None)?;
        if let Some(salt) = salt {
            state.absorb(salt)?;
        };
        let prk = state.squeeze_key(exp_alg).map(HkdfPrk)?;
        Ok(Hkdf { prk, exp_alg })
    }

    pub fn expand(&self, info: impl AsRef<[u8]>, len: usize) -> Result<Vec<u8>, Error> {
        let info = info.as_ref();
        let mut state = SymmetricState::new(self.exp_alg, Some(&self.prk), None)?;
        state.absorb(info)?;
        state.squeeze(len)
    }
}
