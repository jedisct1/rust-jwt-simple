use std::ops::Deref;

use super::low::*;
use crate::error::*;

#[derive(Debug)]
pub struct HashKey(SymmetricKey);

impl Deref for HashKey {
    type Target = SymmetricKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<SymmetricKey> for HashKey {
    fn from(symmetric_key: SymmetricKey) -> Self {
        Self(symmetric_key)
    }
}

impl HashKey {
    pub fn generate(alg: &'static str) -> Result<Self, Error> {
        SymmetricKey::generate(alg, None).map(Self)
    }

    pub fn from_raw(alg: &'static str, encoded: impl AsRef<[u8]>) -> Result<Self, Error> {
        SymmetricKey::from_raw(alg, encoded).map(Self)
    }
}

#[derive(Debug)]
pub struct Hash {
    state: SymmetricState,
}

impl Hash {
    pub fn keyed(key: &HashKey) -> Result<Self, Error> {
        let state = SymmetricState::new(key.alg, Some(key), None)?;
        Ok(Hash { state })
    }

    pub fn unkeyed(alg: &'static str) -> Result<Self, Error> {
        let state = SymmetricState::new(alg, None, None)?;
        Ok(Hash { state })
    }

    pub fn absorb(&mut self, data: impl AsRef<[u8]>) -> Result<(), Error> {
        self.state.absorb(data)
    }

    pub fn squeeze(&mut self, len: usize) -> Result<Vec<u8>, Error> {
        self.state.squeeze(len)
    }

    pub fn hash(
        alg: &'static str,
        data: impl AsRef<[u8]>,
        out_len: usize,
        key: Option<&HashKey>,
    ) -> Result<Vec<u8>, Error> {
        let mut state = if let Some(key) = key {
            Hash::keyed(key)
        } else {
            Hash::unkeyed(alg)
        }?;
        state.absorb(data)?;
        state.squeeze(out_len)
    }
}
