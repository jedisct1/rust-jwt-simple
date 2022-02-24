use std::ops::Deref;

use super::low::*;
use crate::error::*;

#[derive(Debug)]
pub struct AuthKey(SymmetricKey);

impl Deref for AuthKey {
    type Target = SymmetricKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<SymmetricKey> for AuthKey {
    fn from(symmetric_key: SymmetricKey) -> Self {
        Self(symmetric_key)
    }
}

impl AuthKey {
    pub fn generate(alg: &'static str) -> Result<Self, Error> {
        SymmetricKey::generate(alg, None).map(Self)
    }

    pub fn from_raw(alg: &'static str, encoded: impl AsRef<[u8]>) -> Result<Self, Error> {
        SymmetricKey::from_raw(alg, encoded).map(Self)
    }
}

#[derive(Debug)]
pub struct Auth {
    state: SymmetricState,
}

impl Auth {
    pub fn new(key: &AuthKey) -> Result<Self, Error> {
        let state = SymmetricState::new(key.alg, Some(key), None)?;
        Ok(Auth { state })
    }

    pub fn absorb(&mut self, data: impl AsRef<[u8]>) -> Result<(), Error> {
        self.state.absorb(data)
    }

    pub fn tag(&mut self) -> Result<Vec<u8>, Error> {
        self.state.squeeze_tag()
    }

    pub fn tag_verify(&mut self, raw_tag: impl AsRef<[u8]>) -> Result<(), Error> {
        self.state.verify(raw_tag)
    }

    pub fn auth(data: impl AsRef<[u8]>, key: &AuthKey) -> Result<Vec<u8>, Error> {
        let mut state = Auth::new(key)?;
        state.absorb(data)?;
        state.tag()
    }

    pub fn auth_verify(
        data: impl AsRef<[u8]>,
        key: &AuthKey,
        raw_tag: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let mut state = Auth::new(key)?;
        state.absorb(data)?;
        state.tag_verify(raw_tag)
    }
}
