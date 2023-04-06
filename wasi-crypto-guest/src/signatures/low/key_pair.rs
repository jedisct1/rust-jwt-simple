use super::public_key::*;
use super::{Signature, SignatureState};
use crate::asymmetric_common::*;
use crate::error::*;
use crate::raw;

#[derive(Debug)]
pub struct SignatureKeyPair(KeyPair);

impl SignatureKeyPair {
    pub fn generate(alg: &'static str) -> Result<Self, Error> {
        Ok(SignatureKeyPair(KeyPair::generate(
            raw::ALGORITHM_TYPE_SIGNATURES,
            alg,
        )?))
    }

    pub fn publickey(&self) -> Result<SignaturePublicKey, Error> {
        Ok(SignaturePublicKey(self.0.publickey()?))
    }

    pub fn from_raw(alg: &'static str, encoded: impl AsRef<[u8]>) -> Result<Self, Error> {
        Ok(SignatureKeyPair(KeyPair::from_raw(
            raw::ALGORITHM_TYPE_SIGNATURES,
            alg,
            encoded,
        )?))
    }

    pub fn from_pkcs8(alg: &'static str, encoded: impl AsRef<[u8]>) -> Result<Self, Error> {
        Ok(SignatureKeyPair(KeyPair::from_pkcs8(
            raw::ALGORITHM_TYPE_SIGNATURES,
            alg,
            encoded,
        )?))
    }

    pub fn from_pem(alg: &'static str, encoded: impl AsRef<[u8]>) -> Result<Self, Error> {
        Ok(SignatureKeyPair(KeyPair::from_pem(
            raw::ALGORITHM_TYPE_SIGNATURES,
            alg,
            encoded,
        )?))
    }

    pub fn from_local(alg: &'static str, encoded: impl AsRef<[u8]>) -> Result<Self, Error> {
        Ok(SignatureKeyPair(KeyPair::from_local(
            raw::ALGORITHM_TYPE_SIGNATURES,
            alg,
            encoded,
        )?))
    }

    pub fn raw(&self) -> Result<Vec<u8>, Error> {
        self.0.raw()
    }

    pub fn pkcs8(&self) -> Result<Vec<u8>, Error> {
        self.0.pkcs8()
    }

    pub fn pem(&self) -> Result<Vec<u8>, Error> {
        self.0.pem()
    }

    pub fn local(&self) -> Result<Vec<u8>, Error> {
        self.0.local()
    }

    pub fn multipart_signature(&self) -> Result<SignatureState, Error> {
        let handle = unsafe { raw::signature_state_open(self.0.handle) }?;
        Ok(SignatureState {
            handle,
            alg: self.0.alg,
        })
    }

    pub fn sign(&self, msg: impl AsRef<[u8]>) -> Result<Signature, Error> {
        let mut state = self.multipart_signature()?;
        state.update(msg)?;
        state.sign()
    }
}
