use crate::asymmetric_common::*;
use crate::error::*;
use crate::raw;

use super::{Signature, SignatureVerificationState};

#[derive(Debug)]
pub struct SignaturePublicKey(pub(crate) PublicKey);

impl SignaturePublicKey {
    pub fn from_raw(alg: &'static str, encoded: impl AsRef<[u8]>) -> Result<Self, Error> {
        Ok(SignaturePublicKey(PublicKey::from_raw(
            raw::ALGORITHM_TYPE_SIGNATURES,
            alg,
            encoded,
        )?))
    }

    pub fn from_pkcs8(alg: &'static str, encoded: impl AsRef<[u8]>) -> Result<Self, Error> {
        Ok(SignaturePublicKey(PublicKey::from_pkcs8(
            raw::ALGORITHM_TYPE_SIGNATURES,
            alg,
            encoded,
        )?))
    }

    pub fn from_pem(alg: &'static str, encoded: impl AsRef<[u8]>) -> Result<Self, Error> {
        Ok(SignaturePublicKey(PublicKey::from_pem(
            raw::ALGORITHM_TYPE_SIGNATURES,
            alg,
            encoded,
        )?))
    }

    pub fn from_sec(alg: &'static str, encoded: impl AsRef<[u8]>) -> Result<Self, Error> {
        Ok(SignaturePublicKey(PublicKey::from_sec(
            raw::ALGORITHM_TYPE_SIGNATURES,
            alg,
            encoded,
        )?))
    }

    pub fn from_compressed_sec(
        alg: &'static str,
        encoded: impl AsRef<[u8]>,
    ) -> Result<Self, Error> {
        Ok(SignaturePublicKey(PublicKey::from_compressed_sec(
            raw::ALGORITHM_TYPE_SIGNATURES,
            alg,
            encoded,
        )?))
    }

    pub fn from_local(alg: &'static str, encoded: impl AsRef<[u8]>) -> Result<Self, Error> {
        Ok(SignaturePublicKey(PublicKey::from_local(
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

    pub fn sec(&self) -> Result<Vec<u8>, Error> {
        self.0.sec()
    }

    pub fn local(&self) -> Result<Vec<u8>, Error> {
        self.0.local()
    }

    pub fn multipart_signature_verify(&self) -> Result<SignatureVerificationState, Error> {
        let handle = unsafe { raw::signature_verification_state_open(self.0.handle) }?;
        Ok(SignatureVerificationState {
            handle,
            alg: self.0.alg.clone(),
        })
    }

    pub fn signature_verify(
        &self,
        msg: impl AsRef<[u8]>,
        signature: &Signature,
    ) -> Result<(), Error> {
        let mut state = self.multipart_signature_verify()?;
        state.update(msg)?;
        state.verify(signature)
    }
}
