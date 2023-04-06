use super::Signature;
use crate::error::*;
use crate::raw;

#[derive(Debug)]
pub struct SignatureState {
    pub(crate) handle: raw::SignatureState,
    pub alg: &'static str,
}

impl Drop for SignatureState {
    fn drop(&mut self) {
        unsafe { raw::signature_state_close(self.handle) }.unwrap()
    }
}

impl SignatureState {
    pub fn update(&mut self, data: impl AsRef<[u8]>) -> Result<(), Error> {
        let data = data.as_ref();
        unsafe { raw::signature_state_update(self.handle, data.as_ptr(), data.len()) }
    }

    pub fn sign(&self) -> Result<Signature, Error> {
        let handle = unsafe { raw::signature_state_sign(self.handle) }?;
        Ok(Signature {
            handle,
            alg: self.alg,
        })
    }
}

#[derive(Debug)]
pub struct SignatureVerificationState {
    pub(crate) handle: raw::SignatureVerificationState,
    pub alg: &'static str,
}

impl Drop for SignatureVerificationState {
    fn drop(&mut self) {
        unsafe { raw::signature_verification_state_close(self.handle) }.unwrap()
    }
}

impl SignatureVerificationState {
    pub fn update(&mut self, data: impl AsRef<[u8]>) -> Result<(), Error> {
        let data = data.as_ref();
        unsafe { raw::signature_verification_state_update(self.handle, data.as_ptr(), data.len()) }
    }

    pub fn verify(&self, signature: &Signature) -> Result<(), Error> {
        unsafe { raw::signature_verification_state_verify(self.handle, signature.handle) }
    }
}
