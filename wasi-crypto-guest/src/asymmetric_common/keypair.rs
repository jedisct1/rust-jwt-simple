use super::publickey::*;
use crate::common::*;
use crate::error::*;
use crate::raw;

#[derive(Debug)]
pub(crate) struct KeyPair {
    pub handle: raw::Keypair,
    pub alg: &'static str,
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        unsafe { raw::keypair_close(self.handle) }.unwrap()
    }
}

impl KeyPair {
    pub fn generate(alg_type: raw::AlgorithmType, alg: &'static str) -> Result<Self, Error> {
        let handle = unsafe { raw::keypair_generate(alg_type, alg, &OptOptions::none()) }?;
        Ok(KeyPair { handle, alg })
    }

    pub fn publickey(&self) -> Result<PublicKey, Error> {
        let handle = unsafe { raw::keypair_publickey(self.handle)? };
        Ok(PublicKey {
            handle,
            alg: self.alg,
        })
    }

    fn decode_from(
        alg_type: raw::AlgorithmType,
        alg: &'static str,
        encoded: impl AsRef<[u8]>,
        encoding: raw::KeypairEncoding,
    ) -> Result<Self, Error> {
        let encoded = encoded.as_ref();
        let handle = unsafe {
            raw::keypair_import(alg_type, alg, encoded.as_ptr(), encoded.len(), encoding)
        }?;
        Ok(KeyPair { handle, alg })
    }

    pub fn from_raw(
        alg_type: raw::AlgorithmType,
        alg: &'static str,
        encoded: impl AsRef<[u8]>,
    ) -> Result<Self, Error> {
        let encoded = encoded.as_ref();
        Self::decode_from(alg_type, alg, encoded, raw::KEYPAIR_ENCODING_RAW)
    }

    pub fn from_pkcs8(
        alg_type: raw::AlgorithmType,
        alg: &'static str,
        encoded: impl AsRef<[u8]>,
    ) -> Result<Self, Error> {
        Self::decode_from(alg_type, alg, encoded, raw::KEYPAIR_ENCODING_PKCS8)
    }

    pub fn from_pem(
        alg_type: raw::AlgorithmType,
        alg: &'static str,
        encoded: impl AsRef<[u8]>,
    ) -> Result<Self, Error> {
        Self::decode_from(alg_type, alg, encoded, raw::KEYPAIR_ENCODING_PEM)
    }

    pub fn from_local(
        alg_type: raw::AlgorithmType,
        alg: &'static str,
        encoded: impl AsRef<[u8]>,
    ) -> Result<Self, Error> {
        Self::decode_from(alg_type, alg, encoded, raw::KEYPAIR_ENCODING_LOCAL)
    }

    fn encode_as(&self, encoding: raw::KeypairEncoding) -> Result<Vec<u8>, Error> {
        let array_handle = unsafe { raw::keypair_export(self.handle, encoding) }?;
        ArrayOutput::new(array_handle).into_vec()
    }

    pub fn raw(&self) -> Result<Vec<u8>, Error> {
        self.encode_as(raw::KEYPAIR_ENCODING_RAW)
    }

    pub fn pkcs8(&self) -> Result<Vec<u8>, Error> {
        self.encode_as(raw::KEYPAIR_ENCODING_PKCS8)
    }

    pub fn pem(&self) -> Result<Vec<u8>, Error> {
        self.encode_as(raw::KEYPAIR_ENCODING_PEM)
    }

    pub fn local(&self) -> Result<Vec<u8>, Error> {
        self.encode_as(raw::KEYPAIR_ENCODING_LOCAL)
    }
}
