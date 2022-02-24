use crate::common::*;
use crate::error::*;
use crate::raw;

#[derive(Debug)]
pub(crate) struct PublicKey {
    pub handle: raw::Publickey,
    pub alg: &'static str,
}

impl Drop for PublicKey {
    fn drop(&mut self) {
        unsafe { raw::publickey_close(self.handle) }.unwrap()
    }
}

impl PublicKey {
    fn decode_from(
        alg_type: raw::AlgorithmType,
        alg: &'static str,
        encoded: impl AsRef<[u8]>,
        encoding: raw::PublickeyEncoding,
    ) -> Result<Self, Error> {
        let encoded = encoded.as_ref();
        let handle = unsafe {
            raw::publickey_import(alg_type, alg, encoded.as_ptr(), encoded.len(), encoding)
        }?;
        Ok(PublicKey { handle, alg })
    }

    pub fn from_raw(
        alg_type: raw::AlgorithmType,
        alg: &'static str,
        encoded: impl AsRef<[u8]>,
    ) -> Result<Self, Error> {
        Self::decode_from(alg_type, alg, encoded, raw::PUBLICKEY_ENCODING_RAW)
    }

    pub fn from_pkcs8(
        alg_type: raw::AlgorithmType,
        alg: &'static str,
        encoded: impl AsRef<[u8]>,
    ) -> Result<Self, Error> {
        Self::decode_from(alg_type, alg, encoded, raw::PUBLICKEY_ENCODING_PKCS8)
    }

    pub fn from_pem(
        alg_type: raw::AlgorithmType,
        alg: &'static str,
        encoded: impl AsRef<[u8]>,
    ) -> Result<Self, Error> {
        Self::decode_from(alg_type, alg, encoded, raw::PUBLICKEY_ENCODING_PEM)
    }

    pub fn from_sec(
        alg_type: raw::AlgorithmType,
        alg: &'static str,
        encoded: impl AsRef<[u8]>,
    ) -> Result<Self, Error> {
        Self::decode_from(alg_type, alg, encoded, raw::PUBLICKEY_ENCODING_SEC)
    }

    pub fn from_compressed_sec(
        alg_type: raw::AlgorithmType,
        alg: &'static str,
        encoded: impl AsRef<[u8]>,
    ) -> Result<Self, Error> {
        Self::decode_from(
            alg_type,
            alg,
            encoded,
            raw::PUBLICKEY_ENCODING_COMPRESSED_SEC,
        )
    }

    pub fn from_local(
        alg_type: raw::AlgorithmType,
        alg: &'static str,
        encoded: impl AsRef<[u8]>,
    ) -> Result<Self, Error> {
        Self::decode_from(alg_type, alg, encoded, raw::PUBLICKEY_ENCODING_LOCAL)
    }

    fn encode_as(&self, encoding: raw::PublickeyEncoding) -> Result<Vec<u8>, Error> {
        let array_handle = unsafe { raw::publickey_export(self.handle, encoding) }?;
        ArrayOutput::new(array_handle).into_vec()
    }

    pub fn raw(&self) -> Result<Vec<u8>, Error> {
        self.encode_as(raw::PUBLICKEY_ENCODING_RAW)
    }

    pub fn pkcs8(&self) -> Result<Vec<u8>, Error> {
        self.encode_as(raw::PUBLICKEY_ENCODING_PKCS8)
    }

    pub fn pem(&self) -> Result<Vec<u8>, Error> {
        self.encode_as(raw::PUBLICKEY_ENCODING_PEM)
    }

    pub fn sec(&self) -> Result<Vec<u8>, Error> {
        self.encode_as(raw::PUBLICKEY_ENCODING_SEC)
    }

    pub fn local(&self) -> Result<Vec<u8>, Error> {
        self.encode_as(raw::PUBLICKEY_ENCODING_LOCAL)
    }
}
