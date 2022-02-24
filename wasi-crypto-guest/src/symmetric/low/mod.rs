mod state;
pub use state::*;

use crate::common::*;
use crate::error::*;
use crate::raw;

#[derive(Debug)]
pub struct SymmetricOptions(Options<algorithm_type::Symmetric>);

impl SymmetricOptions {
    pub fn new() -> Self {
        SymmetricOptions(Options::new(raw::ALGORITHM_TYPE_SYMMETRIC))
    }

    pub fn set(&mut self, name: &'static str, value: impl AsRef<[u8]>) -> Result<(), Error> {
        let value = value.as_ref();
        unsafe { raw::options_set(self.0.handle, name, value.as_ptr(), value.len()) }
    }

    pub fn set_u64(&mut self, name: &'static str, value: u64) -> Result<(), Error> {
        unsafe { raw::options_set_u64(self.0.handle, name, value) }
    }
}

impl Default for SymmetricOptions {
    fn default() -> Self {
        Self::new()
    }
}

struct OptSymmetricKey;

impl OptSymmetricKey {
    fn none() -> raw::OptSymmetricKey {
        raw::OptSymmetricKey {
            tag: raw::OPT_SYMMETRIC_KEY_U_NONE,
            u: raw::OptSymmetricKeyUnion { none: false },
        }
    }

    fn some(symmetric_key: &SymmetricKey) -> raw::OptSymmetricKey {
        raw::OptSymmetricKey {
            tag: raw::OPT_SYMMETRIC_KEY_U_SOME,
            u: raw::OptSymmetricKeyUnion {
                some: symmetric_key.handle,
            },
        }
    }
}

#[derive(Debug)]
pub struct SymmetricKey {
    pub(crate) handle: raw::SymmetricKey,
    pub alg: &'static str,
}

impl SymmetricKey {
    pub fn generate(
        alg: &'static str,
        options: Option<&SymmetricOptions>,
    ) -> Result<SymmetricKey, Error> {
        let opt_options = if let Some(options) = options {
            OptOptions::some(&options.0)
        } else {
            OptOptions::none()
        };
        let handle = unsafe { raw::symmetric_key_generate(alg, &opt_options) }?;
        Ok(SymmetricKey { handle, alg })
    }

    pub fn from_raw(alg: &'static str, encoded: impl AsRef<[u8]>) -> Result<Self, Error> {
        let encoded = encoded.as_ref();
        let handle = unsafe { raw::symmetric_key_import(alg, encoded.as_ptr(), encoded.len()) }?;
        Ok(SymmetricKey { handle, alg })
    }

    pub fn raw(&self) -> Result<Vec<u8>, Error> {
        let array_handle = unsafe { raw::symmetric_key_export(self.handle) }?;
        ArrayOutput::new(array_handle).into_vec()
    }
}

impl Drop for SymmetricKey {
    fn drop(&mut self) {
        unsafe { raw::symmetric_key_close(self.handle) }.unwrap()
    }
}

#[derive(Debug)]
pub struct Tag {
    handle: raw::SymmetricTag,
    closed: bool,
}

impl Tag {
    fn new(handle: raw::SymmetricTag) -> Self {
        Tag {
            handle,
            closed: false,
        }
    }

    pub fn into_bytes(mut self) -> Vec<u8> {
        let mut bytes = vec![0u8; unsafe { raw::symmetric_tag_len(self.handle) }.unwrap()];
        unsafe { raw::symmetric_tag_pull(self.handle, bytes.as_mut_ptr(), bytes.len()) }.unwrap();
        self.closed = true;
        bytes
    }
}

impl Drop for Tag {
    fn drop(&mut self) {
        if !self.closed {
            unsafe { raw::symmetric_tag_close(self.handle).unwrap() }
        }
    }
}
