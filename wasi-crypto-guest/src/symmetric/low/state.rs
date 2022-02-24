use super::{OptSymmetricKey, SymmetricKey, SymmetricOptions, Tag};
use crate::common::*;
use crate::error::*;
use crate::raw;

#[derive(Debug)]
pub struct SymmetricState {
    handle: raw::SymmetricState,
}

impl SymmetricState {
    pub fn new(
        alg: &'static str,
        symmetric_key: Option<&SymmetricKey>,
        options: Option<&SymmetricOptions>,
    ) -> Result<Self, Error> {
        let opt_symmetric_key = if let Some(symmetric_key) = symmetric_key {
            if symmetric_key.alg != alg {
                return Err(Error::InvalidKey);
            }
            OptSymmetricKey::some(symmetric_key)
        } else {
            OptSymmetricKey::none()
        };
        let opt_options = if let Some(options) = options {
            OptOptions::some(&options.0)
        } else {
            OptOptions::none()
        };
        let symmetric_state_handle =
            unsafe { raw::symmetric_state_open(alg, &opt_symmetric_key, &opt_options) }?;
        Ok(SymmetricState {
            handle: symmetric_state_handle,
        })
    }

    pub fn absorb(&mut self, data: impl AsRef<[u8]>) -> Result<(), Error> {
        let data = data.as_ref();
        unsafe { raw::symmetric_state_absorb(self.handle, data.as_ptr(), data.len()) }
    }

    pub fn squeeze_into(&mut self, mut out: impl AsMut<[u8]>) -> Result<(), Error> {
        let out = out.as_mut();
        unsafe { raw::symmetric_state_squeeze(self.handle, out.as_mut_ptr(), out.len()) }
    }

    pub fn squeeze(&mut self, len: usize) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; len];
        self.squeeze_into(&mut out)?;
        Ok(out)
    }

    pub fn max_tag_len(&mut self) -> Result<usize, Error> {
        unsafe { raw::symmetric_state_max_tag_len(self.handle) }
    }

    pub fn encrypt(&mut self, data: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
        let data = data.as_ref();
        let max_out_len = data.len() + self.max_tag_len()?;
        let mut out = vec![0u8; max_out_len];
        let out_len = unsafe {
            raw::symmetric_state_encrypt(
                self.handle,
                out.as_mut_ptr(),
                max_out_len,
                data.as_ptr(),
                data.len(),
            )
        }?;
        out.truncate(out_len);
        Ok(out)
    }

    pub fn encrypt_detached(
        &mut self,
        mut out: impl AsMut<[u8]>,
        data: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let out = out.as_mut();
        let data = data.as_ref();
        let tag_handle = unsafe {
            raw::symmetric_state_encrypt_detached(
                self.handle,
                out.as_mut_ptr(),
                out.len(),
                data.as_ptr(),
                data.len(),
            )
        }?;
        Ok(Tag::new(tag_handle).into_bytes())
    }

    pub fn decrypt(&mut self, ciphertext: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
        let ciphertext = ciphertext.as_ref();
        let max_out_len = ciphertext
            .len()
            .checked_sub(self.max_tag_len()?)
            .ok_or(Error::InvalidTag)?;
        let mut out = vec![0u8; max_out_len];
        let out_len = unsafe {
            raw::symmetric_state_decrypt(
                self.handle,
                out.as_mut_ptr(),
                max_out_len,
                ciphertext.as_ptr(),
                ciphertext.len(),
            )
        }?;
        out.truncate(out_len);
        Ok(out)
    }

    pub fn decrypt_detached(
        &mut self,
        mut out: impl AsMut<[u8]>,
        ciphertext: impl AsRef<[u8]>,
        raw_tag: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let out = out.as_mut();
        let ciphertext = ciphertext.as_ref();
        let raw_tag = raw_tag.as_ref();
        unsafe {
            raw::symmetric_state_decrypt_detached(
                self.handle,
                out.as_mut_ptr(),
                out.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                raw_tag.as_ptr(),
                raw_tag.len(),
            )
        }?;
        Ok(())
    }

    pub fn ratchet(&mut self) -> Result<(), Error> {
        unsafe { raw::symmetric_state_ratchet(self.handle) }
    }

    pub fn squeeze_key(&mut self, target_alg: &'static str) -> Result<SymmetricKey, Error> {
        let symmetric_key_handle =
            unsafe { raw::symmetric_state_squeeze_key(self.handle, target_alg) }?;
        let symmetric_key = SymmetricKey {
            handle: symmetric_key_handle,
            alg: target_alg,
        };
        Ok(symmetric_key)
    }

    pub fn squeeze_tag(&mut self) -> Result<Vec<u8>, Error> {
        let tag_handle = unsafe { raw::symmetric_state_squeeze_tag(self.handle) }?;
        Ok(Tag::new(tag_handle).into_bytes())
    }

    pub fn verify(&mut self, raw_tag: impl AsRef<[u8]>) -> Result<(), Error> {
        let raw_tag = raw_tag.as_ref();
        let tag_handle = unsafe { raw::symmetric_state_squeeze_tag(self.handle) }?;
        unsafe { raw::symmetric_tag_verify(tag_handle, raw_tag.as_ptr(), raw_tag.len()) }
    }
}

impl Drop for SymmetricState {
    fn drop(&mut self) {
        unsafe { raw::symmetric_state_close(self.handle) }.unwrap()
    }
}
