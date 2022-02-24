use crate::error::*;
use crate::raw;

pub(crate) struct ArrayOutput {
    handle: raw::ArrayOutput,
}

impl ArrayOutput {
    pub fn new(handle: raw::ArrayOutput) -> Self {
        ArrayOutput { handle }
    }

    pub fn into_vec(self) -> Result<Vec<u8>, Error> {
        let mut array = vec![0u8; unsafe { raw::array_output_len(self.handle) }?];
        unsafe { raw::array_output_pull(self.handle, array.as_mut_ptr(), array.len()) }?;
        Ok(array)
    }
}
