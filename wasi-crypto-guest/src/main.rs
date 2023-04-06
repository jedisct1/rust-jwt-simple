mod asymmetric_common;
mod common;
mod raw;

pub mod error;
pub mod signatures;
pub mod symmetric;

pub mod prelude {
    pub use crate::error::Error as WasiCryptoError;
    pub use crate::signatures::*;
    pub use crate::symmetric::*;
}

use prelude::*;

fn main() -> Result<(), WasiCryptoError> {
    let mut options = SymmetricOptions::new();
    let nonce = [0u8; 12];
    options.set("nonce", &nonce)?;
    let key = SymmetricKey::generate("AES-128-GCM", Some(&options))?;
    let mut state = SymmetricState::new("AES-128-GCM", Some(&key), Some(&options))?;
    let ciphertext = state.encrypt(b"test")?;
    let mut state = SymmetricState::new("AES-128-GCM", Some(&key), Some(&options))?;
    state.decrypt(&ciphertext)?;
    Ok(())
}
