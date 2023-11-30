mod eddsa;
mod es256;
mod es256k;
mod es384;
mod hmac;

#[cfg(not(any(feature = "pure-rust", target_arch = "wasm32", target_arch = "wasm64")))]
mod rsa;
#[cfg(any(feature = "pure-rust", target_arch = "wasm32", target_arch = "wasm64"))]
mod rsa_legacy;

pub use self::eddsa::*;
pub use self::es256::*;
pub use self::es256k::*;
pub use self::es384::*;
pub use self::hmac::*;

#[cfg(not(any(feature = "pure-rust", target_arch = "wasm32", target_arch = "wasm64")))]
pub use self::rsa::*;
#[cfg(any(feature = "pure-rust", target_arch = "wasm32", target_arch = "wasm64"))]
pub use self::rsa_legacy::*;
