#[cfg(feature = "eddsa")]
mod eddsa;
#[cfg(feature = "es256")]
mod es256;
#[cfg(feature = "es256k")]
mod es256k;
#[cfg(feature = "es384")]
mod es384;
#[cfg(any(feature = "hs256", feature = "hs384", feature = "hs512"))]
mod hmac;
#[cfg(any(
    feature = "rs256",
    feature = "rs384",
    feature = "rs512",
    feature = "ps256",
    feature = "ps384",
    feature = "ps512"
))]
mod rsa;

#[cfg(feature = "eddsa")]
pub use self::eddsa::*;
#[cfg(feature = "es256")]
pub use self::es256::*;
#[cfg(feature = "es256k")]
pub use self::es256k::*;
#[cfg(feature = "es384")]
pub use self::es384::*;
#[cfg(any(feature = "hs256", feature = "hs384", feature = "hs512"))]
pub use self::hmac::*;
#[cfg(any(
    feature = "rs256",
    feature = "rs384",
    feature = "rs512",
    feature = "ps256",
    feature = "ps384",
    feature = "ps512"
))]
pub use self::rsa::*;
