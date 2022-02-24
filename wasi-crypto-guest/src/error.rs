use crate::raw;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::convert::TryFrom;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, TryFromPrimitive, IntoPrimitive)]
#[repr(u16)]
pub enum Error {
    GuestError = raw::CRYPTO_ERRNO_GUEST_ERROR,
    NotImplemented = raw::CRYPTO_ERRNO_NOT_IMPLEMENTED,
    UnsupportedFeature = raw::CRYPTO_ERRNO_UNSUPPORTED_FEATURE,
    ProhibitedOperation = raw::CRYPTO_ERRNO_PROHIBITED_OPERATION,
    UnsupportedEncoding = raw::CRYPTO_ERRNO_UNSUPPORTED_ENCODING,
    UnsupportedAlgorithm = raw::CRYPTO_ERRNO_UNSUPPORTED_ALGORITHM,
    UnsupportedOption = raw::CRYPTO_ERRNO_UNSUPPORTED_OPTION,
    InvalidKey = raw::CRYPTO_ERRNO_INVALID_KEY,
    InvalidLength = raw::CRYPTO_ERRNO_INVALID_LENGTH,
    VerificationFailed = raw::CRYPTO_ERRNO_VERIFICATION_FAILED,
    RngError = raw::CRYPTO_ERRNO_RNG_ERROR,
    AlgorithmFailure = raw::CRYPTO_ERRNO_ALGORITHM_FAILURE,
    InvalidSignature = raw::CRYPTO_ERRNO_INVALID_SIGNATURE,
    Closed = raw::CRYPTO_ERRNO_CLOSED,
    InvalidHandle = raw::CRYPTO_ERRNO_INVALID_HANDLE,
    Overflow = raw::CRYPTO_ERRNO_OVERFLOW,
    InternalError = raw::CRYPTO_ERRNO_INTERNAL_ERROR,
    TooManyHandles = raw::CRYPTO_ERRNO_TOO_MANY_HANDLES,
    KeyNotSupported = raw::CRYPTO_ERRNO_KEY_NOT_SUPPORTED,
    KeyRequired = raw::CRYPTO_ERRNO_KEY_REQUIRED,
    InvalidTag = raw::CRYPTO_ERRNO_INVALID_TAG,
    InvalidOperation = raw::CRYPTO_ERRNO_INVALID_OPERATION,
    NonceRequired = raw::CRYPTO_ERRNO_NONCE_REQUIRED,
    InvalidNonce = raw::CRYPTO_ERRNO_INVALID_NONCE,
    OptionNotSet = raw::CRYPTO_ERRNO_OPTION_NOT_SET,
    NotFound = raw::CRYPTO_ERRNO_NOT_FOUND,
    ParametersMissing = raw::CRYPTO_ERRNO_PARAMETERS_MISSING,
    InProgress = raw::CRYPTO_ERRNO_IN_PROGRESS,
    IncompatibleKeys = raw::CRYPTO_ERRNO_INCOMPATIBLE_KEYS,
    Expired = raw::CRYPTO_ERRNO_EXPIRED,
}

impl Error {
    pub fn from_raw_error(e: u16) -> Option<Self> {
        match e {
            raw::CRYPTO_ERRNO_SUCCESS => None,
            e => Some(Error::try_from(e).expect("Unexpected error")),
        }
    }
}
