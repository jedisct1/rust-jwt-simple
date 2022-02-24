#![allow(dead_code, unused_variables)]

use core::mem::MaybeUninit;

pub use crate::error::Error;
pub type Result<T, E = Error> = core::result::Result<T, E>;
pub type CryptoErrno = u16;
/// Operation succeeded.
pub const CRYPTO_ERRNO_SUCCESS: CryptoErrno = 0;
/// An error occurred when trying to during a conversion from a host type to a guest type.
///
/// Only an internal bug can throw this error.
pub const CRYPTO_ERRNO_GUEST_ERROR: CryptoErrno = 1;
/// The requested operation is valid, but not implemented by the host.
pub const CRYPTO_ERRNO_NOT_IMPLEMENTED: CryptoErrno = 2;
/// The requested feature is not supported by the chosen algorithm.
pub const CRYPTO_ERRNO_UNSUPPORTED_FEATURE: CryptoErrno = 3;
/// The requested operation is valid, but was administratively prohibited.
pub const CRYPTO_ERRNO_PROHIBITED_OPERATION: CryptoErrno = 4;
/// Unsupported encoding for an import or export operation.
pub const CRYPTO_ERRNO_UNSUPPORTED_ENCODING: CryptoErrno = 5;
/// The requested algorithm is not supported by the host.
pub const CRYPTO_ERRNO_UNSUPPORTED_ALGORITHM: CryptoErrno = 6;
/// The requested option is not supported by the currently selected algorithm.
pub const CRYPTO_ERRNO_UNSUPPORTED_OPTION: CryptoErrno = 7;
/// An invalid or incompatible key was supplied.
///
/// The key may not be valid, or was generated for a different algorithm or parameters set.
pub const CRYPTO_ERRNO_INVALID_KEY: CryptoErrno = 8;
/// The currently selected algorithm doesn't support the requested output length.
///
/// This error is thrown by non-extensible hash functions, when requesting an output size larger than they produce out of a single block.
pub const CRYPTO_ERRNO_INVALID_LENGTH: CryptoErrno = 9;
/// A signature or authentication tag verification failed.
pub const CRYPTO_ERRNO_VERIFICATION_FAILED: CryptoErrno = 10;
/// A secure random numbers generator is not available.
///
/// The requested operation requires random numbers, but the host cannot securely generate them at the moment.
pub const CRYPTO_ERRNO_RNG_ERROR: CryptoErrno = 11;
/// An error was returned by the underlying cryptography library.
///
/// The host may be running out of memory, parameters may be incompatible with the chosen implementation of an algorithm or another unexpected error may have happened.
///
/// Ideally, the specification should provide enough details and guidance to make this error impossible to ever be thrown.
///
/// Realistically, the WASI crypto module cannot possibly cover all possible error types implementations can return, especially since some of these may be language-specific.
/// This error can thus be thrown when other error types are not suitable, and when the original error comes from the cryptographic primitives themselves and not from the WASI module.
pub const CRYPTO_ERRNO_ALGORITHM_FAILURE: CryptoErrno = 12;
/// The supplied signature is invalid, or incompatible with the chosen algorithm.
pub const CRYPTO_ERRNO_INVALID_SIGNATURE: CryptoErrno = 13;
/// An attempt was made to close a handle that was already closed.
pub const CRYPTO_ERRNO_CLOSED: CryptoErrno = 14;
/// A function was called with an unassigned handle, a closed handle, or handle of an unexpected type.
pub const CRYPTO_ERRNO_INVALID_HANDLE: CryptoErrno = 15;
/// The host needs to copy data to a guest-allocated buffer, but that buffer is too small.
pub const CRYPTO_ERRNO_OVERFLOW: CryptoErrno = 16;
/// An internal error occurred.
///
/// This error is reserved to internal consistency checks, and must only be sent if the internal state of the host remains safe after an inconsistency was detected.
pub const CRYPTO_ERRNO_INTERNAL_ERROR: CryptoErrno = 17;
/// Too many handles are currently open, and a new one cannot be created.
///
/// Implementations are free to represent handles as they want, and to enforce limits to limit resources usage.
pub const CRYPTO_ERRNO_TOO_MANY_HANDLES: CryptoErrno = 18;
/// A key was provided, but the chosen algorithm doesn't support keys.
///
/// This is returned by symmetric operations.
///
/// Many hash functions, in particular, do not support keys without being used in particular constructions.
/// Blindly ignoring a key provided by mistake while trying to open a context for such as function could cause serious security vulnerabilities.
///
/// These functions must refuse to create the context and return this error instead.
pub const CRYPTO_ERRNO_KEY_NOT_SUPPORTED: CryptoErrno = 19;
/// A key is required for the chosen algorithm, but none was given.
pub const CRYPTO_ERRNO_KEY_REQUIRED: CryptoErrno = 20;
/// The provided authentication tag is invalid or incompatible with the current algorithm.
///
/// This error is returned by decryption functions and tag verification functions.
///
/// Unlike `verification_failed`, this error code is returned when the tag cannot possibly verify for any input.
pub const CRYPTO_ERRNO_INVALID_TAG: CryptoErrno = 21;
/// The requested operation is incompatible with the current scheme.
///
/// For example, the `symmetric_state_encrypt()` function cannot complete if the selected construction is a key derivation function.
/// This error code will be returned instead.
pub const CRYPTO_ERRNO_INVALID_OPERATION: CryptoErrno = 22;
/// A nonce is required.
///
/// Most encryption schemes require a nonce.
///
/// In the absence of a nonce, the WASI cryptography module can automatically generate one, if that can be done safely. The nonce can be retrieved later with the `symmetric_state_option_get()` function using the `nonce` parameter.
/// If automatically generating a nonce cannot be done safely, the module never falls back to an insecure option and requests an explicit nonce by throwing that error.
pub const CRYPTO_ERRNO_NONCE_REQUIRED: CryptoErrno = 23;
/// The provided nonce doesn't have a correct size for the given cipher.
pub const CRYPTO_ERRNO_INVALID_NONCE: CryptoErrno = 24;
/// The named option was not set.
///
/// The caller tried to read the value of an option that was not set.
/// This error is used to make the distinction between an empty option, and an option that was not set and left to its default value.
pub const CRYPTO_ERRNO_OPTION_NOT_SET: CryptoErrno = 25;
/// A key or key pair matching the requested identifier cannot be found using the supplied information.
///
/// This error is returned by a secrets manager via the `keypair_from_id()` function.
pub const CRYPTO_ERRNO_NOT_FOUND: CryptoErrno = 26;
/// The algorithm requires parameters that haven't been set.
///
/// Non-generic options are required and must be given by building an `options` set and giving that object to functions instantiating that algorithm.
pub const CRYPTO_ERRNO_PARAMETERS_MISSING: CryptoErrno = 27;
/// A requested computation is not done yet, and additional calls to the function are required.
///
/// Some functions, such as functions generating key pairs and password stretching functions, can take a long time to complete.
///
/// In order to avoid a host call to be blocked for too long, these functions can return prematurely, requiring additional calls with the same parameters until they complete.
pub const CRYPTO_ERRNO_IN_PROGRESS: CryptoErrno = 28;
/// Multiple keys have been provided, but they do not share the same type.
///
/// This error is returned when trying to build a key pair from a public key and a secret key that were created for different and incompatible algorithms.
pub const CRYPTO_ERRNO_INCOMPATIBLE_KEYS: CryptoErrno = 29;
/// A managed key or secret expired and cannot be used any more.
pub const CRYPTO_ERRNO_EXPIRED: CryptoErrno = 30;
pub type KeypairEncoding = u16;
/// Raw bytes.
pub const KEYPAIR_ENCODING_RAW: KeypairEncoding = 0;
/// PCSK8/DER encoding.
pub const KEYPAIR_ENCODING_PKCS8: KeypairEncoding = 1;
/// PEM encoding.
pub const KEYPAIR_ENCODING_PEM: KeypairEncoding = 2;
/// Implementation-defined encoding.
pub const KEYPAIR_ENCODING_LOCAL: KeypairEncoding = 3;
pub type PublickeyEncoding = u16;
/// Raw bytes.
pub const PUBLICKEY_ENCODING_RAW: PublickeyEncoding = 0;
/// PKCS8/DER encoding.
pub const PUBLICKEY_ENCODING_PKCS8: PublickeyEncoding = 1;
/// PEM encoding.
pub const PUBLICKEY_ENCODING_PEM: PublickeyEncoding = 2;
/// SEC encoding.
pub const PUBLICKEY_ENCODING_SEC: PublickeyEncoding = 3;
/// Compressed SEC encoding.
pub const PUBLICKEY_ENCODING_COMPRESSED_SEC: PublickeyEncoding = 4;
/// Implementation-defined encoding.
pub const PUBLICKEY_ENCODING_LOCAL: PublickeyEncoding = 5;
pub type SecretkeyEncoding = u16;
/// Raw bytes.
pub const SECRETKEY_ENCODING_RAW: SecretkeyEncoding = 0;
/// PKCS8/DER encoding.
pub const SECRETKEY_ENCODING_PKCS8: SecretkeyEncoding = 1;
/// PEM encoding.
pub const SECRETKEY_ENCODING_PEM: SecretkeyEncoding = 2;
/// SEC encoding.
pub const SECRETKEY_ENCODING_SEC: SecretkeyEncoding = 3;
/// Compressed SEC encoding.
pub const SECRETKEY_ENCODING_COMPRESSED_SEC: SecretkeyEncoding = 4;
/// Implementation-defined encoding.
pub const SECRETKEY_ENCODING_LOCAL: SecretkeyEncoding = 5;
pub type SignatureEncoding = u16;
/// Raw bytes.
pub const SIGNATURE_ENCODING_RAW: SignatureEncoding = 0;
/// DER encoding.
pub const SIGNATURE_ENCODING_DER: SignatureEncoding = 1;
pub type AlgorithmType = u16;
pub const ALGORITHM_TYPE_SIGNATURES: AlgorithmType = 0;
pub const ALGORITHM_TYPE_SYMMETRIC: AlgorithmType = 1;
pub const ALGORITHM_TYPE_KEY_EXCHANGE: AlgorithmType = 2;
pub type Version = u64;
/// Key doesn't support versioning.
pub const VERSION_UNSPECIFIED: Version = 18374686479671623680;
/// Use the latest version of a key.
pub const VERSION_LATEST: Version = 18374686479671623681;
/// Perform an operation over all versions of a key.
pub const VERSION_ALL: Version = 18374686479671623682;
pub type Size = usize;
pub type Timestamp = u64;
pub type ArrayOutput = u32;
pub type Options = u32;
pub type SecretsManager = u32;
pub type Keypair = u32;
pub type SignatureState = u32;
pub type Signature = u32;
pub type Publickey = u32;
pub type Secretkey = u32;
pub type SignatureVerificationState = u32;
pub type SymmetricState = u32;
pub type SymmetricKey = u32;
pub type SymmetricTag = u32;
pub type OptOptionsU = u8;
pub const OPT_OPTIONS_U_SOME: OptOptionsU = 0;
pub const OPT_OPTIONS_U_NONE: OptOptionsU = 1;
#[repr(C)]
#[derive(Copy, Clone)]
pub union OptOptionsUnion {
    pub some: Options,
    pub none: bool,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct OptOptions {
    pub tag: OptOptionsU,
    pub u: OptOptionsUnion,
}

pub type OptSymmetricKeyU = u8;
pub const OPT_SYMMETRIC_KEY_U_SOME: OptSymmetricKeyU = 0;
pub const OPT_SYMMETRIC_KEY_U_NONE: OptSymmetricKeyU = 1;
#[repr(C)]
#[derive(Copy, Clone)]
pub union OptSymmetricKeyUnion {
    pub some: SymmetricKey,
    pub none: bool,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct OptSymmetricKey {
    pub tag: OptSymmetricKeyU,
    pub u: OptSymmetricKeyUnion,
}

pub type SignatureKeypair = Keypair;
pub type SignaturePublickey = Publickey;
pub type SignatureSecretkey = Secretkey;
pub type KxKeypair = Keypair;
pub type KxPublickey = Publickey;
pub type KxSecretkey = Secretkey;
/// Create a new object to set non-default options.
///
/// Example usage:
///
/// ```rust
/// let options_handle = options_open(AlgorithmType::Symmetric)?;
/// options_set(options_handle, "context", context)?;
/// options_set_u64(options_handle, "threads", 4)?;
/// let state = symmetric_state_open("BLAKE3", None, Some(options_handle))?;
/// options_close(options_handle)?;
/// ```
pub unsafe fn options_open(algorithm_type: AlgorithmType) -> Result<Options> {
    let mut handle = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_common::options_open(algorithm_type, handle.as_mut_ptr());
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(handle.assume_init())
    }
}

/// Destroy an options object.
///
/// Objects are reference counted. It is safe to close an object immediately after the last function needing it is called.
pub unsafe fn options_close(handle: Options) -> Result<()> {
    let rc = wasi_ephemeral_crypto_common::options_close(handle);
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

/// Set or update an option.
///
/// This is used to set algorithm-specific parameters, but also to provide credentials for the secrets management facilities, if required.
///
/// This function may return `unsupported_option` if an option that doesn't exist for any implemented algorithms is specified.
pub unsafe fn options_set(
    handle: Options,
    name: &str,
    value: *const u8,
    value_len: Size,
) -> Result<()> {
    let rc = wasi_ephemeral_crypto_common::options_set(
        handle,
        name.as_ptr(),
        name.len(),
        value,
        value_len,
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

/// Set or update an integer option.
///
/// This is used to set algorithm-specific parameters.
///
/// This function may return `unsupported_option` if an option that doesn't exist for any implemented algorithms is specified.
pub unsafe fn options_set_u64(handle: Options, name: &str, value: u64) -> Result<()> {
    let rc =
        wasi_ephemeral_crypto_common::options_set_u64(handle, name.as_ptr(), name.len(), value);
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

/// Set or update a guest-allocated memory that the host can use or return data into.
///
/// This is for example used to set the scratch buffer required by memory-hard functions.
///
/// This function may return `unsupported_option` if an option that doesn't exist for any implemented algorithms is specified.
pub unsafe fn options_set_guest_buffer(
    handle: Options,
    name: &str,
    buffer: *mut u8,
    buffer_len: Size,
) -> Result<()> {
    let rc = wasi_ephemeral_crypto_common::options_set_guest_buffer(
        handle,
        name.as_ptr(),
        name.len(),
        buffer,
        buffer_len,
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

/// Return the length of an `array_output` object.
///
/// This allows a guest to allocate a buffer of the correct size in order to copy the output of a function returning this object type.
pub unsafe fn array_output_len(array_output: ArrayOutput) -> Result<Size> {
    let mut len = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_common::array_output_len(array_output, len.as_mut_ptr());
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(len.assume_init())
    }
}

/// Copy the content of an `array_output` object into an application-allocated buffer.
///
/// Multiple calls to that function can be made in order to consume the data in a streaming fashion, if necessary.
///
/// The function returns the number of bytes that were actually copied. `0` means that the end of the stream has been reached. The total size always matches the output of `array_output_len()`.
///
/// The handle is automatically closed after all the data has been consumed.
///
/// Example usage:
///
/// ```rust
/// let len = array_output_len(output_handle)?;
/// let mut out = vec![0u8; len];
/// array_output_pull(output_handle, &mut out)?;
/// ```
pub unsafe fn array_output_pull(
    array_output: ArrayOutput,
    buf: *mut u8,
    buf_len: Size,
) -> Result<Size> {
    let mut len = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_common::array_output_pull(
        array_output,
        buf,
        buf_len,
        len.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(len.assume_init())
    }
}

/// __(optional)__
/// Create a context to use a secrets manager.
///
/// The set of required and supported options is defined by the host.
///
/// The function returns the `unsupported_feature` error code if secrets management facilities are not supported by the host.
/// This is also an optional import, meaning that the function may not even exist.
pub unsafe fn secrets_manager_open(options: &OptOptions) -> Result<SecretsManager> {
    let mut handle = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_common::secrets_manager_open(options, handle.as_mut_ptr());
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(handle.assume_init())
    }
}

/// __(optional)__
/// Destroy a secrets manager context.
///
/// The function returns the `unsupported_feature` error code if secrets management facilities are not supported by the host.
/// This is also an optional import, meaning that the function may not even exist.
pub unsafe fn secrets_manager_close(secrets_manager: SecretsManager) -> Result<()> {
    let rc = wasi_ephemeral_crypto_common::secrets_manager_close(secrets_manager);
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

/// __(optional)__
/// Invalidate a managed key or key pair given an identifier and a version.
///
/// This asks the secrets manager to delete or revoke a stored key, a specific version of a key.
///
/// `key_version` can be set to a version number, to `version.latest` to invalidate the current version, or to `version.all` to invalidate all versions of a key.
///
/// The function returns `unsupported_feature` if this operation is not supported by the host, and `not_found` if the identifier and version don't match any existing key.
///
/// This is an optional import, meaning that the function may not even exist.
pub unsafe fn secrets_manager_invalidate(
    secrets_manager: SecretsManager,
    key_id: *const u8,
    key_id_len: Size,
    key_version: Version,
) -> Result<()> {
    let rc = wasi_ephemeral_crypto_common::secrets_manager_invalidate(
        secrets_manager,
        key_id,
        key_id_len,
        key_version,
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

pub mod wasi_ephemeral_crypto_common {
    use super::*;
    #[link(wasm_import_module = "wasi_ephemeral_crypto_common")]
    extern "C" {
        /// Create a new object to set non-default options.
        ///
        /// Example usage:
        ///
        /// ```rust
        /// let options_handle = options_open(AlgorithmType::Symmetric)?;
        /// options_set(options_handle, "context", context)?;
        /// options_set_u64(options_handle, "threads", 4)?;
        /// let state = symmetric_state_open("BLAKE3", None, Some(options_handle))?;
        /// options_close(options_handle)?;
        /// ```
        pub fn options_open(algorithm_type: AlgorithmType, handle: *mut Options) -> CryptoErrno;
        /// Destroy an options object.
        ///
        /// Objects are reference counted. It is safe to close an object immediately after the last function needing it is called.
        pub fn options_close(handle: Options) -> CryptoErrno;
        /// Set or update an option.
        ///
        /// This is used to set algorithm-specific parameters, but also to provide credentials for the secrets management facilities, if required.
        ///
        /// This function may return `unsupported_option` if an option that doesn't exist for any implemented algorithms is specified.
        pub fn options_set(
            handle: Options,
            name_ptr: *const u8,
            name_len: usize,
            value: *const u8,
            value_len: Size,
        ) -> CryptoErrno;
        /// Set or update an integer option.
        ///
        /// This is used to set algorithm-specific parameters.
        ///
        /// This function may return `unsupported_option` if an option that doesn't exist for any implemented algorithms is specified.
        pub fn options_set_u64(
            handle: Options,
            name_ptr: *const u8,
            name_len: usize,
            value: u64,
        ) -> CryptoErrno;
        /// Set or update a guest-allocated memory that the host can use or return data into.
        ///
        /// This is for example used to set the scratch buffer required by memory-hard functions.
        ///
        /// This function may return `unsupported_option` if an option that doesn't exist for any implemented algorithms is specified.
        pub fn options_set_guest_buffer(
            handle: Options,
            name_ptr: *const u8,
            name_len: usize,
            buffer: *mut u8,
            buffer_len: Size,
        ) -> CryptoErrno;
        /// Return the length of an `array_output` object.
        ///
        /// This allows a guest to allocate a buffer of the correct size in order to copy the output of a function returning this object type.
        pub fn array_output_len(array_output: ArrayOutput, len: *mut Size) -> CryptoErrno;
        /// Copy the content of an `array_output` object into an application-allocated buffer.
        ///
        /// Multiple calls to that function can be made in order to consume the data in a streaming fashion, if necessary.
        ///
        /// The function returns the number of bytes that were actually copied. `0` means that the end of the stream has been reached. The total size always matches the output of `array_output_len()`.
        ///
        /// The handle is automatically closed after all the data has been consumed.
        ///
        /// Example usage:
        ///
        /// ```rust
        /// let len = array_output_len(output_handle)?;
        /// let mut out = vec![0u8; len];
        /// array_output_pull(output_handle, &mut out)?;
        /// ```
        pub fn array_output_pull(
            array_output: ArrayOutput,
            buf: *mut u8,
            buf_len: Size,
            len: *mut Size,
        ) -> CryptoErrno;
        /// __(optional)__
        /// Create a context to use a secrets manager.
        ///
        /// The set of required and supported options is defined by the host.
        ///
        /// The function returns the `unsupported_feature` error code if secrets management facilities are not supported by the host.
        /// This is also an optional import, meaning that the function may not even exist.
        pub fn secrets_manager_open(
            options: *const OptOptions,
            handle: *mut SecretsManager,
        ) -> CryptoErrno;
        /// __(optional)__
        /// Destroy a secrets manager context.
        ///
        /// The function returns the `unsupported_feature` error code if secrets management facilities are not supported by the host.
        /// This is also an optional import, meaning that the function may not even exist.
        pub fn secrets_manager_close(secrets_manager: SecretsManager) -> CryptoErrno;
        /// __(optional)__
        /// Invalidate a managed key or key pair given an identifier and a version.
        ///
        /// This asks the secrets manager to delete or revoke a stored key, a specific version of a key.
        ///
        /// `key_version` can be set to a version number, to `version.latest` to invalidate the current version, or to `version.all` to invalidate all versions of a key.
        ///
        /// The function returns `unsupported_feature` if this operation is not supported by the host, and `not_found` if the identifier and version don't match any existing key.
        ///
        /// This is an optional import, meaning that the function may not even exist.
        pub fn secrets_manager_invalidate(
            secrets_manager: SecretsManager,
            key_id: *const u8,
            key_id_len: Size,
            key_version: Version,
        ) -> CryptoErrno;
    }
}
/// Generate a new key pair.
///
/// Internally, a key pair stores the supplied algorithm and optional parameters.
///
/// Trying to use that key pair with different parameters will throw an `invalid_key` error.
///
/// This function may return `$crypto_errno.unsupported_feature` if key generation is not supported by the host for the chosen algorithm.
///
/// The function may also return `unsupported_algorithm` if the algorithm is not supported by the host.
///
/// Finally, if generating that type of key pair is an expensive operation, the function may return `in_progress`.
/// In that case, the guest should retry with the same parameters until the function completes.
///
/// Example usage:
///
/// ```rust
/// let kp_handle = ctx.keypair_generate(AlgorithmType::Signatures, "RSA_PKCS1_2048_SHA256", None)?;
/// ```
pub unsafe fn keypair_generate(
    algorithm_type: AlgorithmType,
    algorithm: &str,
    options: &OptOptions,
) -> Result<Keypair> {
    let mut handle = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_asymmetric_common::keypair_generate(
        algorithm_type,
        algorithm.as_ptr(),
        algorithm.len(),
        options,
        handle.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(handle.assume_init())
    }
}

/// Import a key pair.
///
/// This function creates a `keypair` object from existing material.
///
/// It may return `unsupported_algorithm` if the encoding scheme is not supported, or `invalid_key` if the key cannot be decoded.
///
/// The function may also return `unsupported_algorithm` if the algorithm is not supported by the host.
///
/// Example usage:
///
/// ```rust
/// let kp_handle = ctx.keypair_import(AlgorithmType::Signatures, "RSA_PKCS1_2048_SHA256", KeypairEncoding::PKCS8)?;
/// ```
pub unsafe fn keypair_import(
    algorithm_type: AlgorithmType,
    algorithm: &str,
    encoded: *const u8,
    encoded_len: Size,
    encoding: KeypairEncoding,
) -> Result<Keypair> {
    let mut handle = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_asymmetric_common::keypair_import(
        algorithm_type,
        algorithm.as_ptr(),
        algorithm.len(),
        encoded,
        encoded_len,
        encoding,
        handle.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(handle.assume_init())
    }
}

/// __(optional)__
/// Generate a new managed key pair.
///
/// The key pair is generated and stored by the secrets management facilities.
///
/// It may be used through its identifier, but the host may not allow it to be exported.
///
/// The function returns the `unsupported_feature` error code if secrets management facilities are not supported by the host,
/// or `unsupported_algorithm` if a key cannot be created for the chosen algorithm.
///
/// The function may also return `unsupported_algorithm` if the algorithm is not supported by the host.
///
/// This is also an optional import, meaning that the function may not even exist.
pub unsafe fn keypair_generate_managed(
    secrets_manager: SecretsManager,
    algorithm_type: AlgorithmType,
    algorithm: &str,
    options: &OptOptions,
) -> Result<Keypair> {
    let mut handle = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_asymmetric_common::keypair_generate_managed(
        secrets_manager,
        algorithm_type,
        algorithm.as_ptr(),
        algorithm.len(),
        options,
        handle.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(handle.assume_init())
    }
}

/// __(optional)__
/// Store a key pair into the secrets manager.
///
/// On success, the function stores the key pair identifier into `$kp_id`,
/// into which up to `$kp_id_max_len` can be written.
///
/// The function returns `overflow` if the supplied buffer is too small.
pub unsafe fn keypair_store_managed(
    secrets_manager: SecretsManager,
    kp: Keypair,
    kp_id: *mut u8,
    kp_id_max_len: Size,
) -> Result<()> {
    let rc = wasi_ephemeral_crypto_asymmetric_common::keypair_store_managed(
        secrets_manager,
        kp,
        kp_id,
        kp_id_max_len,
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

/// __(optional)__
/// Replace a managed key pair.
///
/// This function crates a new version of a managed key pair, by replacing `$kp_old` with `$kp_new`.
///
/// It does several things:
///
/// - The key identifier for `$kp_new` is set to the one of `$kp_old`.
/// - A new, unique version identifier is assigned to `$kp_new`. This version will be equivalent to using `$version_latest` until the key is replaced.
/// - The `$kp_old` handle is closed.
///
/// Both keys must share the same algorithm and have compatible parameters. If this is not the case, `incompatible_keys` is returned.
///
/// The function may also return the `unsupported_feature` error code if secrets management facilities are not supported by the host,
/// or if keys cannot be rotated.
///
/// Finally, `prohibited_operation` can be returned if `$kp_new` wasn't created by the secrets manager, and the secrets manager prohibits imported keys.
///
/// If the operation succeeded, the new version is returned.
///
/// This is an optional import, meaning that the function may not even exist.
pub unsafe fn keypair_replace_managed(
    secrets_manager: SecretsManager,
    kp_old: Keypair,
    kp_new: Keypair,
) -> Result<Version> {
    let mut version = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_asymmetric_common::keypair_replace_managed(
        secrets_manager,
        kp_old,
        kp_new,
        version.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(version.assume_init())
    }
}

/// __(optional)__
/// Return the key pair identifier and version of a managed key pair.
///
/// If the key pair is not managed, `unsupported_feature` is returned instead.
///
/// This is an optional import, meaning that the function may not even exist.
pub unsafe fn keypair_id(
    kp: Keypair,
    kp_id: *mut u8,
    kp_id_max_len: Size,
) -> Result<(Size, Version)> {
    let mut kp_id_len = MaybeUninit::uninit();
    let mut version = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_asymmetric_common::keypair_id(
        kp,
        kp_id,
        kp_id_max_len,
        kp_id_len.as_mut_ptr(),
        version.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok((kp_id_len.assume_init(), version.assume_init()))
    }
}

/// __(optional)__
/// Return a managed key pair from a key identifier.
///
/// `kp_version` can be set to `version_latest` to retrieve the most recent version of a key pair.
///
/// If no key pair matching the provided information is found, `not_found` is returned instead.
///
/// This is an optional import, meaning that the function may not even exist.
/// ```
pub unsafe fn keypair_from_id(
    secrets_manager: SecretsManager,
    kp_id: *const u8,
    kp_id_len: Size,
    kp_version: Version,
) -> Result<Keypair> {
    let mut handle = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_asymmetric_common::keypair_from_id(
        secrets_manager,
        kp_id,
        kp_id_len,
        kp_version,
        handle.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(handle.assume_init())
    }
}

/// Create a key pair from a public key and a secret key.
pub unsafe fn keypair_from_pk_and_sk(
    publickey: Publickey,
    secretkey: Secretkey,
) -> Result<Keypair> {
    let mut handle = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_asymmetric_common::keypair_from_pk_and_sk(
        publickey,
        secretkey,
        handle.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(handle.assume_init())
    }
}

/// Export a key pair as the given encoding format.
///
/// May return `prohibited_operation` if this operation is denied or `unsupported_encoding` if the encoding is not supported.
pub unsafe fn keypair_export(kp: Keypair, encoding: KeypairEncoding) -> Result<ArrayOutput> {
    let mut encoded = MaybeUninit::uninit();
    let rc =
        wasi_ephemeral_crypto_asymmetric_common::keypair_export(kp, encoding, encoded.as_mut_ptr());
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(encoded.assume_init())
    }
}

/// Get the public key of a key pair.
pub unsafe fn keypair_publickey(kp: Keypair) -> Result<Publickey> {
    let mut pk = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_asymmetric_common::keypair_publickey(kp, pk.as_mut_ptr());
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(pk.assume_init())
    }
}

/// Get the secret key of a key pair.
pub unsafe fn keypair_secretkey(kp: Keypair) -> Result<Secretkey> {
    let mut sk = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_asymmetric_common::keypair_secretkey(kp, sk.as_mut_ptr());
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(sk.assume_init())
    }
}

/// Destroy a key pair.
///
/// The host will automatically wipe traces of the secret key from memory.
///
/// If this is a managed key, the key will not be removed from persistent storage, and can be reconstructed later using the key identifier.
pub unsafe fn keypair_close(kp: Keypair) -> Result<()> {
    let rc = wasi_ephemeral_crypto_asymmetric_common::keypair_close(kp);
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

/// Import a public key.
///
/// The function may return `unsupported_encoding` if importing from the given format is not implemented or incompatible with the key type.
///
/// It may also return `invalid_key` if the key doesn't appear to match the supplied algorithm.
///
/// Finally, the function may return `unsupported_algorithm` if the algorithm is not supported by the host.
///
/// Example usage:
///
/// ```rust
/// let pk_handle = ctx.publickey_import(AlgorithmType::Signatures, encoded, PublicKeyEncoding::Sec)?;
/// ```
pub unsafe fn publickey_import(
    algorithm_type: AlgorithmType,
    algorithm: &str,
    encoded: *const u8,
    encoded_len: Size,
    encoding: PublickeyEncoding,
) -> Result<Publickey> {
    let mut pk = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_asymmetric_common::publickey_import(
        algorithm_type,
        algorithm.as_ptr(),
        algorithm.len(),
        encoded,
        encoded_len,
        encoding,
        pk.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(pk.assume_init())
    }
}

/// Export a public key as the given encoding format.
///
/// May return `unsupported_encoding` if the encoding is not supported.
pub unsafe fn publickey_export(pk: Publickey, encoding: PublickeyEncoding) -> Result<ArrayOutput> {
    let mut encoded = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_asymmetric_common::publickey_export(
        pk,
        encoding,
        encoded.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(encoded.assume_init())
    }
}

/// Check that a public key is valid and in canonical form.
///
/// This function may perform stricter checks than those made during importation at the expense of additional CPU cycles.
///
/// The function returns `invalid_key` if the public key didn't pass the checks.
pub unsafe fn publickey_verify(pk: Publickey) -> Result<()> {
    let rc = wasi_ephemeral_crypto_asymmetric_common::publickey_verify(pk);
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

/// Compute the public key for a secret key.
pub unsafe fn publickey_from_secretkey(sk: Secretkey) -> Result<Publickey> {
    let mut pk = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_asymmetric_common::publickey_from_secretkey(sk, pk.as_mut_ptr());
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(pk.assume_init())
    }
}

/// Destroy a public key.
///
/// Objects are reference counted. It is safe to close an object immediately after the last function needing it is called.
pub unsafe fn publickey_close(pk: Publickey) -> Result<()> {
    let rc = wasi_ephemeral_crypto_asymmetric_common::publickey_close(pk);
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

/// Import a secret key.
///
/// The function may return `unsupported_encoding` if importing from the given format is not implemented or incompatible with the key type.
///
/// It may also return `invalid_key` if the key doesn't appear to match the supplied algorithm.
///
/// Finally, the function may return `unsupported_algorithm` if the algorithm is not supported by the host.
///
/// Example usage:
///
/// ```rust
/// let pk_handle = ctx.secretkey_import(AlgorithmType::KX, encoded, SecretKeyEncoding::Raw)?;
/// ```
pub unsafe fn secretkey_import(
    algorithm_type: AlgorithmType,
    algorithm: &str,
    encoded: *const u8,
    encoded_len: Size,
    encoding: SecretkeyEncoding,
) -> Result<Secretkey> {
    let mut sk = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_asymmetric_common::secretkey_import(
        algorithm_type,
        algorithm.as_ptr(),
        algorithm.len(),
        encoded,
        encoded_len,
        encoding,
        sk.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(sk.assume_init())
    }
}

/// Export a secret key as the given encoding format.
///
/// May return `unsupported_encoding` if the encoding is not supported.
pub unsafe fn secretkey_export(sk: Secretkey, encoding: SecretkeyEncoding) -> Result<ArrayOutput> {
    let mut encoded = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_asymmetric_common::secretkey_export(
        sk,
        encoding,
        encoded.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(encoded.assume_init())
    }
}

/// Destroy a secret key.
///
/// Objects are reference counted. It is safe to close an object immediately after the last function needing it is called.
pub unsafe fn secretkey_close(sk: Secretkey) -> Result<()> {
    let rc = wasi_ephemeral_crypto_asymmetric_common::secretkey_close(sk);
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

pub mod wasi_ephemeral_crypto_asymmetric_common {
    use super::*;
    #[link(wasm_import_module = "wasi_ephemeral_crypto_asymmetric_common")]
    extern "C" {
        /// Generate a new key pair.
        ///
        /// Internally, a key pair stores the supplied algorithm and optional parameters.
        ///
        /// Trying to use that key pair with different parameters will throw an `invalid_key` error.
        ///
        /// This function may return `$crypto_errno.unsupported_feature` if key generation is not supported by the host for the chosen algorithm.
        ///
        /// The function may also return `unsupported_algorithm` if the algorithm is not supported by the host.
        ///
        /// Finally, if generating that type of key pair is an expensive operation, the function may return `in_progress`.
        /// In that case, the guest should retry with the same parameters until the function completes.
        ///
        /// Example usage:
        ///
        /// ```rust
        /// let kp_handle = ctx.keypair_generate(AlgorithmType::Signatures, "RSA_PKCS1_2048_SHA256", None)?;
        /// ```
        pub fn keypair_generate(
            algorithm_type: AlgorithmType,
            algorithm_ptr: *const u8,
            algorithm_len: usize,
            options: *const OptOptions,
            handle: *mut Keypair,
        ) -> CryptoErrno;
        /// Import a key pair.
        ///
        /// This function creates a `keypair` object from existing material.
        ///
        /// It may return `unsupported_algorithm` if the encoding scheme is not supported, or `invalid_key` if the key cannot be decoded.
        ///
        /// The function may also return `unsupported_algorithm` if the algorithm is not supported by the host.
        ///
        /// Example usage:
        ///
        /// ```rust
        /// let kp_handle = ctx.keypair_import(AlgorithmType::Signatures, "RSA_PKCS1_2048_SHA256", KeypairEncoding::PKCS8)?;
        /// ```
        pub fn keypair_import(
            algorithm_type: AlgorithmType,
            algorithm_ptr: *const u8,
            algorithm_len: usize,
            encoded: *const u8,
            encoded_len: Size,
            encoding: KeypairEncoding,
            handle: *mut Keypair,
        ) -> CryptoErrno;
        /// __(optional)__
        /// Generate a new managed key pair.
        ///
        /// The key pair is generated and stored by the secrets management facilities.
        ///
        /// It may be used through its identifier, but the host may not allow it to be exported.
        ///
        /// The function returns the `unsupported_feature` error code if secrets management facilities are not supported by the host,
        /// or `unsupported_algorithm` if a key cannot be created for the chosen algorithm.
        ///
        /// The function may also return `unsupported_algorithm` if the algorithm is not supported by the host.
        ///
        /// This is also an optional import, meaning that the function may not even exist.
        pub fn keypair_generate_managed(
            secrets_manager: SecretsManager,
            algorithm_type: AlgorithmType,
            algorithm_ptr: *const u8,
            algorithm_len: usize,
            options: *const OptOptions,
            handle: *mut Keypair,
        ) -> CryptoErrno;
        /// __(optional)__
        /// Store a key pair into the secrets manager.
        ///
        /// On success, the function stores the key pair identifier into `$kp_id`,
        /// into which up to `$kp_id_max_len` can be written.
        ///
        /// The function returns `overflow` if the supplied buffer is too small.
        pub fn keypair_store_managed(
            secrets_manager: SecretsManager,
            kp: Keypair,
            kp_id: *mut u8,
            kp_id_max_len: Size,
        ) -> CryptoErrno;
        /// __(optional)__
        /// Replace a managed key pair.
        ///
        /// This function crates a new version of a managed key pair, by replacing `$kp_old` with `$kp_new`.
        ///
        /// It does several things:
        ///
        /// - The key identifier for `$kp_new` is set to the one of `$kp_old`.
        /// - A new, unique version identifier is assigned to `$kp_new`. This version will be equivalent to using `$version_latest` until the key is replaced.
        /// - The `$kp_old` handle is closed.
        ///
        /// Both keys must share the same algorithm and have compatible parameters. If this is not the case, `incompatible_keys` is returned.
        ///
        /// The function may also return the `unsupported_feature` error code if secrets management facilities are not supported by the host,
        /// or if keys cannot be rotated.
        ///
        /// Finally, `prohibited_operation` can be returned if `$kp_new` wasn't created by the secrets manager, and the secrets manager prohibits imported keys.
        ///
        /// If the operation succeeded, the new version is returned.
        ///
        /// This is an optional import, meaning that the function may not even exist.
        pub fn keypair_replace_managed(
            secrets_manager: SecretsManager,
            kp_old: Keypair,
            kp_new: Keypair,
            version: *mut Version,
        ) -> CryptoErrno;
        /// __(optional)__
        /// Return the key pair identifier and version of a managed key pair.
        ///
        /// If the key pair is not managed, `unsupported_feature` is returned instead.
        ///
        /// This is an optional import, meaning that the function may not even exist.
        pub fn keypair_id(
            kp: Keypair,
            kp_id: *mut u8,
            kp_id_max_len: Size,
            kp_id_len: *mut Size,
            version: *mut Version,
        ) -> CryptoErrno;
        /// __(optional)__
        /// Return a managed key pair from a key identifier.
        ///
        /// `kp_version` can be set to `version_latest` to retrieve the most recent version of a key pair.
        ///
        /// If no key pair matching the provided information is found, `not_found` is returned instead.
        ///
        /// This is an optional import, meaning that the function may not even exist.
        /// ```
        pub fn keypair_from_id(
            secrets_manager: SecretsManager,
            kp_id: *const u8,
            kp_id_len: Size,
            kp_version: Version,
            handle: *mut Keypair,
        ) -> CryptoErrno;
        /// Create a key pair from a public key and a secret key.
        pub fn keypair_from_pk_and_sk(
            publickey: Publickey,
            secretkey: Secretkey,
            handle: *mut Keypair,
        ) -> CryptoErrno;
        /// Export a key pair as the given encoding format.
        ///
        /// May return `prohibited_operation` if this operation is denied or `unsupported_encoding` if the encoding is not supported.
        pub fn keypair_export(
            kp: Keypair,
            encoding: KeypairEncoding,
            encoded: *mut ArrayOutput,
        ) -> CryptoErrno;
        /// Get the public key of a key pair.
        pub fn keypair_publickey(kp: Keypair, pk: *mut Publickey) -> CryptoErrno;
        /// Get the secret key of a key pair.
        pub fn keypair_secretkey(kp: Keypair, sk: *mut Secretkey) -> CryptoErrno;
        /// Destroy a key pair.
        ///
        /// The host will automatically wipe traces of the secret key from memory.
        ///
        /// If this is a managed key, the key will not be removed from persistent storage, and can be reconstructed later using the key identifier.
        pub fn keypair_close(kp: Keypair) -> CryptoErrno;
        /// Import a public key.
        ///
        /// The function may return `unsupported_encoding` if importing from the given format is not implemented or incompatible with the key type.
        ///
        /// It may also return `invalid_key` if the key doesn't appear to match the supplied algorithm.
        ///
        /// Finally, the function may return `unsupported_algorithm` if the algorithm is not supported by the host.
        ///
        /// Example usage:
        ///
        /// ```rust
        /// let pk_handle = ctx.publickey_import(AlgorithmType::Signatures, encoded, PublicKeyEncoding::Sec)?;
        /// ```
        pub fn publickey_import(
            algorithm_type: AlgorithmType,
            algorithm_ptr: *const u8,
            algorithm_len: usize,
            encoded: *const u8,
            encoded_len: Size,
            encoding: PublickeyEncoding,
            pk: *mut Publickey,
        ) -> CryptoErrno;
        /// Export a public key as the given encoding format.
        ///
        /// May return `unsupported_encoding` if the encoding is not supported.
        pub fn publickey_export(
            pk: Publickey,
            encoding: PublickeyEncoding,
            encoded: *mut ArrayOutput,
        ) -> CryptoErrno;
        /// Check that a public key is valid and in canonical form.
        ///
        /// This function may perform stricter checks than those made during importation at the expense of additional CPU cycles.
        ///
        /// The function returns `invalid_key` if the public key didn't pass the checks.
        pub fn publickey_verify(pk: Publickey) -> CryptoErrno;
        /// Compute the public key for a secret key.
        pub fn publickey_from_secretkey(sk: Secretkey, pk: *mut Publickey) -> CryptoErrno;
        /// Destroy a public key.
        ///
        /// Objects are reference counted. It is safe to close an object immediately after the last function needing it is called.
        pub fn publickey_close(pk: Publickey) -> CryptoErrno;
        /// Import a secret key.
        ///
        /// The function may return `unsupported_encoding` if importing from the given format is not implemented or incompatible with the key type.
        ///
        /// It may also return `invalid_key` if the key doesn't appear to match the supplied algorithm.
        ///
        /// Finally, the function may return `unsupported_algorithm` if the algorithm is not supported by the host.
        ///
        /// Example usage:
        ///
        /// ```rust
        /// let pk_handle = ctx.secretkey_import(AlgorithmType::KX, encoded, SecretKeyEncoding::Raw)?;
        /// ```
        pub fn secretkey_import(
            algorithm_type: AlgorithmType,
            algorithm_ptr: *const u8,
            algorithm_len: usize,
            encoded: *const u8,
            encoded_len: Size,
            encoding: SecretkeyEncoding,
            sk: *mut Secretkey,
        ) -> CryptoErrno;
        /// Export a secret key as the given encoding format.
        ///
        /// May return `unsupported_encoding` if the encoding is not supported.
        pub fn secretkey_export(
            sk: Secretkey,
            encoding: SecretkeyEncoding,
            encoded: *mut ArrayOutput,
        ) -> CryptoErrno;
        /// Destroy a secret key.
        ///
        /// Objects are reference counted. It is safe to close an object immediately after the last function needing it is called.
        pub fn secretkey_close(sk: Secretkey) -> CryptoErrno;
    }
}
/// Export a signature.
///
/// This function exports a signature object using the specified encoding.
///
/// May return `unsupported_encoding` if the signature cannot be encoded into the given format.
pub unsafe fn signature_export(
    signature: Signature,
    encoding: SignatureEncoding,
) -> Result<ArrayOutput> {
    let mut encoded = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_signatures::signature_export(
        signature,
        encoding,
        encoded.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(encoded.assume_init())
    }
}

/// Create a signature object.
///
/// This object can be used along with a public key to verify an existing signature.
///
/// It may return `invalid_signature` if the signature is invalid or incompatible with the specified algorithm, as well as `unsupported_encoding` if the encoding is not compatible with the signature type.
///
/// The function may also return `unsupported_algorithm` if the algorithm is not supported by the host.
///
/// Example usage:
///
/// ```rust
/// let signature_handle = ctx.signature_import("ECDSA_P256_SHA256", SignatureEncoding::DER, encoded)?;
/// ```
pub unsafe fn signature_import(
    algorithm: &str,
    encoded: *const u8,
    encoded_len: Size,
    encoding: SignatureEncoding,
) -> Result<Signature> {
    let mut signature = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_signatures::signature_import(
        algorithm.as_ptr(),
        algorithm.len(),
        encoded,
        encoded_len,
        encoding,
        signature.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(signature.assume_init())
    }
}

/// Create a new state to collect data to compute a signature on.
///
/// This function allows data to be signed to be supplied in a streaming fashion.
///
/// The state is not closed and can be used after a signature has been computed, allowing incremental updates by calling `signature_state_update()` again afterwards.
///
/// Example usage - signature creation
///
/// ```rust
/// let kp_handle = ctx.keypair_import(AlgorithmType::Signatures, "Ed25519ph", keypair, KeypairEncoding::Raw)?;
/// let state_handle = ctx.signature_state_open(kp_handle)?;
/// ctx.signature_state_update(state_handle, b"message part 1")?;
/// ctx.signature_state_update(state_handle, b"message part 2")?;
/// let sig_handle = ctx.signature_state_sign(state_handle)?;
/// let raw_sig = ctx.signature_export(sig_handle, SignatureEncoding::Raw)?;
/// ```
pub unsafe fn signature_state_open(kp: SignatureKeypair) -> Result<SignatureState> {
    let mut state = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_signatures::signature_state_open(kp, state.as_mut_ptr());
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(state.assume_init())
    }
}

/// Absorb data into the signature state.
///
/// This function may return `unsupported_feature` is the selected algorithm doesn't support incremental updates.
pub unsafe fn signature_state_update(
    state: SignatureState,
    input: *const u8,
    input_len: Size,
) -> Result<()> {
    let rc = wasi_ephemeral_crypto_signatures::signature_state_update(state, input, input_len);
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

/// Compute a signature for all the data collected up to that point.
///
/// The function can be called multiple times for incremental signing.
pub unsafe fn signature_state_sign(state: SignatureState) -> Result<ArrayOutput> {
    let mut signature = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_signatures::signature_state_sign(state, signature.as_mut_ptr());
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(signature.assume_init())
    }
}

/// Destroy a signature state.
///
/// Objects are reference counted. It is safe to close an object immediately after the last function needing it is called.
///
/// Note that closing a signature state doesn't close or invalidate the key pair object, that be reused for further signatures.
pub unsafe fn signature_state_close(state: SignatureState) -> Result<()> {
    let rc = wasi_ephemeral_crypto_signatures::signature_state_close(state);
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

/// Create a new state to collect data to verify a signature on.
///
/// This is the verification counterpart of `signature_state`.
///
/// Data can be injected using `signature_verification_state_update()`, and the state is not closed after a verification, allowing incremental verification.
///
/// Example usage - signature verification:
///
/// ```rust
/// let pk_handle = ctx.publickey_import(AlgorithmType::Signatures, "ECDSA_P256_SHA256", encoded_pk, PublicKeyEncoding::CompressedSec)?;
/// let signature_handle = ctx.signature_import(AlgorithmType::Signatures, "ECDSA_P256_SHA256", encoded_sig, PublicKeyEncoding::Der)?;
/// let state_handle = ctx.signature_verification_state_open(pk_handle)?;
/// ctx.signature_verification_state_update(state_handle, "message")?;
/// ctx.signature_verification_state_verify(signature_handle)?;
/// ```
pub unsafe fn signature_verification_state_open(
    kp: SignaturePublickey,
) -> Result<SignatureVerificationState> {
    let mut state = MaybeUninit::uninit();
    let rc =
        wasi_ephemeral_crypto_signatures::signature_verification_state_open(kp, state.as_mut_ptr());
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(state.assume_init())
    }
}

/// Absorb data into the signature verification state.
///
/// This function may return `unsupported_feature` is the selected algorithm doesn't support incremental updates.
pub unsafe fn signature_verification_state_update(
    state: SignatureVerificationState,
    input: *const u8,
    input_len: Size,
) -> Result<()> {
    let rc = wasi_ephemeral_crypto_signatures::signature_verification_state_update(
        state, input, input_len,
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

/// Check that the given signature is verifies for the data collected up to that point point.
///
/// The state is not closed and can absorb more data to allow for incremental verification.
///
/// The function returns `invalid_signature` if the signature doesn't appear to be valid.
pub unsafe fn signature_verification_state_verify(
    state: SignatureVerificationState,
    signature: Signature,
) -> Result<()> {
    let rc =
        wasi_ephemeral_crypto_signatures::signature_verification_state_verify(state, signature);
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

/// Destroy a signature verification state.
///
/// Objects are reference counted. It is safe to close an object immediately after the last function needing it is called.
///
/// Note that closing a signature state doesn't close or invalidate the public key object, that be reused for further verifications.
pub unsafe fn signature_verification_state_close(state: SignatureVerificationState) -> Result<()> {
    let rc = wasi_ephemeral_crypto_signatures::signature_verification_state_close(state);
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

/// Destroy a signature.
///
/// Objects are reference counted. It is safe to close an object immediately after the last function needing it is called.
pub unsafe fn signature_close(signature: Signature) -> Result<()> {
    let rc = wasi_ephemeral_crypto_signatures::signature_close(signature);
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

pub mod wasi_ephemeral_crypto_signatures {
    use super::*;
    #[link(wasm_import_module = "wasi_ephemeral_crypto_signatures")]
    extern "C" {
        /// Export a signature.
        ///
        /// This function exports a signature object using the specified encoding.
        ///
        /// May return `unsupported_encoding` if the signature cannot be encoded into the given format.
        pub fn signature_export(
            signature: Signature,
            encoding: SignatureEncoding,
            encoded: *mut ArrayOutput,
        ) -> CryptoErrno;
        /// Create a signature object.
        ///
        /// This object can be used along with a public key to verify an existing signature.
        ///
        /// It may return `invalid_signature` if the signature is invalid or incompatible with the specified algorithm, as well as `unsupported_encoding` if the encoding is not compatible with the signature type.
        ///
        /// The function may also return `unsupported_algorithm` if the algorithm is not supported by the host.
        ///
        /// Example usage:
        ///
        /// ```rust
        /// let signature_handle = ctx.signature_import("ECDSA_P256_SHA256", SignatureEncoding::DER, encoded)?;
        /// ```
        pub fn signature_import(
            algorithm_ptr: *const u8,
            algorithm_len: usize,
            encoded: *const u8,
            encoded_len: Size,
            encoding: SignatureEncoding,
            signature: *mut Signature,
        ) -> CryptoErrno;
        /// Create a new state to collect data to compute a signature on.
        ///
        /// This function allows data to be signed to be supplied in a streaming fashion.
        ///
        /// The state is not closed and can be used after a signature has been computed, allowing incremental updates by calling `signature_state_update()` again afterwards.
        ///
        /// Example usage - signature creation
        ///
        /// ```rust
        /// let kp_handle = ctx.keypair_import(AlgorithmType::Signatures, "Ed25519ph", keypair, KeypairEncoding::Raw)?;
        /// let state_handle = ctx.signature_state_open(kp_handle)?;
        /// ctx.signature_state_update(state_handle, b"message part 1")?;
        /// ctx.signature_state_update(state_handle, b"message part 2")?;
        /// let sig_handle = ctx.signature_state_sign(state_handle)?;
        /// let raw_sig = ctx.signature_export(sig_handle, SignatureEncoding::Raw)?;
        /// ```
        pub fn signature_state_open(
            kp: SignatureKeypair,
            state: *mut SignatureState,
        ) -> CryptoErrno;
        /// Absorb data into the signature state.
        ///
        /// This function may return `unsupported_feature` is the selected algorithm doesn't support incremental updates.
        pub fn signature_state_update(
            state: SignatureState,
            input: *const u8,
            input_len: Size,
        ) -> CryptoErrno;
        /// Compute a signature for all the data collected up to that point.
        ///
        /// The function can be called multiple times for incremental signing.
        pub fn signature_state_sign(
            state: SignatureState,
            signature: *mut ArrayOutput,
        ) -> CryptoErrno;
        /// Destroy a signature state.
        ///
        /// Objects are reference counted. It is safe to close an object immediately after the last function needing it is called.
        ///
        /// Note that closing a signature state doesn't close or invalidate the key pair object, that be reused for further signatures.
        pub fn signature_state_close(state: SignatureState) -> CryptoErrno;
        /// Create a new state to collect data to verify a signature on.
        ///
        /// This is the verification counterpart of `signature_state`.
        ///
        /// Data can be injected using `signature_verification_state_update()`, and the state is not closed after a verification, allowing incremental verification.
        ///
        /// Example usage - signature verification:
        ///
        /// ```rust
        /// let pk_handle = ctx.publickey_import(AlgorithmType::Signatures, "ECDSA_P256_SHA256", encoded_pk, PublicKeyEncoding::CompressedSec)?;
        /// let signature_handle = ctx.signature_import(AlgorithmType::Signatures, "ECDSA_P256_SHA256", encoded_sig, PublicKeyEncoding::Der)?;
        /// let state_handle = ctx.signature_verification_state_open(pk_handle)?;
        /// ctx.signature_verification_state_update(state_handle, "message")?;
        /// ctx.signature_verification_state_verify(signature_handle)?;
        /// ```
        pub fn signature_verification_state_open(
            kp: SignaturePublickey,
            state: *mut SignatureVerificationState,
        ) -> CryptoErrno;
        /// Absorb data into the signature verification state.
        ///
        /// This function may return `unsupported_feature` is the selected algorithm doesn't support incremental updates.
        pub fn signature_verification_state_update(
            state: SignatureVerificationState,
            input: *const u8,
            input_len: Size,
        ) -> CryptoErrno;
        /// Check that the given signature is verifies for the data collected up to that point point.
        ///
        /// The state is not closed and can absorb more data to allow for incremental verification.
        ///
        /// The function returns `invalid_signature` if the signature doesn't appear to be valid.
        pub fn signature_verification_state_verify(
            state: SignatureVerificationState,
            signature: Signature,
        ) -> CryptoErrno;
        /// Destroy a signature verification state.
        ///
        /// Objects are reference counted. It is safe to close an object immediately after the last function needing it is called.
        ///
        /// Note that closing a signature state doesn't close or invalidate the public key object, that be reused for further verifications.
        pub fn signature_verification_state_close(state: SignatureVerificationState)
            -> CryptoErrno;
        /// Destroy a signature.
        ///
        /// Objects are reference counted. It is safe to close an object immediately after the last function needing it is called.
        pub fn signature_close(signature: Signature) -> CryptoErrno;
    }
}
/// Generate a new symmetric key for a given algorithm.
///
/// `options` can be `None` to use the default parameters, or an algoritm-specific set of parameters to override.
///
/// This function may return `unsupported_feature` if key generation is not supported by the host for the chosen algorithm, or `unsupported_algorithm` if the algorithm is not supported by the host.
pub unsafe fn symmetric_key_generate(
    algorithm: &str,
    options: &OptOptions,
) -> Result<SymmetricKey> {
    let mut handle = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_key_generate(
        algorithm.as_ptr(),
        algorithm.len(),
        options,
        handle.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(handle.assume_init())
    }
}

/// Create a symmetric key from raw material.
///
/// The algorithm is internally stored along with the key, and trying to use the key with an operation expecting a different algorithm will return `invalid_key`.
///
/// The function may also return `unsupported_algorithm` if the algorithm is not supported by the host.
pub unsafe fn symmetric_key_import(
    algorithm: &str,
    raw: *const u8,
    raw_len: Size,
) -> Result<SymmetricKey> {
    let mut handle = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_key_import(
        algorithm.as_ptr(),
        algorithm.len(),
        raw,
        raw_len,
        handle.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(handle.assume_init())
    }
}

/// Export a symmetric key as raw material.
///
/// This is mainly useful to export a managed key.
///
/// May return `prohibited_operation` if this operation is denied.
pub unsafe fn symmetric_key_export(symmetric_key: SymmetricKey) -> Result<ArrayOutput> {
    let mut encoded = MaybeUninit::uninit();
    let rc =
        wasi_ephemeral_crypto_symmetric::symmetric_key_export(symmetric_key, encoded.as_mut_ptr());
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(encoded.assume_init())
    }
}

/// Destroy a symmetric key.
///
/// Objects are reference counted. It is safe to close an object immediately after the last function needing it is called.
pub unsafe fn symmetric_key_close(symmetric_key: SymmetricKey) -> Result<()> {
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_key_close(symmetric_key);
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

/// __(optional)__
/// Generate a new managed symmetric key.
///
/// The key is generated and stored by the secrets management facilities.
///
/// It may be used through its identifier, but the host may not allow it to be exported.
///
/// The function returns the `unsupported_feature` error code if secrets management facilities are not supported by the host,
/// or `unsupported_algorithm` if a key cannot be created for the chosen algorithm.
///
/// The function may also return `unsupported_algorithm` if the algorithm is not supported by the host.
///
/// This is also an optional import, meaning that the function may not even exist.
pub unsafe fn symmetric_key_generate_managed(
    secrets_manager: SecretsManager,
    algorithm: &str,
    options: &OptOptions,
) -> Result<SymmetricKey> {
    let mut handle = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_key_generate_managed(
        secrets_manager,
        algorithm.as_ptr(),
        algorithm.len(),
        options,
        handle.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(handle.assume_init())
    }
}

/// __(optional)__
/// Store a symmetric key into the secrets manager.
///
/// On success, the function stores the key identifier into `$symmetric_key_id`,
/// into which up to `$symmetric_key_id_max_len` can be written.
///
/// The function returns `overflow` if the supplied buffer is too small.
pub unsafe fn symmetric_key_store_managed(
    secrets_manager: SecretsManager,
    symmetric_key: SymmetricKey,
    symmetric_key_id: *mut u8,
    symmetric_key_id_max_len: Size,
) -> Result<()> {
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_key_store_managed(
        secrets_manager,
        symmetric_key,
        symmetric_key_id,
        symmetric_key_id_max_len,
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

/// __(optional)__
/// Replace a managed symmetric key.
///
/// This function crates a new version of a managed symmetric key, by replacing `$kp_old` with `$kp_new`.
///
/// It does several things:
///
/// - The key identifier for `$symmetric_key_new` is set to the one of `$symmetric_key_old`.
/// - A new, unique version identifier is assigned to `$kp_new`. This version will be equivalent to using `$version_latest` until the key is replaced.
/// - The `$symmetric_key_old` handle is closed.
///
/// Both keys must share the same algorithm and have compatible parameters. If this is not the case, `incompatible_keys` is returned.
///
/// The function may also return the `unsupported_feature` error code if secrets management facilities are not supported by the host,
/// or if keys cannot be rotated.
///
/// Finally, `prohibited_operation` can be returned if `$symmetric_key_new` wasn't created by the secrets manager, and the secrets manager prohibits imported keys.
///
/// If the operation succeeded, the new version is returned.
///
/// This is an optional import, meaning that the function may not even exist.
pub unsafe fn symmetric_key_replace_managed(
    secrets_manager: SecretsManager,
    symmetric_key_old: SymmetricKey,
    symmetric_key_new: SymmetricKey,
) -> Result<Version> {
    let mut version = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_key_replace_managed(
        secrets_manager,
        symmetric_key_old,
        symmetric_key_new,
        version.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(version.assume_init())
    }
}

/// __(optional)__
/// Return the key identifier and version of a managed symmetric key.
///
/// If the key is not managed, `unsupported_feature` is returned instead.
///
/// This is an optional import, meaning that the function may not even exist.
pub unsafe fn symmetric_key_id(
    symmetric_key: SymmetricKey,
    symmetric_key_id: *mut u8,
    symmetric_key_id_max_len: Size,
) -> Result<(Size, Version)> {
    let mut symmetric_key_id_len = MaybeUninit::uninit();
    let mut version = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_key_id(
        symmetric_key,
        symmetric_key_id,
        symmetric_key_id_max_len,
        symmetric_key_id_len.as_mut_ptr(),
        version.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok((symmetric_key_id_len.assume_init(), version.assume_init()))
    }
}

/// __(optional)__
/// Return a managed symmetric key from a key identifier.
///
/// `kp_version` can be set to `version_latest` to retrieve the most recent version of a symmetric key.
///
/// If no key matching the provided information is found, `not_found` is returned instead.
///
/// This is an optional import, meaning that the function may not even exist.
pub unsafe fn symmetric_key_from_id(
    secrets_manager: SecretsManager,
    symmetric_key_id: *const u8,
    symmetric_key_id_len: Size,
    symmetric_key_version: Version,
) -> Result<SymmetricKey> {
    let mut handle = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_key_from_id(
        secrets_manager,
        symmetric_key_id,
        symmetric_key_id_len,
        symmetric_key_version,
        handle.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(handle.assume_init())
    }
}

/// Create a new state to aborb and produce data using symmetric operations.
///
/// The state remains valid after every operation in order to support incremental updates.
///
/// The function has two optional parameters: a key and an options set.
///
/// It will fail with a `key_not_supported` error code if a key was provided but the chosen algorithm doesn't natively support keying.
///
/// On the other hand, if a key is required, but was not provided, a `key_required` error will be thrown.
///
/// Some algorithms may require additional parameters. They have to be supplied as an options set:
///
/// ```rust
/// let options_handle = ctx.options_open()?;
/// ctx.options_set("context", b"My application")?;
/// ctx.options_set_u64("fanout", 16)?;
/// let state_handle = ctx.symmetric_state_open("BLAKE2b-512", None, Some(options_handle))?;
/// ```
///
/// If some parameters are mandatory but were not set, the `parameters_missing` error code will be returned.
///
/// A notable exception is the `nonce` parameter, that is common to most AEAD constructions.
///
/// If a nonce is required but was not supplied:
///
/// - If it is safe to do so, the host will automatically generate a nonce. This is true for nonces that are large enough to be randomly generated, or if the host is able to maintain a global counter.
/// - If not, the function will fail and return the dedicated `nonce_required` error code.
///
/// A nonce that was automatically generated can be retrieved after the function returns with `symmetric_state_get(state_handle, "nonce")`.
///
/// **Sample usage patterns:**
///
/// - **Hashing**
///
/// ```rust
/// let mut out = [0u8; 64];
/// let state_handle = ctx.symmetric_state_open("SHAKE-128", None, None)?;
/// ctx.symmetric_state_absorb(state_handle, b"data")?;
/// ctx.symmetric_state_absorb(state_handle, b"more_data")?;
/// ctx.symmetric_state_squeeze(state_handle, &mut out)?;
/// ```
///
/// - **MAC**
///
/// ```rust
/// let mut raw_tag = [0u8; 64];
/// let key_handle = ctx.symmetric_key_import("HMAC/SHA-512", b"key")?;
/// let state_handle = ctx.symmetric_state_open("HMAC/SHA-512", Some(key_handle), None)?;
/// ctx.symmetric_state_absorb(state_handle, b"data")?;
/// ctx.symmetric_state_absorb(state_handle, b"more_data")?;
/// let computed_tag_handle = ctx.symmetric_state_squeeze_tag(state_handle)?;
/// ctx.symmetric_tag_pull(computed_tag_handle, &mut raw_tag)?;
/// ```
///
/// Verification:
///
/// ```rust
/// let state_handle = ctx.symmetric_state_open("HMAC/SHA-512", Some(key_handle), None)?;
/// ctx.symmetric_state_absorb(state_handle, b"data")?;
/// ctx.symmetric_state_absorb(state_handle, b"more_data")?;
/// let computed_tag_handle = ctx.symmetric_state_squeeze_tag(state_handle)?;
/// ctx.symmetric_tag_verify(computed_tag_handle, expected_raw_tag)?;
/// ```
///
/// - **Tuple hashing**
///
/// ```rust
/// let mut out = [0u8; 64];
/// let state_handle = ctx.symmetric_state_open("TupleHashXOF256", None, None)?;
/// ctx.symmetric_state_absorb(state_handle, b"value 1")?;
/// ctx.symmetric_state_absorb(state_handle, b"value 2")?;
/// ctx.symmetric_state_absorb(state_handle, b"value 3")?;
/// ctx.symmetric_state_squeeze(state_handle, &mut out)?;
/// ```
/// Unlike MACs and regular hash functions, inputs are domain separated instead of being concatenated.
///
/// - **Key derivation using extract-and-expand**
///
/// Extract:
///
/// ```rust
/// let mut prk = vec![0u8; 64];
/// let key_handle = ctx.symmetric_key_import("HKDF-EXTRACT/SHA-512", b"key")?;
/// let state_handle = ctx.symmetric_state_open("HKDF-EXTRACT/SHA-512", Some(key_handle), None)?;
/// ctx.symmetric_state_absorb(state_handle, b"salt")?;
/// let prk_handle = ctx.symmetric_state_squeeze_key(state_handle, "HKDF-EXPAND/SHA-512")?;
/// ```
///
/// Expand:
///
/// ```rust
/// let mut subkey = vec![0u8; 32];
/// let state_handle = ctx.symmetric_state_open("HKDF-EXPAND/SHA-512", Some(prk_handle), None)?;
/// ctx.symmetric_state_absorb(state_handle, b"info")?;
/// ctx.symmetric_state_squeeze(state_handle, &mut subkey)?;
/// ```
///
/// - **Key derivation using a XOF**
///
/// ```rust
/// let mut subkey1 = vec![0u8; 32];
/// let mut subkey2 = vec![0u8; 32];
/// let key_handle = ctx.symmetric_key_import("BLAKE3", b"key")?;
/// let state_handle = ctx.symmetric_state_open("BLAKE3", Some(key_handle), None)?;
/// ctx.symmetric_absorb(state_handle, b"context")?;
/// ctx.squeeze(state_handle, &mut subkey1)?;
/// ctx.squeeze(state_handle, &mut subkey2)?;
/// ```
///
/// - **Password hashing**
///
/// ```rust
/// let mut memory = vec![0u8; 1_000_000_000];
/// let options_handle = ctx.symmetric_options_open()?;
/// ctx.symmetric_options_set_guest_buffer(options_handle, "memory", &mut memory)?;
/// ctx.symmetric_options_set_u64(options_handle, "opslimit", 5)?;
/// ctx.symmetric_options_set_u64(options_handle, "parallelism", 8)?;
///
/// let state_handle = ctx.symmetric_state_open("ARGON2-ID-13", None, Some(options))?;
/// ctx.symmtric_state_absorb(state_handle, b"password")?;
///
/// let pw_str_handle = ctx.symmetric_state_squeeze_tag(state_handle)?;
/// let mut pw_str = vec![0u8; ctx.symmetric_tag_len(pw_str_handle)?];
/// ctx.symmetric_tag_pull(pw_str_handle, &mut pw_str)?;
/// ```
///
/// - **AEAD encryption with an explicit nonce**
///
/// ```rust
/// let key_handle = ctx.symmetric_key_generate("AES-256-GCM", None)?;
/// let message = b"test";
///
/// let options_handle = ctx.symmetric_options_open()?;
/// ctx.symmetric_options_set(options_handle, "nonce", nonce)?;
///
/// let state_handle = ctx.symmetric_state_open("AES-256-GCM", Some(key_handle), Some(options_handle))?;
/// let mut ciphertext = vec![0u8; message.len() + ctx.symmetric_state_max_tag_len(state_handle)?];
/// ctx.symmetric_state_absorb(state_handle, "additional data")?;
/// ctx.symmetric_state_encrypt(state_handle, &mut ciphertext, message)?;
/// ```
///
/// - **AEAD encryption with automatic nonce generation**
///
/// ```rust
/// let key_handle = ctx.symmetric_key_generate("AES-256-GCM-SIV", None)?;
/// let message = b"test";
/// let mut nonce = [0u8; 24];
///
/// let state_handle = ctx.symmetric_state_open("AES-256-GCM-SIV", Some(key_handle), None)?;
///
/// let nonce_handle = ctx.symmetric_state_options_get(state_handle, "nonce")?;
/// ctx.array_output_pull(nonce_handle, &mut nonce)?;
///
/// let mut ciphertext = vec![0u8; message.len() + ctx.symmetric_state_max_tag_len(state_handle)?];
/// ctx.symmetric_state_absorb(state_handle, "additional data")?;
/// ctx.symmetric_state_encrypt(state_handle, &mut ciphertext, message)?;
/// ```
///
/// - **Session authenticated modes**
///
/// ```rust
/// let mut out = [0u8; 16];
/// let mut out2 = [0u8; 16];
/// let mut ciphertext = [0u8; 20];
/// let key_handle = ctx.symmetric_key_generate("Xoodyak-128", None)?;
/// let state_handle = ctx.symmetric_state_open("Xoodyak-128", Some(key_handle), None)?;
/// ctx.symmetric_state_absorb(state_handle, b"data")?;
/// ctx.symmetric_state_encrypt(state_handle, &mut ciphertext, b"abcd")?;
/// ctx.symmetric_state_absorb(state_handle, b"more data")?;
/// ctx.symmetric_state_squeeze(state_handle, &mut out)?;
/// ctx.symmetric_state_squeeze(state_handle, &mut out2)?;
/// ctx.symmetric_state_ratchet(state_handle)?;
/// ctx.symmetric_state_absorb(state_handle, b"more data")?;
/// let next_key_handle = ctx.symmetric_state_squeeze_key(state_handle, "Xoodyak-128")?;
/// // ...
/// ```
pub unsafe fn symmetric_state_open(
    algorithm: &str,
    key: &OptSymmetricKey,
    options: &OptOptions,
) -> Result<SymmetricState> {
    let mut symmetric_state = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_state_open(
        algorithm.as_ptr(),
        algorithm.len(),
        key,
        options,
        symmetric_state.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(symmetric_state.assume_init())
    }
}

/// Retrieve a parameter from the current state.
///
/// In particular, `symmetric_state_options_get("nonce")` can be used to get a nonce that as automatically generated.
///
/// The function may return `options_not_set` if an option was not set, which is different from an empty value.
///
/// It may also return `unsupported_option` if the option doesn't exist for the chosen algorithm.
pub unsafe fn symmetric_state_options_get(
    handle: SymmetricState,
    name: &str,
    value: *mut u8,
    value_max_len: Size,
) -> Result<Size> {
    let mut value_len = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_state_options_get(
        handle,
        name.as_ptr(),
        name.len(),
        value,
        value_max_len,
        value_len.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(value_len.assume_init())
    }
}

/// Retrieve an integer parameter from the current state.
///
/// In particular, `symmetric_state_options_get("nonce")` can be used to get a nonce that as automatically generated.
///
/// The function may return `options_not_set` if an option was not set.
///
/// It may also return `unsupported_option` if the option doesn't exist for the chosen algorithm.
pub unsafe fn symmetric_state_options_get_u64(handle: SymmetricState, name: &str) -> Result<u64> {
    let mut value = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_state_options_get_u64(
        handle,
        name.as_ptr(),
        name.len(),
        value.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(value.assume_init())
    }
}

/// Destroy a symmetric state.
///
/// Objects are reference counted. It is safe to close an object immediately after the last function needing it is called.
pub unsafe fn symmetric_state_close(handle: SymmetricState) -> Result<()> {
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_state_close(handle);
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

/// Absorb data into the state.
///
/// - **Hash functions:** adds data to be hashed.
/// - **MAC functions:** adds data to be authenticated.
/// - **Tuplehash-like constructions:** adds a new tuple to the state.
/// - **Key derivation functions:** adds to the IKM or to the subkey information.
/// - **AEAD constructions:** adds additional data to be authenticated.
/// - **Stateful hash objects, permutation-based constructions:** absorbs.
///
/// If the chosen algorithm doesn't accept input data, the `invalid_operation` error code is returned.
///
/// If too much data has been fed for the algorithm, `overflow` may be thrown.
pub unsafe fn symmetric_state_absorb(
    handle: SymmetricState,
    data: *const u8,
    data_len: Size,
) -> Result<()> {
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_state_absorb(handle, data, data_len);
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

/// Squeeze bytes from the state.
///
/// - **Hash functions:** this tries to output an `out_len` bytes digest from the absorbed data. The hash function output will be truncated if necessary. If the requested size is too large, the `invalid_len` error code is returned.
/// - **Key derivation functions:** : outputs an arbitrary-long derived key.
/// - **RNGs, DRBGs, stream ciphers:**: outputs arbitrary-long data.
/// - **Stateful hash objects, permutation-based constructions:** squeeze.
///
/// Other kinds of algorithms may return `invalid_operation` instead.
///
/// For password-stretching functions, the function may return `in_progress`.
/// In that case, the guest should retry with the same parameters until the function completes.
pub unsafe fn symmetric_state_squeeze(
    handle: SymmetricState,
    out: *mut u8,
    out_len: Size,
) -> Result<()> {
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_state_squeeze(handle, out, out_len);
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

/// Compute and return a tag for all the data injected into the state so far.
///
/// - **MAC functions**: returns a tag authenticating the absorbed data.
/// - **Tuplehash-like constructions:** returns a tag authenticating all the absorbed tuples.
/// - **Password-hashing functions:** returns a standard string containing all the required parameters for password verification.
///
/// Other kinds of algorithms may return `invalid_operation` instead.
///
/// For password-stretching functions, the function may return `in_progress`.
/// In that case, the guest should retry with the same parameters until the function completes.
pub unsafe fn symmetric_state_squeeze_tag(handle: SymmetricState) -> Result<SymmetricTag> {
    let mut symmetric_tag = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_state_squeeze_tag(
        handle,
        symmetric_tag.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(symmetric_tag.assume_init())
    }
}

/// Use the current state to produce a key for a target algorithm.
///
/// For extract-then-expand constructions, this returns the PRK.
/// For session-base authentication encryption, this returns a key that can be used to resume a session without storing a nonce.
///
/// `invalid_operation` is returned for algorithms not supporting this operation.
pub unsafe fn symmetric_state_squeeze_key(
    handle: SymmetricState,
    alg_str: &str,
) -> Result<SymmetricKey> {
    let mut symmetric_key = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_state_squeeze_key(
        handle,
        alg_str.as_ptr(),
        alg_str.len(),
        symmetric_key.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(symmetric_key.assume_init())
    }
}

/// Return the maximum length of an authentication tag for the current algorithm.
///
/// This allows guests to compute the size required to store a ciphertext along with its authentication tag.
///
/// The returned length may include the encryption mode's padding requirements in addition to the actual tag.
///
/// For an encryption operation, the size of the output buffer should be `input_len + symmetric_state_max_tag_len()`.
///
/// For a decryption operation, the size of the buffer that will store the decrypted data can be reduced to `ciphertext_len - symmetric_state_max_tag_len()` only if the algorithm is known to have a fixed tag length.
pub unsafe fn symmetric_state_max_tag_len(handle: SymmetricState) -> Result<Size> {
    let mut len = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_state_max_tag_len(handle, len.as_mut_ptr());
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(len.assume_init())
    }
}

/// Encrypt data with an attached tag.
///
/// - **Stream cipher:** adds the input to the stream cipher output. `out_len` and `data_len` can be equal, as no authentication tags will be added.
/// - **AEAD:** encrypts `data` into `out`, including the authentication tag to the output. Additional data must have been previously absorbed using `symmetric_state_absorb()`. The `symmetric_state_max_tag_len()` function can be used to retrieve the overhead of adding the tag, as well as padding if necessary.
/// - **SHOE, Xoodyak, Strobe:** encrypts data, squeezes a tag and appends it to the output.
///
/// If `out` and `data` are the same address, encryption may happen in-place.
///
/// The function returns the actual size of the ciphertext along with the tag.
///
/// `invalid_operation` is returned for algorithms not supporting encryption.
pub unsafe fn symmetric_state_encrypt(
    handle: SymmetricState,
    out: *mut u8,
    out_len: Size,
    data: *const u8,
    data_len: Size,
) -> Result<Size> {
    let mut actual_out_len = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_state_encrypt(
        handle,
        out,
        out_len,
        data,
        data_len,
        actual_out_len.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(actual_out_len.assume_init())
    }
}

/// Encrypt data, with a detached tag.
///
/// - **Stream cipher:** returns `invalid_operation` since stream ciphers do not include authentication tags.
/// - **AEAD:** encrypts `data` into `out` and returns the tag separately. Additional data must have been previously absorbed using `symmetric_state_absorb()`. The output and input buffers must be of the same length.
/// - **SHOE, Xoodyak, Strobe:** encrypts data and squeezes a tag.
///
/// If `out` and `data` are the same address, encryption may happen in-place.
///
/// The function returns the tag.
///
/// `invalid_operation` is returned for algorithms not supporting encryption.
pub unsafe fn symmetric_state_encrypt_detached(
    handle: SymmetricState,
    out: *mut u8,
    out_len: Size,
    data: *const u8,
    data_len: Size,
) -> Result<SymmetricTag> {
    let mut symmetric_tag = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_state_encrypt_detached(
        handle,
        out,
        out_len,
        data,
        data_len,
        symmetric_tag.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(symmetric_tag.assume_init())
    }
}

/// - **Stream cipher:** adds the input to the stream cipher output. `out_len` and `data_len` can be equal, as no authentication tags will be added.
/// - **AEAD:** decrypts `data` into `out`. Additional data must have been previously absorbed using `symmetric_state_absorb()`.
/// - **SHOE, Xoodyak, Strobe:** decrypts data, squeezes a tag and verify that it matches the one that was appended to the ciphertext.
///
/// If `out` and `data` are the same address, decryption may happen in-place.
///
/// The function returns the actual size of the decrypted message.
///
/// `invalid_tag` is returned if the tag didn't verify.
///
/// `invalid_operation` is returned for algorithms not supporting encryption.
pub unsafe fn symmetric_state_decrypt(
    handle: SymmetricState,
    out: *mut u8,
    out_len: Size,
    data: *const u8,
    data_len: Size,
) -> Result<Size> {
    let mut actual_out_len = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_state_decrypt(
        handle,
        out,
        out_len,
        data,
        data_len,
        actual_out_len.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(actual_out_len.assume_init())
    }
}

/// - **Stream cipher:** returns `invalid_operation` since stream ciphers do not include authentication tags.
/// - **AEAD:** decrypts `data` into `out`. Additional data must have been previously absorbed using `symmetric_state_absorb()`.
/// - **SHOE, Xoodyak, Strobe:** decrypts data, squeezes a tag and verify that it matches the expected one.
///
/// `raw_tag` is the expected tag, as raw bytes.
///
/// `out` and `data` be must have the same length.
/// If they also share the same address, decryption may happen in-place.
///
/// The function returns the actual size of the decrypted message.
///
/// `invalid_tag` is returned if the tag verification failed.
///
/// `invalid_operation` is returned for algorithms not supporting encryption.
pub unsafe fn symmetric_state_decrypt_detached(
    handle: SymmetricState,
    out: *mut u8,
    out_len: Size,
    data: *const u8,
    data_len: Size,
    raw_tag: *const u8,
    raw_tag_len: Size,
) -> Result<Size> {
    let mut actual_out_len = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_state_decrypt_detached(
        handle,
        out,
        out_len,
        data,
        data_len,
        raw_tag,
        raw_tag_len,
        actual_out_len.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(actual_out_len.assume_init())
    }
}

/// Make it impossible to recover the previous state.
///
/// This operation is supported by some systems keeping a rolling state over an entire session, for forward security.
///
/// `invalid_operation` is returned for algorithms not supporting ratcheting.
pub unsafe fn symmetric_state_ratchet(handle: SymmetricState) -> Result<()> {
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_state_ratchet(handle);
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

/// Return the length of an authentication tag.
///
/// This function can be used by a guest to allocate the correct buffer size to copy a computed authentication tag.
pub unsafe fn symmetric_tag_len(symmetric_tag: SymmetricTag) -> Result<Size> {
    let mut len = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_tag_len(symmetric_tag, len.as_mut_ptr());
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(len.assume_init())
    }
}

/// Copy an authentication tag into a guest-allocated buffer.
///
/// The handle automatically becomes invalid after this operation. Manually closing it is not required.
///
/// Example usage:
///
/// ```rust
/// let mut raw_tag = [0u8; 16];
/// ctx.symmetric_tag_pull(raw_tag_handle, &mut raw_tag)?;
/// ```
///
/// The function returns `overflow` if the supplied buffer is too small to copy the tag.
///
/// Otherwise, it returns the number of bytes that have been copied.
pub unsafe fn symmetric_tag_pull(
    symmetric_tag: SymmetricTag,
    buf: *mut u8,
    buf_len: Size,
) -> Result<Size> {
    let mut len = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_tag_pull(
        symmetric_tag,
        buf,
        buf_len,
        len.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(len.assume_init())
    }
}

/// Verify that a computed authentication tag matches the expected value, in constant-time.
///
/// The expected tag must be provided as a raw byte string.
///
/// The function returns `invalid_tag` if the tags don't match.
///
/// Example usage:
///
/// ```rust
/// let key_handle = ctx.symmetric_key_import("HMAC/SHA-256", b"key")?;
/// let state_handle = ctx.symmetric_state_open("HMAC/SHA-256", Some(key_handle), None)?;
/// ctx.symmetric_state_absorb(state_handle, b"data")?;
/// let computed_tag_handle = ctx.symmetric_state_squeeze_tag(state_handle)?;
/// ctx.symmetric_tag_verify(computed_tag_handle, expected_raw_tag)?;
/// ```
pub unsafe fn symmetric_tag_verify(
    symmetric_tag: SymmetricTag,
    expected_raw_tag_ptr: *const u8,
    expected_raw_tag_len: Size,
) -> Result<()> {
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_tag_verify(
        symmetric_tag,
        expected_raw_tag_ptr,
        expected_raw_tag_len,
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

/// Explicitly destroy an unused authentication tag.
///
/// This is usually not necessary, as `symmetric_tag_pull()` automatically closes a tag after it has been copied.
///
/// Objects are reference counted. It is safe to close an object immediately after the last function needing it is called.
pub unsafe fn symmetric_tag_close(symmetric_tag: SymmetricTag) -> Result<()> {
    let rc = wasi_ephemeral_crypto_symmetric::symmetric_tag_close(symmetric_tag);
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(())
    }
}

pub mod wasi_ephemeral_crypto_symmetric {
    use super::*;
    #[link(wasm_import_module = "wasi_ephemeral_crypto_symmetric")]
    extern "C" {
        /// Generate a new symmetric key for a given algorithm.
        ///
        /// `options` can be `None` to use the default parameters, or an algoritm-specific set of parameters to override.
        ///
        /// This function may return `unsupported_feature` if key generation is not supported by the host for the chosen algorithm, or `unsupported_algorithm` if the algorithm is not supported by the host.
        pub fn symmetric_key_generate(
            algorithm_ptr: *const u8,
            algorithm_len: usize,
            options: *const OptOptions,
            handle: *mut SymmetricKey,
        ) -> CryptoErrno;
        /// Create a symmetric key from raw material.
        ///
        /// The algorithm is internally stored along with the key, and trying to use the key with an operation expecting a different algorithm will return `invalid_key`.
        ///
        /// The function may also return `unsupported_algorithm` if the algorithm is not supported by the host.
        pub fn symmetric_key_import(
            algorithm_ptr: *const u8,
            algorithm_len: usize,
            raw: *const u8,
            raw_len: Size,
            handle: *mut SymmetricKey,
        ) -> CryptoErrno;
        /// Export a symmetric key as raw material.
        ///
        /// This is mainly useful to export a managed key.
        ///
        /// May return `prohibited_operation` if this operation is denied.
        pub fn symmetric_key_export(
            symmetric_key: SymmetricKey,
            encoded: *mut ArrayOutput,
        ) -> CryptoErrno;
        /// Destroy a symmetric key.
        ///
        /// Objects are reference counted. It is safe to close an object immediately after the last function needing it is called.
        pub fn symmetric_key_close(symmetric_key: SymmetricKey) -> CryptoErrno;
        /// __(optional)__
        /// Generate a new managed symmetric key.
        ///
        /// The key is generated and stored by the secrets management facilities.
        ///
        /// It may be used through its identifier, but the host may not allow it to be exported.
        ///
        /// The function returns the `unsupported_feature` error code if secrets management facilities are not supported by the host,
        /// or `unsupported_algorithm` if a key cannot be created for the chosen algorithm.
        ///
        /// The function may also return `unsupported_algorithm` if the algorithm is not supported by the host.
        ///
        /// This is also an optional import, meaning that the function may not even exist.
        pub fn symmetric_key_generate_managed(
            secrets_manager: SecretsManager,
            algorithm_ptr: *const u8,
            algorithm_len: usize,
            options: *const OptOptions,
            handle: *mut SymmetricKey,
        ) -> CryptoErrno;
        /// __(optional)__
        /// Store a symmetric key into the secrets manager.
        ///
        /// On success, the function stores the key identifier into `$symmetric_key_id`,
        /// into which up to `$symmetric_key_id_max_len` can be written.
        ///
        /// The function returns `overflow` if the supplied buffer is too small.
        pub fn symmetric_key_store_managed(
            secrets_manager: SecretsManager,
            symmetric_key: SymmetricKey,
            symmetric_key_id: *mut u8,
            symmetric_key_id_max_len: Size,
        ) -> CryptoErrno;
        /// __(optional)__
        /// Replace a managed symmetric key.
        ///
        /// This function crates a new version of a managed symmetric key, by replacing `$kp_old` with `$kp_new`.
        ///
        /// It does several things:
        ///
        /// - The key identifier for `$symmetric_key_new` is set to the one of `$symmetric_key_old`.
        /// - A new, unique version identifier is assigned to `$kp_new`. This version will be equivalent to using `$version_latest` until the key is replaced.
        /// - The `$symmetric_key_old` handle is closed.
        ///
        /// Both keys must share the same algorithm and have compatible parameters. If this is not the case, `incompatible_keys` is returned.
        ///
        /// The function may also return the `unsupported_feature` error code if secrets management facilities are not supported by the host,
        /// or if keys cannot be rotated.
        ///
        /// Finally, `prohibited_operation` can be returned if `$symmetric_key_new` wasn't created by the secrets manager, and the secrets manager prohibits imported keys.
        ///
        /// If the operation succeeded, the new version is returned.
        ///
        /// This is an optional import, meaning that the function may not even exist.
        pub fn symmetric_key_replace_managed(
            secrets_manager: SecretsManager,
            symmetric_key_old: SymmetricKey,
            symmetric_key_new: SymmetricKey,
            version: *mut Version,
        ) -> CryptoErrno;
        /// __(optional)__
        /// Return the key identifier and version of a managed symmetric key.
        ///
        /// If the key is not managed, `unsupported_feature` is returned instead.
        ///
        /// This is an optional import, meaning that the function may not even exist.
        pub fn symmetric_key_id(
            symmetric_key: SymmetricKey,
            symmetric_key_id: *mut u8,
            symmetric_key_id_max_len: Size,
            symmetric_key_id_len: *mut Size,
            version: *mut Version,
        ) -> CryptoErrno;
        /// __(optional)__
        /// Return a managed symmetric key from a key identifier.
        ///
        /// `kp_version` can be set to `version_latest` to retrieve the most recent version of a symmetric key.
        ///
        /// If no key matching the provided information is found, `not_found` is returned instead.
        ///
        /// This is an optional import, meaning that the function may not even exist.
        pub fn symmetric_key_from_id(
            secrets_manager: SecretsManager,
            symmetric_key_id: *const u8,
            symmetric_key_id_len: Size,
            symmetric_key_version: Version,
            handle: *mut SymmetricKey,
        ) -> CryptoErrno;
        /// Create a new state to aborb and produce data using symmetric operations.
        ///
        /// The state remains valid after every operation in order to support incremental updates.
        ///
        /// The function has two optional parameters: a key and an options set.
        ///
        /// It will fail with a `key_not_supported` error code if a key was provided but the chosen algorithm doesn't natively support keying.
        ///
        /// On the other hand, if a key is required, but was not provided, a `key_required` error will be thrown.
        ///
        /// Some algorithms may require additional parameters. They have to be supplied as an options set:
        ///
        /// ```rust
        /// let options_handle = ctx.options_open()?;
        /// ctx.options_set("context", b"My application")?;
        /// ctx.options_set_u64("fanout", 16)?;
        /// let state_handle = ctx.symmetric_state_open("BLAKE2b-512", None, Some(options_handle))?;
        /// ```
        ///
        /// If some parameters are mandatory but were not set, the `parameters_missing` error code will be returned.
        ///
        /// A notable exception is the `nonce` parameter, that is common to most AEAD constructions.
        ///
        /// If a nonce is required but was not supplied:
        ///
        /// - If it is safe to do so, the host will automatically generate a nonce. This is true for nonces that are large enough to be randomly generated, or if the host is able to maintain a global counter.
        /// - If not, the function will fail and return the dedicated `nonce_required` error code.
        ///
        /// A nonce that was automatically generated can be retrieved after the function returns with `symmetric_state_get(state_handle, "nonce")`.
        ///
        /// **Sample usage patterns:**
        ///
        /// - **Hashing**
        ///
        /// ```rust
        /// let mut out = [0u8; 64];
        /// let state_handle = ctx.symmetric_state_open("SHAKE-128", None, None)?;
        /// ctx.symmetric_state_absorb(state_handle, b"data")?;
        /// ctx.symmetric_state_absorb(state_handle, b"more_data")?;
        /// ctx.symmetric_state_squeeze(state_handle, &mut out)?;
        /// ```
        ///
        /// - **MAC**
        ///
        /// ```rust
        /// let mut raw_tag = [0u8; 64];
        /// let key_handle = ctx.symmetric_key_import("HMAC/SHA-512", b"key")?;
        /// let state_handle = ctx.symmetric_state_open("HMAC/SHA-512", Some(key_handle), None)?;
        /// ctx.symmetric_state_absorb(state_handle, b"data")?;
        /// ctx.symmetric_state_absorb(state_handle, b"more_data")?;
        /// let computed_tag_handle = ctx.symmetric_state_squeeze_tag(state_handle)?;
        /// ctx.symmetric_tag_pull(computed_tag_handle, &mut raw_tag)?;
        /// ```
        ///
        /// Verification:
        ///
        /// ```rust
        /// let state_handle = ctx.symmetric_state_open("HMAC/SHA-512", Some(key_handle), None)?;
        /// ctx.symmetric_state_absorb(state_handle, b"data")?;
        /// ctx.symmetric_state_absorb(state_handle, b"more_data")?;
        /// let computed_tag_handle = ctx.symmetric_state_squeeze_tag(state_handle)?;
        /// ctx.symmetric_tag_verify(computed_tag_handle, expected_raw_tag)?;
        /// ```
        ///
        /// - **Tuple hashing**
        ///
        /// ```rust
        /// let mut out = [0u8; 64];
        /// let state_handle = ctx.symmetric_state_open("TupleHashXOF256", None, None)?;
        /// ctx.symmetric_state_absorb(state_handle, b"value 1")?;
        /// ctx.symmetric_state_absorb(state_handle, b"value 2")?;
        /// ctx.symmetric_state_absorb(state_handle, b"value 3")?;
        /// ctx.symmetric_state_squeeze(state_handle, &mut out)?;
        /// ```
        /// Unlike MACs and regular hash functions, inputs are domain separated instead of being concatenated.
        ///
        /// - **Key derivation using extract-and-expand**
        ///
        /// Extract:
        ///
        /// ```rust
        /// let mut prk = vec![0u8; 64];
        /// let key_handle = ctx.symmetric_key_import("HKDF-EXTRACT/SHA-512", b"key")?;
        /// let state_handle = ctx.symmetric_state_open("HKDF-EXTRACT/SHA-512", Some(key_handle), None)?;
        /// ctx.symmetric_state_absorb(state_handle, b"salt")?;
        /// let prk_handle = ctx.symmetric_state_squeeze_key(state_handle, "HKDF-EXPAND/SHA-512")?;
        /// ```
        ///
        /// Expand:
        ///
        /// ```rust
        /// let mut subkey = vec![0u8; 32];
        /// let state_handle = ctx.symmetric_state_open("HKDF-EXPAND/SHA-512", Some(prk_handle), None)?;
        /// ctx.symmetric_state_absorb(state_handle, b"info")?;
        /// ctx.symmetric_state_squeeze(state_handle, &mut subkey)?;
        /// ```
        ///
        /// - **Key derivation using a XOF**
        ///
        /// ```rust
        /// let mut subkey1 = vec![0u8; 32];
        /// let mut subkey2 = vec![0u8; 32];
        /// let key_handle = ctx.symmetric_key_import("BLAKE3", b"key")?;
        /// let state_handle = ctx.symmetric_state_open("BLAKE3", Some(key_handle), None)?;
        /// ctx.symmetric_absorb(state_handle, b"context")?;
        /// ctx.squeeze(state_handle, &mut subkey1)?;
        /// ctx.squeeze(state_handle, &mut subkey2)?;
        /// ```
        ///
        /// - **Password hashing**
        ///
        /// ```rust
        /// let mut memory = vec![0u8; 1_000_000_000];
        /// let options_handle = ctx.symmetric_options_open()?;
        /// ctx.symmetric_options_set_guest_buffer(options_handle, "memory", &mut memory)?;
        /// ctx.symmetric_options_set_u64(options_handle, "opslimit", 5)?;
        /// ctx.symmetric_options_set_u64(options_handle, "parallelism", 8)?;
        ///
        /// let state_handle = ctx.symmetric_state_open("ARGON2-ID-13", None, Some(options))?;
        /// ctx.symmtric_state_absorb(state_handle, b"password")?;
        ///
        /// let pw_str_handle = ctx.symmetric_state_squeeze_tag(state_handle)?;
        /// let mut pw_str = vec![0u8; ctx.symmetric_tag_len(pw_str_handle)?];
        /// ctx.symmetric_tag_pull(pw_str_handle, &mut pw_str)?;
        /// ```
        ///
        /// - **AEAD encryption with an explicit nonce**
        ///
        /// ```rust
        /// let key_handle = ctx.symmetric_key_generate("AES-256-GCM", None)?;
        /// let message = b"test";
        ///
        /// let options_handle = ctx.symmetric_options_open()?;
        /// ctx.symmetric_options_set(options_handle, "nonce", nonce)?;
        ///
        /// let state_handle = ctx.symmetric_state_open("AES-256-GCM", Some(key_handle), Some(options_handle))?;
        /// let mut ciphertext = vec![0u8; message.len() + ctx.symmetric_state_max_tag_len(state_handle)?];
        /// ctx.symmetric_state_absorb(state_handle, "additional data")?;
        /// ctx.symmetric_state_encrypt(state_handle, &mut ciphertext, message)?;
        /// ```
        ///
        /// - **AEAD encryption with automatic nonce generation**
        ///
        /// ```rust
        /// let key_handle = ctx.symmetric_key_generate("AES-256-GCM-SIV", None)?;
        /// let message = b"test";
        /// let mut nonce = [0u8; 24];
        ///
        /// let state_handle = ctx.symmetric_state_open("AES-256-GCM-SIV", Some(key_handle), None)?;
        ///
        /// let nonce_handle = ctx.symmetric_state_options_get(state_handle, "nonce")?;
        /// ctx.array_output_pull(nonce_handle, &mut nonce)?;
        ///
        /// let mut ciphertext = vec![0u8; message.len() + ctx.symmetric_state_max_tag_len(state_handle)?];
        /// ctx.symmetric_state_absorb(state_handle, "additional data")?;
        /// ctx.symmetric_state_encrypt(state_handle, &mut ciphertext, message)?;
        /// ```
        ///
        /// - **Session authenticated modes**
        ///
        /// ```rust
        /// let mut out = [0u8; 16];
        /// let mut out2 = [0u8; 16];
        /// let mut ciphertext = [0u8; 20];
        /// let key_handle = ctx.symmetric_key_generate("Xoodyak-128", None)?;
        /// let state_handle = ctx.symmetric_state_open("Xoodyak-128", Some(key_handle), None)?;
        /// ctx.symmetric_state_absorb(state_handle, b"data")?;
        /// ctx.symmetric_state_encrypt(state_handle, &mut ciphertext, b"abcd")?;
        /// ctx.symmetric_state_absorb(state_handle, b"more data")?;
        /// ctx.symmetric_state_squeeze(state_handle, &mut out)?;
        /// ctx.symmetric_state_squeeze(state_handle, &mut out2)?;
        /// ctx.symmetric_state_ratchet(state_handle)?;
        /// ctx.symmetric_state_absorb(state_handle, b"more data")?;
        /// let next_key_handle = ctx.symmetric_state_squeeze_key(state_handle, "Xoodyak-128")?;
        /// // ...
        /// ```
        pub fn symmetric_state_open(
            algorithm_ptr: *const u8,
            algorithm_len: usize,
            key: *const OptSymmetricKey,
            options: *const OptOptions,
            symmetric_state: *mut SymmetricState,
        ) -> CryptoErrno;
        /// Retrieve a parameter from the current state.
        ///
        /// In particular, `symmetric_state_options_get("nonce")` can be used to get a nonce that as automatically generated.
        ///
        /// The function may return `options_not_set` if an option was not set, which is different from an empty value.
        ///
        /// It may also return `unsupported_option` if the option doesn't exist for the chosen algorithm.
        pub fn symmetric_state_options_get(
            handle: SymmetricState,
            name_ptr: *const u8,
            name_len: usize,
            value: *mut u8,
            value_max_len: Size,
            value_len: *mut Size,
        ) -> CryptoErrno;
        /// Retrieve an integer parameter from the current state.
        ///
        /// In particular, `symmetric_state_options_get("nonce")` can be used to get a nonce that as automatically generated.
        ///
        /// The function may return `options_not_set` if an option was not set.
        ///
        /// It may also return `unsupported_option` if the option doesn't exist for the chosen algorithm.
        pub fn symmetric_state_options_get_u64(
            handle: SymmetricState,
            name_ptr: *const u8,
            name_len: usize,
            value: *mut u64,
        ) -> CryptoErrno;
        /// Destroy a symmetric state.
        ///
        /// Objects are reference counted. It is safe to close an object immediately after the last function needing it is called.
        pub fn symmetric_state_close(handle: SymmetricState) -> CryptoErrno;
        /// Absorb data into the state.
        ///
        /// - **Hash functions:** adds data to be hashed.
        /// - **MAC functions:** adds data to be authenticated.
        /// - **Tuplehash-like constructions:** adds a new tuple to the state.
        /// - **Key derivation functions:** adds to the IKM or to the subkey information.
        /// - **AEAD constructions:** adds additional data to be authenticated.
        /// - **Stateful hash objects, permutation-based constructions:** absorbs.
        ///
        /// If the chosen algorithm doesn't accept input data, the `invalid_operation` error code is returned.
        ///
        /// If too much data has been fed for the algorithm, `overflow` may be thrown.
        pub fn symmetric_state_absorb(
            handle: SymmetricState,
            data: *const u8,
            data_len: Size,
        ) -> CryptoErrno;
        /// Squeeze bytes from the state.
        ///
        /// - **Hash functions:** this tries to output an `out_len` bytes digest from the absorbed data. The hash function output will be truncated if necessary. If the requested size is too large, the `invalid_len` error code is returned.
        /// - **Key derivation functions:** : outputs an arbitrary-long derived key.
        /// - **RNGs, DRBGs, stream ciphers:**: outputs arbitrary-long data.
        /// - **Stateful hash objects, permutation-based constructions:** squeeze.
        ///
        /// Other kinds of algorithms may return `invalid_operation` instead.
        ///
        /// For password-stretching functions, the function may return `in_progress`.
        /// In that case, the guest should retry with the same parameters until the function completes.
        pub fn symmetric_state_squeeze(
            handle: SymmetricState,
            out: *mut u8,
            out_len: Size,
        ) -> CryptoErrno;
        /// Compute and return a tag for all the data injected into the state so far.
        ///
        /// - **MAC functions**: returns a tag authenticating the absorbed data.
        /// - **Tuplehash-like constructions:** returns a tag authenticating all the absorbed tuples.
        /// - **Password-hashing functions:** returns a standard string containing all the required parameters for password verification.
        ///
        /// Other kinds of algorithms may return `invalid_operation` instead.
        ///
        /// For password-stretching functions, the function may return `in_progress`.
        /// In that case, the guest should retry with the same parameters until the function completes.
        pub fn symmetric_state_squeeze_tag(
            handle: SymmetricState,
            symmetric_tag: *mut SymmetricTag,
        ) -> CryptoErrno;
        /// Use the current state to produce a key for a target algorithm.
        ///
        /// For extract-then-expand constructions, this returns the PRK.
        /// For session-base authentication encryption, this returns a key that can be used to resume a session without storing a nonce.
        ///
        /// `invalid_operation` is returned for algorithms not supporting this operation.
        pub fn symmetric_state_squeeze_key(
            handle: SymmetricState,
            alg_str_ptr: *const u8,
            alg_str_len: usize,
            symmetric_key: *mut SymmetricKey,
        ) -> CryptoErrno;
        /// Return the maximum length of an authentication tag for the current algorithm.
        ///
        /// This allows guests to compute the size required to store a ciphertext along with its authentication tag.
        ///
        /// The returned length may include the encryption mode's padding requirements in addition to the actual tag.
        ///
        /// For an encryption operation, the size of the output buffer should be `input_len + symmetric_state_max_tag_len()`.
        ///
        /// For a decryption operation, the size of the buffer that will store the decrypted data can be reduced to `ciphertext_len - symmetric_state_max_tag_len()` only if the algorithm is known to have a fixed tag length.
        pub fn symmetric_state_max_tag_len(handle: SymmetricState, len: *mut Size) -> CryptoErrno;
        /// Encrypt data with an attached tag.
        ///
        /// - **Stream cipher:** adds the input to the stream cipher output. `out_len` and `data_len` can be equal, as no authentication tags will be added.
        /// - **AEAD:** encrypts `data` into `out`, including the authentication tag to the output. Additional data must have been previously absorbed using `symmetric_state_absorb()`. The `symmetric_state_max_tag_len()` function can be used to retrieve the overhead of adding the tag, as well as padding if necessary.
        /// - **SHOE, Xoodyak, Strobe:** encrypts data, squeezes a tag and appends it to the output.
        ///
        /// If `out` and `data` are the same address, encryption may happen in-place.
        ///
        /// The function returns the actual size of the ciphertext along with the tag.
        ///
        /// `invalid_operation` is returned for algorithms not supporting encryption.
        pub fn symmetric_state_encrypt(
            handle: SymmetricState,
            out: *mut u8,
            out_len: Size,
            data: *const u8,
            data_len: Size,
            actual_out_len: *mut Size,
        ) -> CryptoErrno;
        /// Encrypt data, with a detached tag.
        ///
        /// - **Stream cipher:** returns `invalid_operation` since stream ciphers do not include authentication tags.
        /// - **AEAD:** encrypts `data` into `out` and returns the tag separately. Additional data must have been previously absorbed using `symmetric_state_absorb()`. The output and input buffers must be of the same length.
        /// - **SHOE, Xoodyak, Strobe:** encrypts data and squeezes a tag.
        ///
        /// If `out` and `data` are the same address, encryption may happen in-place.
        ///
        /// The function returns the tag.
        ///
        /// `invalid_operation` is returned for algorithms not supporting encryption.
        pub fn symmetric_state_encrypt_detached(
            handle: SymmetricState,
            out: *mut u8,
            out_len: Size,
            data: *const u8,
            data_len: Size,
            symmetric_tag: *mut SymmetricTag,
        ) -> CryptoErrno;
        /// - **Stream cipher:** adds the input to the stream cipher output. `out_len` and `data_len` can be equal, as no authentication tags will be added.
        /// - **AEAD:** decrypts `data` into `out`. Additional data must have been previously absorbed using `symmetric_state_absorb()`.
        /// - **SHOE, Xoodyak, Strobe:** decrypts data, squeezes a tag and verify that it matches the one that was appended to the ciphertext.
        ///
        /// If `out` and `data` are the same address, decryption may happen in-place.
        ///
        /// The function returns the actual size of the decrypted message.
        ///
        /// `invalid_tag` is returned if the tag didn't verify.
        ///
        /// `invalid_operation` is returned for algorithms not supporting encryption.
        pub fn symmetric_state_decrypt(
            handle: SymmetricState,
            out: *mut u8,
            out_len: Size,
            data: *const u8,
            data_len: Size,
            actual_out_len: *mut Size,
        ) -> CryptoErrno;
        /// - **Stream cipher:** returns `invalid_operation` since stream ciphers do not include authentication tags.
        /// - **AEAD:** decrypts `data` into `out`. Additional data must have been previously absorbed using `symmetric_state_absorb()`.
        /// - **SHOE, Xoodyak, Strobe:** decrypts data, squeezes a tag and verify that it matches the expected one.
        ///
        /// `raw_tag` is the expected tag, as raw bytes.
        ///
        /// `out` and `data` be must have the same length.
        /// If they also share the same address, decryption may happen in-place.
        ///
        /// The function returns the actual size of the decrypted message.
        ///
        /// `invalid_tag` is returned if the tag verification failed.
        ///
        /// `invalid_operation` is returned for algorithms not supporting encryption.
        pub fn symmetric_state_decrypt_detached(
            handle: SymmetricState,
            out: *mut u8,
            out_len: Size,
            data: *const u8,
            data_len: Size,
            raw_tag: *const u8,
            raw_tag_len: Size,
            actual_out_len: *mut Size,
        ) -> CryptoErrno;
        /// Make it impossible to recover the previous state.
        ///
        /// This operation is supported by some systems keeping a rolling state over an entire session, for forward security.
        ///
        /// `invalid_operation` is returned for algorithms not supporting ratcheting.
        pub fn symmetric_state_ratchet(handle: SymmetricState) -> CryptoErrno;
        /// Return the length of an authentication tag.
        ///
        /// This function can be used by a guest to allocate the correct buffer size to copy a computed authentication tag.
        pub fn symmetric_tag_len(symmetric_tag: SymmetricTag, len: *mut Size) -> CryptoErrno;
        /// Copy an authentication tag into a guest-allocated buffer.
        ///
        /// The handle automatically becomes invalid after this operation. Manually closing it is not required.
        ///
        /// Example usage:
        ///
        /// ```rust
        /// let mut raw_tag = [0u8; 16];
        /// ctx.symmetric_tag_pull(raw_tag_handle, &mut raw_tag)?;
        /// ```
        ///
        /// The function returns `overflow` if the supplied buffer is too small to copy the tag.
        ///
        /// Otherwise, it returns the number of bytes that have been copied.
        pub fn symmetric_tag_pull(
            symmetric_tag: SymmetricTag,
            buf: *mut u8,
            buf_len: Size,
            len: *mut Size,
        ) -> CryptoErrno;
        /// Verify that a computed authentication tag matches the expected value, in constant-time.
        ///
        /// The expected tag must be provided as a raw byte string.
        ///
        /// The function returns `invalid_tag` if the tags don't match.
        ///
        /// Example usage:
        ///
        /// ```rust
        /// let key_handle = ctx.symmetric_key_import("HMAC/SHA-256", b"key")?;
        /// let state_handle = ctx.symmetric_state_open("HMAC/SHA-256", Some(key_handle), None)?;
        /// ctx.symmetric_state_absorb(state_handle, b"data")?;
        /// let computed_tag_handle = ctx.symmetric_state_squeeze_tag(state_handle)?;
        /// ctx.symmetric_tag_verify(computed_tag_handle, expected_raw_tag)?;
        /// ```
        pub fn symmetric_tag_verify(
            symmetric_tag: SymmetricTag,
            expected_raw_tag_ptr: *const u8,
            expected_raw_tag_len: Size,
        ) -> CryptoErrno;
        /// Explicitly destroy an unused authentication tag.
        ///
        /// This is usually not necessary, as `symmetric_tag_pull()` automatically closes a tag after it has been copied.
        ///
        /// Objects are reference counted. It is safe to close an object immediately after the last function needing it is called.
        pub fn symmetric_tag_close(symmetric_tag: SymmetricTag) -> CryptoErrno;
    }
}
/// Perform a simple Diffie-Hellman key exchange.
///
/// Both keys must be of the same type, or else the `$crypto_errno.incompatible_keys` error is returned.
/// The algorithm also has to support this kind of key exchange. If this is not the case, the `$crypto_errno.invalid_operation` error is returned.
///
/// Otherwide, a raw shared key is returned, and can be imported as a symmetric key.
/// ```
pub unsafe fn kx_dh(pk: Publickey, sk: Secretkey) -> Result<ArrayOutput> {
    let mut shared_secret = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_kx::kx_dh(pk, sk, shared_secret.as_mut_ptr());
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(shared_secret.assume_init())
    }
}

/// Create a shared secret and encrypt it for the given public key.
///
/// This operation is only compatible with specific algorithms.
/// If a selected algorithm doesn't support it, `$crypto_errno.invalid_operation` is returned.
///
/// On success, both the shared secret and its encrypted version are returned.
pub unsafe fn kx_encapsulate(pk: Publickey) -> Result<(ArrayOutput, ArrayOutput)> {
    let mut secret = MaybeUninit::uninit();
    let mut encapsulated_secret = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_kx::kx_encapsulate(
        pk,
        secret.as_mut_ptr(),
        encapsulated_secret.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok((secret.assume_init(), encapsulated_secret.assume_init()))
    }
}

/// Decapsulate an encapsulated secret crated with `kx_encapsulate`
///
/// Return the secret, or `$crypto_errno.verification_failed` on error.
pub unsafe fn kx_decapsulate(
    sk: Secretkey,
    encapsulated_secret: *const u8,
    encapsulated_secret_len: Size,
) -> Result<ArrayOutput> {
    let mut secret = MaybeUninit::uninit();
    let rc = wasi_ephemeral_crypto_kx::kx_decapsulate(
        sk,
        encapsulated_secret,
        encapsulated_secret_len,
        secret.as_mut_ptr(),
    );
    if let Some(err) = Error::from_raw_error(rc) {
        Err(err)
    } else {
        Ok(secret.assume_init())
    }
}

pub mod wasi_ephemeral_crypto_kx {
    use super::*;
    #[link(wasm_import_module = "wasi_ephemeral_crypto_kx")]
    extern "C" {
        /// Perform a simple Diffie-Hellman key exchange.
        ///
        /// Both keys must be of the same type, or else the `$crypto_errno.incompatible_keys` error is returned.
        /// The algorithm also has to support this kind of key exchange. If this is not the case, the `$crypto_errno.invalid_operation` error is returned.
        ///
        /// Otherwide, a raw shared key is returned, and can be imported as a symmetric key.
        /// ```
        pub fn kx_dh(pk: Publickey, sk: Secretkey, shared_secret: *mut ArrayOutput) -> CryptoErrno;
        /// Create a shared secret and encrypt it for the given public key.
        ///
        /// This operation is only compatible with specific algorithms.
        /// If a selected algorithm doesn't support it, `$crypto_errno.invalid_operation` is returned.
        ///
        /// On success, both the shared secret and its encrypted version are returned.
        pub fn kx_encapsulate(
            pk: Publickey,
            secret: *mut ArrayOutput,
            encapsulated_secret: *mut ArrayOutput,
        ) -> CryptoErrno;
        /// Decapsulate an encapsulated secret crated with `kx_encapsulate`
        ///
        /// Return the secret, or `$crypto_errno.verification_failed` on error.
        pub fn kx_decapsulate(
            sk: Secretkey,
            encapsulated_secret: *const u8,
            encapsulated_secret_len: Size,
            secret: *mut ArrayOutput,
        ) -> CryptoErrno;
    }
}
