#![forbid(unsafe_code)]

pub mod claims;
pub mod common;
pub mod eddsa;
pub mod error;
pub mod es256;
pub mod es256k;
pub mod hmac;
pub mod rsa;
pub mod token;

mod jwt_header;
mod serde_additions;

pub use coarsetime;
pub use serde;

pub mod prelude {
    pub use crate::claims::*;
    pub use crate::common::*;
    pub use crate::eddsa::*;
    pub use crate::error::Error;
    pub use crate::es256::*;
    pub use crate::es256k::*;
    pub use crate::hmac::*;
    pub use crate::rsa::*;
    pub use crate::token::*;
    pub use coarsetime::{self, Clock, Duration, UnixTimeStamp};
    pub use serde::{Deserialize, Serialize};
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[test]
    fn hs384() {
        let key = HS384Key::from_bytes(b"your-256-bit-secret").with_key_id("my-key-id");
        let mut claims = Claims::create(Duration::from_secs(86400));
        claims.issuer = Some("test issuer".to_string());
        let token = key.authenticate(claims).unwrap();
        let mut options = VerificationOptions::default();
        options.required_issuer = Some("test issuer".to_string());
        let _claims = key
            .verify_token::<NoCustomClaims>(&token, Some(options))
            .unwrap();
    }

    #[test]
    fn ps384() {
        let key_pair = PS384KeyPair::generate(2048).unwrap();
        let claims = Claims::create(Duration::from_secs(86400));
        let token = key_pair.sign(claims).unwrap();
        let _claims = key_pair
            .public_key()
            .verify_token::<NoCustomClaims>(&token, None)
            .unwrap();
    }

    #[test]
    fn es256() {
        let key_pair = ES256KeyPair::generate();
        let claims = Claims::create(Duration::from_secs(86400));
        let token = key_pair.sign(claims).unwrap();
        let _claims = key_pair
            .public_key()
            .verify_token::<NoCustomClaims>(&token, None)
            .unwrap();
    }

    #[test]
    fn es256k() {
        let key_pair = ES256kKeyPair::generate();
        let claims = Claims::create(Duration::from_secs(86400));
        let token = key_pair.sign(claims).unwrap();
        let _claims = key_pair
            .public_key()
            .verify_token::<NoCustomClaims>(&token, None)
            .unwrap();
    }

    #[test]
    fn ed25519() {
        #[derive(Serialize, Deserialize)]
        struct CustomClaims {
            is_custom: bool,
        }

        let key_pair = Ed25519KeyPair::generate();
        let mut pk = key_pair.public_key();
        let key_id = pk.create_key_id();
        let key_pair = key_pair.with_key_id(key_id);
        let custom_claims = CustomClaims { is_custom: true };
        let claims = Claims::with_custom_claims(custom_claims, Duration::from_secs(86400));
        let token = key_pair.sign(claims).unwrap();
        let mut options = VerificationOptions::default();
        options.required_key_id = Some(key_id.to_string());
        let claims: JWTClaims<CustomClaims> = key_pair
            .public_key()
            .verify_token::<CustomClaims>(&token, None)
            .unwrap();
        assert!(claims.custom.is_custom, true);
    }
}
