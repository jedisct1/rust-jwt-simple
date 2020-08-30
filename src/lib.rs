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

    const RSA_KP_PEM: &str = r"
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyqq0N5u8Jvl+BLH2VMP/NAv/zY9T8mSq0V2Gk5Ql5H1a+4qi
3viorUXG3AvIEEccpLsW85ps5+I9itp74jllRjA5HG5smbb+Oym0m2Hovfj6qP/1
m1drQg8oth6tNmupNqVzlGGWZLsSCBLuMa3pFaPhoxl9lGU3XJIQ1/evMkOb98I3
hHb4ELn3WGtNlAVkbP20R8sSii/zFjPqrG/NbSPLyAl1ctbG2d8RllQF1uRIqYQj
85yx73hqQCMpYWU3d9QzpkLf/C35/79qNnSKa3t0cyDKinOY7JGIwh8DWAa4pfEz
gg56yLcilYSSohXeaQV0nR8+rm9J8GUYXjPK7wIDAQABAoIBAQCpeRPYyHcPFGTH
4lU9zuQSjtIq/+bP9FRPXWkS8bi6GAVEAUtvLvpGYuoGyidTTVPrgLORo5ncUnjq
KwebRimlBuBLIR/Zboery5VGthoc+h4JwniMnQ6JIAoIOSDZODA5DSPYeb58n15V
uBbNHkOiH/eoHsG/nOAtnctN/cXYPenkCfeLXa3se9EzkcmpNGhqCBL/awtLU17P
Iw7XxsJsRMBOst4Aqiri1GQI8wqjtXWLyfjMpPR8Sqb4UpTDmU1wHhE/w/+2lahC
Tu0/+sCWj7TlafYkT28+4pAMyMqUT6MjqdmGw8lD7/vXv8TF15NU1cUv3QSKpVGe
50vlB1QpAoGBAO1BU1evrNvA91q1bliFjxrH3MzkTQAJRMn9PBX29XwxVG7/HlhX
0tZRSR92ZimT2bAu7tH0Tcl3Bc3NwEQrmqKlIMqiW+1AVYtNjuipIuB7INb/TUM3
smEh+fn3yhMoVxbbh/klR1FapPUFXlpNv3DJHYM+STqLMhl9tEc/I7bLAoGBANqt
zR6Kovf2rh7VK/Qyb2w0rLJE7Zh/WI+r9ubCba46sorqkJclE5cocxWuTy8HWyQp
spxzLP1FQlsI+MESgRLueoH3HtB9lu/pv6/8JlNjU6SzovfUZ0KztVUyUeB4vAcH
pGcf2CkUtoYc8YL22Ybck3s8ThIdnY5zphCF55PtAoGAf46Go3c05XVKx78R05AD
D2/y+0mnSGSzUjHPMzPyadIPxhltlCurlERhnwPGC4aNHFcvWTwS8kUGns6HF1+m
JNnI1okSCW10UI/jTJ1avfwU/OKIBKKWSfi9cDJTt5cRs51V7pKnVEr6sy0uvDhe
u+G091HuhwY9ak0WNtPwfJ8CgYEAuRdoyZQQso7x/Bj0tiHGW7EOB2n+LRiErj6g
odspmNIH8zrtHXF9bnEHT++VCDpSs34ztuZpywnHS2SBoHH4HD0MJlszksbqbbDM
1bk3+1bUIlEF/Hyk1jljn3QTB0tJ4y1dwweaH9NvVn7DENW9cr/aePGnJwA4Lq3G
fq/IPlUCgYAuqgJQ4ztOq0EaB75xgqtErBM57A/+lMWS9eD/euzCEO5UzWVaiIJ+
nNDmx/jvSrxA1Ih8TEHjzv4ezLFYpaJrTst4Mjhtx+csXRJU9a2W6HMXJ4Kdn8rk
PBziuVURslNyLdlFsFlm/kfvX+4Cxrbb+pAGETtRTgmAoCDbvuDGRQ==
-----END RSA PRIVATE KEY-----
    ";

    const RSA_PK_PEM: &str = r"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyqq0N5u8Jvl+BLH2VMP/
NAv/zY9T8mSq0V2Gk5Ql5H1a+4qi3viorUXG3AvIEEccpLsW85ps5+I9itp74jll
RjA5HG5smbb+Oym0m2Hovfj6qP/1m1drQg8oth6tNmupNqVzlGGWZLsSCBLuMa3p
FaPhoxl9lGU3XJIQ1/evMkOb98I3hHb4ELn3WGtNlAVkbP20R8sSii/zFjPqrG/N
bSPLyAl1ctbG2d8RllQF1uRIqYQj85yx73hqQCMpYWU3d9QzpkLf/C35/79qNnSK
a3t0cyDKinOY7JGIwh8DWAa4pfEzgg56yLcilYSSohXeaQV0nR8+rm9J8GUYXjPK
7wIDAQAB
-----END PUBLIC KEY-----
    ";

    #[test]
    fn hs384() {
        let key = HS384Key::from_bytes(b"your-256-bit-secret").with_key_id("my-key-id");
        let claims = Claims::create(Duration::from_secs(86400)).with_issuer("test issuer");
        let token = key.authenticate(claims).unwrap();
        let mut options = VerificationOptions::default();
        options.required_issuer = Some("test issuer".to_string());
        let _claims = key
            .verify_token::<NoCustomClaims>(&token, Some(options))
            .unwrap();
    }

    #[test]
    fn rs256() {
        let key_pair = RS256KeyPair::from_pem(RSA_KP_PEM).unwrap();
        let claims = Claims::create(Duration::from_secs(86400));
        let token = key_pair.sign(claims).unwrap();
        let pk = RS256PublicKey::from_pem(RSA_PK_PEM).unwrap();
        let _claims = pk.verify_token::<NoCustomClaims>(&token, None).unwrap();
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
