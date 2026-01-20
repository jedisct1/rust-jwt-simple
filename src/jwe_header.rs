use serde::{Deserialize, Serialize};

/// JWE (JSON Web Encryption) header structure.
///
/// This header identifies the cryptographic algorithms used to encrypt
/// the content encryption key (CEK) and the plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWEHeader {
    /// Key management algorithm (e.g., "RSA-OAEP", "A256KW", "ECDH-ES+A256KW")
    #[serde(rename = "alg")]
    pub algorithm: String,

    /// Content encryption algorithm (e.g., "A256GCM", "A128GCM")
    #[serde(rename = "enc")]
    pub encryption: String,

    /// Key ID - identifies which key was used for encryption
    #[serde(rename = "kid", default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    /// Token type (typically "JWE" or omitted)
    #[serde(rename = "typ", default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,

    /// Content type - describes the media type of the encrypted content
    #[serde(rename = "cty", default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    /// Ephemeral public key (for ECDH key agreement)
    #[serde(rename = "epk", default, skip_serializing_if = "Option::is_none")]
    pub ephemeral_public_key: Option<serde_json::Value>,

    /// Agreement PartyUInfo (for ECDH)
    #[serde(rename = "apu", default, skip_serializing_if = "Option::is_none")]
    pub apu: Option<String>,

    /// Agreement PartyVInfo (for ECDH)
    #[serde(rename = "apv", default, skip_serializing_if = "Option::is_none")]
    pub apv: Option<String>,

    /// Initialization vector (for AES-GCM key wrap)
    #[serde(rename = "iv", default, skip_serializing_if = "Option::is_none")]
    pub iv: Option<String>,

    /// Authentication tag (for AES-GCM key wrap)
    #[serde(rename = "tag", default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// PBES2 salt (not used - PBES2 not supported)
    #[serde(rename = "p2s", default, skip_serializing_if = "Option::is_none")]
    pub p2s: Option<String>,

    /// PBES2 iteration count (not used - PBES2 not supported)
    #[serde(rename = "p2c", default, skip_serializing_if = "Option::is_none")]
    pub p2c: Option<u32>,

    /// Critical headers that must be understood
    #[serde(rename = "crit", default, skip_serializing_if = "Option::is_none")]
    pub critical: Option<Vec<String>>,

    /// X.509 certificate chain
    #[serde(rename = "x5c", default, skip_serializing_if = "Option::is_none")]
    pub certificate_chain: Option<Vec<String>>,

    /// X.509 certificate URL
    #[serde(rename = "x5u", default, skip_serializing_if = "Option::is_none")]
    pub certificate_url: Option<String>,

    /// X.509 certificate SHA-1 thumbprint
    #[serde(rename = "x5t", default, skip_serializing_if = "Option::is_none")]
    pub certificate_sha1_thumbprint: Option<String>,

    /// X.509 certificate SHA-256 thumbprint
    #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]
    pub certificate_sha256_thumbprint: Option<String>,

    /// JWK Set URL
    #[serde(rename = "jku", default, skip_serializing_if = "Option::is_none")]
    pub key_set_url: Option<String>,

    /// Embedded JWK public key
    #[serde(rename = "jwk", default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<serde_json::Value>,
}

impl JWEHeader {
    /// Create a new JWE header with the specified algorithms.
    pub fn new(algorithm: impl Into<String>, encryption: impl Into<String>) -> Self {
        JWEHeader {
            algorithm: algorithm.into(),
            encryption: encryption.into(),
            key_id: None,
            token_type: None,
            content_type: None,
            ephemeral_public_key: None,
            apu: None,
            apv: None,
            iv: None,
            tag: None,
            p2s: None,
            p2c: None,
            critical: None,
            certificate_chain: None,
            certificate_url: None,
            certificate_sha1_thumbprint: None,
            certificate_sha256_thumbprint: None,
            key_set_url: None,
            public_key: None,
        }
    }

    /// Set the key ID.
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Set the content type.
    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Set the ephemeral public key (for ECDH).
    pub fn with_ephemeral_public_key(mut self, epk: serde_json::Value) -> Self {
        self.ephemeral_public_key = Some(epk);
        self
    }
}

impl Default for JWEHeader {
    fn default() -> Self {
        JWEHeader::new("RSA-OAEP", "A256GCM")
    }
}
