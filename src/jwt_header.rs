use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct JWTHeader {
    #[serde(rename = "alg")]
    pub algorithm: String,

    #[serde(rename = "cty")]
    pub content_type: Option<String>,

    #[serde(rename = "jku", default, skip_serializing_if = "Option::is_none")]
    pub key_set_url: Option<String>,

    #[serde(rename = "jwk", default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,

    #[serde(rename = "kid", default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    #[serde(rename = "x5u", default, skip_serializing_if = "Option::is_none")]
    pub certificate_url: Option<String>,

    #[serde(rename = "x5c", default, skip_serializing_if = "Option::is_none")]
    pub certificate_chain: Option<String>,

    #[serde(rename = "x5t", default, skip_serializing_if = "Option::is_none")]
    pub certificate_sha1_thumbprint: Option<String>,

    #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]
    pub certificate_sha256_thumbprint: Option<String>,

    #[serde(rename = "typ", default, skip_serializing_if = "Option::is_none")]
    pub signature_type: Option<String>,

    #[serde(rename = "crit", default, skip_serializing_if = "Option::is_none")]
    pub critical: Option<String>,
}

impl Default for JWTHeader {
    fn default() -> Self {
        JWTHeader {
            algorithm: "Not set".to_string(),
            content_type: None,
            key_set_url: None,
            public_key: None,
            key_id: None,
            certificate_url: None,
            certificate_chain: None,
            certificate_sha1_thumbprint: None,
            certificate_sha256_thumbprint: None,
            signature_type: Some("JWT".to_string()),
            critical: None,
        }
    }
}
