use serde::{Deserialize, Serialize};

use crate::common::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct JWTHeader {
    #[serde(rename = "alg")]
    pub(crate) algorithm: String,

    #[serde(rename = "cty", default, skip_serializing_if = "Option::is_none")]
    pub(crate) content_type: Option<String>,

    #[serde(rename = "kid", default, skip_serializing_if = "Option::is_none")]
    pub(crate) key_id: Option<String>,

    #[serde(rename = "typ", default, skip_serializing_if = "Option::is_none")]
    pub(crate) signature_type: Option<String>,

    #[serde(rename = "crit", default, skip_serializing_if = "Option::is_none")]
    pub(crate) critical: Option<Vec<String>>,

    #[serde(rename = "x5c", default, skip_serializing_if = "Option::is_none")]
    pub(crate) certificate_chain: Option<Vec<String>>,

    #[serde(rename = "jku", default, skip_serializing_if = "Option::is_none")]
    pub key_set_url: Option<String>,

    #[serde(rename = "jwk", default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,

    #[serde(rename = "x5u", default, skip_serializing_if = "Option::is_none")]
    pub certificate_url: Option<String>,

    #[serde(rename = "x5t", default, skip_serializing_if = "Option::is_none")]
    pub certificate_sha1_thumbprint: Option<String>,

    #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]
    pub certificate_sha256_thumbprint: Option<String>,
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

impl JWTHeader {
    pub(crate) fn new(algorithm: String, key_id: Option<String>) -> Self {
        JWTHeader {
            algorithm,
            key_id,
            ..Default::default()
        }
    }

    pub(crate) fn with_metadata(mut self, metadata: &Option<KeyMetadata>) -> Self {
        let metadata = match metadata {
            None => return self,
            Some(metadata) => metadata,
        };
        if self.key_set_url.is_none() {
            self.key_set_url = metadata.key_set_url.clone();
        }
        if self.public_key.is_none() {
            self.public_key = metadata.public_key.clone();
        }
        if self.certificate_url.is_none() {
            self.certificate_url = metadata.certificate_url.clone();
        }
        if self.certificate_sha1_thumbprint.is_none() {
            self.certificate_sha1_thumbprint = metadata.certificate_sha1_thumbprint.clone();
        }
        if self.certificate_sha256_thumbprint.is_none() {
            self.certificate_sha256_thumbprint = metadata.certificate_sha256_thumbprint.clone();
        }
        self
    }
}
