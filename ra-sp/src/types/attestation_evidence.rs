use serde::Serialize;

/// Attestation evidence submitted by SP to IAS
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationEvidence {
    /// Base64 encoded Quote structure generated by quoting enclave
    pub isv_enclave_quote: String,
    /// Base64 encoded SGX platform service security property descriptor
    pub pse_manifest: Option<String>,
    /// Custom nonce value provided by SP (max characters: 32)
    pub nonce: Option<String>,
}

impl AttestationEvidence {
    /// Creates attestation evidence from quote
    pub fn from_quote(quote: &[u8]) -> Self {
        Self {
            isv_enclave_quote: base64::encode(quote),
            pse_manifest: None,
            nonce: None,
        }
    }
}
