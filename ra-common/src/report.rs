use serde::{Deserialize, Serialize};

/// Attestation verification report body returned by IAS to SP
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationReportBody {
    pub id: String,
    pub timestamp: String,
    pub version: u8,
    pub isv_enclave_quote_status: String,
    pub isv_enclave_quote_body: String,
    pub revocation_reason: Option<u64>,
    pub pse_manifest_status: Option<String>,
    pub pse_manifest_hash: Option<String>,
    pub platform_info_blob: Option<String>,
    pub nonce: Option<String>,
    pub epid_pseudonym: Option<String>,
    pub advisory_url: Option<String>,
    pub advisory_ids: Option<Vec<String>>,
}

/// Attestation verification report (containing report body, signature and signing certificate chain)
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationReport {
    pub body: AttestationReportBody,
    pub signature: Vec<u8>,
    pub signing_cert_chain: Vec<u8>,
}
