#[cfg(feature = "server")]
mod attestation_evidence;
mod attestation_report;
mod quote_result;

#[cfg(feature = "server")]
pub use self::attestation_evidence::AttestationEvidence;
pub use self::{
    attestation_report::{AttestationReport, AttestationReportBody},
    quote_result::QuoteResult,
};
