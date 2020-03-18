#[cfg(feature = "server")]
mod attestation_evidence;
#[cfg(any(feature = "client", feature = "server"))]
mod quote_result;

#[cfg(feature = "server")]
pub use self::attestation_evidence::AttestationEvidence;
#[cfg(any(feature = "client", feature = "server"))]
pub use self::quote_result::QuoteResult;
