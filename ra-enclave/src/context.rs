use sgx_isa::{Report, Targetinfo};
use thiserror::Error;

use crate::key_pair::KeyPair;

/// Wraps all the in-enclave operations required for remote attestation
pub struct EnclaveRaContext {
    key_pair: KeyPair,
}

impl EnclaveRaContext {
    /// Creates a new enclave context
    pub fn new() -> Result<Self, EnclaveRaContextError> {
        let key_pair = KeyPair::new().ok_or_else(|| EnclaveRaContextError::KeyGenerationError)?;

        Ok(Self { key_pair })
    }

    pub fn get_report() -> Report {
        let target_info = Targetinfo::from(Report::for_self());
    }
}

#[derive(Debug, Error)]
pub enum EnclaveRaContextError {
    #[error("Error while generating new key pair")]
    KeyGenerationError,
}
