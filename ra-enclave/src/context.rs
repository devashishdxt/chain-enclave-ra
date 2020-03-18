use sgx_isa::{Report, Targetinfo};
use thiserror::Error;

use crate::{
    cmac::{Cmac, CmacError},
    key_pair::KeyPair,
};

/// Wraps all the in-enclave operations required for remote attestation
pub struct EnclaveRaContext {
    key_pair: KeyPair,
}

impl EnclaveRaContext {
    /// Creates a new enclave remote attestation context
    pub fn new() -> Result<Self, EnclaveRaContextError> {
        let key_pair = KeyPair::new().ok_or_else(|| EnclaveRaContextError::KeyGenerationError)?;

        Ok(Self { key_pair })
    }

    /// Generates enclave report containing hash of public key of RA-TLS key-pair in user-data
    pub fn get_report(&self, target_info: &Targetinfo) -> Report {
        let public_key_hash = self.key_pair.public_key_hash();
        let mut report_data = [0; 64];
        (&mut report_data[0..32]).copy_from_slice(&public_key_hash);

        Report::for_target(target_info, &report_data)
    }

    /// Verifies the QE report
    pub fn verify_eq_report(qe_report: &Report) -> Result<(), EnclaveRaContextError> {
        qe_report
            .verify(|key, mac_data, mac| {
                let cmac = Cmac::new(key);
                cmac.verify(mac_data, mac)
            })
            .map_err(Into::into)
    }
}

#[derive(Debug, Error)]
pub enum EnclaveRaContextError {
    #[error("Error while generating new key pair")]
    KeyGenerationError,
    #[error("CMAC error while verifying report: {0}")]
    CmacError(#[from] CmacError),
}
