use ra_common::report::AttestationReport;
use ra_sp::{SpRaClient, SpRaClientError};
use sgx_isa::{Report, Targetinfo};
use thiserror::Error;

use crate::{
    cmac::{Cmac, CmacError},
    config::EnclaveRaConfig,
    key_pair::KeyPair,
};

/// Wraps all the in-enclave operations required for remote attestation
pub struct EnclaveRaContext {
    key_pair: KeyPair,
    sp_ra_client: SpRaClient,
}

impl EnclaveRaContext {
    /// Creates a new enclave remote attestation context
    pub fn new(config: &EnclaveRaConfig) -> Result<Self, EnclaveRaContextError> {
        let key_pair = KeyPair::new().ok_or_else(|| EnclaveRaContextError::KeyGenerationError)?;
        let sp_ra_client = SpRaClient::connect(&config.sp_addr)?;

        Ok(Self {
            key_pair,
            sp_ra_client,
        })
    }

    /// Generates attestation report for remote attestation
    pub fn get_attestation_report(&self) -> Result<AttestationReport, EnclaveRaContextError> {
        // Get target info from SP server
        let target_info_bytes = self.sp_ra_client.get_target_info()?;
        let target_info = Targetinfo::try_copy_from(&target_info_bytes)
            .ok_or_else(|| EnclaveRaContextError::InvalidTargetInfo)?;

        // Generate enclave report
        let report = self.get_report(&target_info);
        let report_bytes: &[u8] = report.as_ref();

        // Get quote and QE report from SP server
        let quote_result = self.sp_ra_client.get_quote(report_bytes.to_vec())?;
        let quote = quote_result.quote;
        let qe_report_bytes = quote_result.qe_report;

        // Verify QE report
        let qe_report = Report::try_copy_from(&qe_report_bytes)
            .ok_or_else(|| EnclaveRaContextError::InvalidQeReport)?;
        verify_report(&qe_report)?;

        // Get attestation report from SP server
        self.sp_ra_client
            .get_attestation_report(quote)
            .map_err(Into::into)
    }

    /// Generates enclave report containing hash of public key of RA-TLS key-pair in user-data
    fn get_report(&self, target_info: &Targetinfo) -> Report {
        let public_key_hash = self.key_pair.public_key_hash();
        let mut report_data = [0; 64];
        (&mut report_data[0..32]).copy_from_slice(&public_key_hash);

        Report::for_target(target_info, &report_data)
    }
}

/// Verifies the report
pub fn verify_report(report: &Report) -> Result<(), EnclaveRaContextError> {
    report
        .verify(|key, mac_data, mac| {
            let cmac = Cmac::new(key);
            cmac.verify(mac_data, mac)
        })
        .map_err(Into::into)
}

#[derive(Debug, Error)]
pub enum EnclaveRaContextError {
    #[error("CMAC error while verifying report: {0}")]
    CmacError(#[from] CmacError),
    #[error("Invalid target info received from SP server")]
    InvalidTargetInfo,
    #[error("Invalid QE report received from SP server")]
    InvalidQeReport,
    #[error("SP client error: {0}")]
    SpRaClientError(#[from] SpRaClientError),
    #[error("Error while generating new key pair")]
    KeyGenerationError,
}
