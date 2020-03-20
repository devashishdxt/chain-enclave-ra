use std::sync::{Arc, Mutex};

use bincode::serialize;
use chrono::{Duration, Utc};
use ra_common::report::AttestationReport;
use ra_sp::{SpRaClient, SpRaClientError};
use rcgen::{
    Certificate as RcGenCertificate, CertificateParams, CustomExtension, DistinguishedName, DnType,
    IsCa, KeyPair, SanType, PKCS_ECDSA_P256_SHA256,
};
use rustls::{Certificate as RustlsCertificate, PrivateKey};
use sgx_isa::{Report, Targetinfo};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    certificate::Certificate,
    cmac::{Cmac, CmacError},
    config::EnclaveRaConfig,
};

static OID_EXTENSION: &[u64] = &[2, 16, 840, 1, 113_730, 1, 13];

/// Wraps all the in-enclave operations required for remote attestation
pub struct EnclaveRaContext {
    certificate: Arc<Mutex<Option<Certificate>>>,
    sp_ra_client: SpRaClient,
    validity_duration: Duration,
}

impl EnclaveRaContext {
    /// Creates a new enclave remote attestation context
    pub fn new(config: &EnclaveRaConfig) -> Result<Self, EnclaveRaContextError> {
        let sp_ra_client = SpRaClient::connect(&config.sp_addr)?;
        let validity_duration = Duration::seconds(config.certificate_validity_secs.into());

        Ok(Self {
            certificate: Default::default(),
            sp_ra_client,
            validity_duration,
        })
    }

    /// Returns current certificate. If current certificate is no longer valid, then it creates a new one
    pub fn get_certificate(&self) -> Result<Certificate, EnclaveRaContextError> {
        let mut certificate = self.certificate.lock().unwrap();

        let needs_creating = match *certificate {
            None => true,
            Some(ref certificate) => !certificate.is_valid(self.validity_duration),
        };

        if needs_creating {
            let new_certificate = self.create_certificate();

            match new_certificate {
                Ok(new_certificate) => {
                    log::info!("Successfully created new certificate for remote attestation");
                    *certificate = Some(new_certificate);
                }
                Err(e) => {
                    // If the certificate generation fails, we do not crash and keep using the old certificate
                    // (if available) and client can decide if they want to use the old certificate. Every certificate
                    // has a 90 days valid duration. If certificate creation fails for 90 days, the enclave itself will
                    // not serve any client.
                    log::error!("Failed to create new certificate: {}", e);
                }
            }
        }

        match *certificate {
            Some(ref certificate) => Ok(certificate.clone()),
            None => Err(EnclaveRaContextError::CertificateCreationError),
        }
    }

    /// Generates attestation report for remote attestation
    fn get_attestation_report(
        &self,
        public_key_hash: [u8; 32],
    ) -> Result<AttestationReport, EnclaveRaContextError> {
        // Get target info from SP server
        let target_info_bytes = self.sp_ra_client.get_target_info()?;
        let target_info = Targetinfo::try_copy_from(&target_info_bytes)
            .ok_or_else(|| EnclaveRaContextError::InvalidTargetInfo)?;

        // Generate enclave report
        let report = self.get_report(&target_info, public_key_hash)?;
        let report_bytes: &[u8] = report.as_ref();

        // Get quote and QE report from SP server
        let quote_result = self.sp_ra_client.get_quote(report_bytes.to_vec())?;
        let quote = quote_result.quote;
        let qe_report_bytes = quote_result.qe_report;

        // Verify QE report
        let qe_report = Report::try_copy_from(&qe_report_bytes)
            .ok_or_else(|| EnclaveRaContextError::InvalidQeReport)?;
        verify_qe_report(&qe_report, &target_info)?;

        // Get attestation report from SP server
        self.sp_ra_client
            .get_attestation_report(quote)
            .map_err(Into::into)
    }

    /// Generates enclave report containing hash of public key of RA-TLS key-pair in user-data
    fn get_report(
        &self,
        target_info: &Targetinfo,
        public_key_hash: [u8; 32],
    ) -> Result<Report, EnclaveRaContextError> {
        let mut report_data = [0; 64];
        (&mut report_data[0..32]).copy_from_slice(&public_key_hash);

        Ok(Report::for_target(target_info, &report_data))
    }

    /// Creates new certificate
    fn create_certificate(&self) -> Result<Certificate, EnclaveRaContextError> {
        let certificate_params = self.create_certificate_params()?;

        let private_key = PrivateKey(
            certificate_params
                .key_pair
                .as_ref()
                .ok_or_else(|| EnclaveRaContextError::MissingKeyPair)?
                .serialize_der(),
        );
        let created = certificate_params.not_before;
        let rustls_certificate =
            RustlsCertificate(RcGenCertificate::from_params(certificate_params)?.serialize_der()?);

        Ok(Certificate {
            certificate: rustls_certificate,
            created,
            private_key,
        })
    }

    /// Creates new certificate params
    fn create_certificate_params(&self) -> Result<CertificateParams, EnclaveRaContextError> {
        let mut certificate_params = CertificateParams::default();

        certificate_params.alg = &PKCS_ECDSA_P256_SHA256;

        let current_time = Utc::now();
        certificate_params.not_before = current_time;
        certificate_params.not_after = current_time + Duration::days(90);

        certificate_params.subject_alt_names =
            vec![SanType::Rfc822Name("security@crypto.com".to_string())];

        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::OrganizationName, "Crypto.com");
        distinguished_name.push(DnType::CommonName, "Crypto.com");
        certificate_params.distinguished_name = distinguished_name;

        certificate_params.is_ca = IsCa::SelfSignedOnly;

        let key_pair = KeyPair::generate(&PKCS_ECDSA_P256_SHA256)?;

        let attestation_report = self.get_attestation_report(sha256(key_pair.public_key_raw()))?;
        certificate_params.custom_extensions = vec![CustomExtension::from_oid_content(
            OID_EXTENSION,
            serialize(&attestation_report)?,
        )];

        certificate_params.key_pair = Some(key_pair);

        Ok(certificate_params)
    }
}

/// Verifies QE report
fn verify_qe_report(
    report: &Report,
    target_info: &Targetinfo,
) -> Result<(), EnclaveRaContextError> {
    // Check if the QE report is valid
    verify_report(report)?;

    // Check if the qe_report is produced on the same platform
    if target_info.measurement != report.mrenclave || target_info.attributes != report.attributes {
        return Err(EnclaveRaContextError::InvalidQeReport);
    }

    Ok(())
}

/// Verifies the report
fn verify_report(report: &Report) -> Result<(), EnclaveRaContextError> {
    report
        .verify(|key, mac_data, mac| {
            let cmac = Cmac::new(key);
            cmac.verify(mac_data, mac)
        })
        .map_err(Into::into)
}

fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.input(input);
    hasher.result().into()
}

#[derive(Debug, Error)]
pub enum EnclaveRaContextError {
    #[error("Bincode error: {0}")]
    BincodeError(#[from] bincode::Error),
    #[error("Unable to create new certificate")]
    CertificateCreationError,
    #[error("CMAC error while verifying report: {0}")]
    CmacError(#[from] CmacError),
    #[error("Invalid target info received from SP server")]
    InvalidTargetInfo,
    #[error("Invalid QE report received from SP server")]
    InvalidQeReport,
    #[error("Key pair in certificate parameters not found")]
    MissingKeyPair,
    #[error("Certificate generateion error: {0}")]
    RcGenError(#[from] rcgen::RcgenError),
    #[error("SP client error: {0}")]
    SpRaClientError(#[from] SpRaClientError),
}
