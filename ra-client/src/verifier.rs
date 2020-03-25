use std::{collections::HashSet, fs::read, sync::Arc, time::SystemTime};

use der_parser::oid::Oid;
use ra_common::report::{
    AttestationReport, AttestationReportBody, OID_EXTENSION_ATTESTATION_REPORT,
};
use rustls::{
    internal::pemfile::certs, Certificate, ClientConfig, RootCertStore, ServerCertVerified,
    ServerCertVerifier, TLSError,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use webpki::{
    DNSNameRef, EndEntityCert, SignatureAlgorithm, TLSServerTrustAnchors, Time, TrustAnchor,
    ECDSA_P256_SHA256, RSA_PKCS1_2048_8192_SHA256,
};
use x509_parser::parse_x509_der;

use crate::EnclaveCertVerifierConfig;

static SUPPORTED_SIG_ALGS: &[&SignatureAlgorithm] = &[&ECDSA_P256_SHA256];

pub struct EnclaveCertVerifier {
    root_cert_store: RootCertStore,
    valid_enclave_quote_statuses: HashSet<String>,
}

impl EnclaveCertVerifier {
    /// Creates a new instance of enclave certificate verifier
    pub fn new<'a>(
        config: EnclaveCertVerifierConfig<'a>,
    ) -> Result<Self, EnclaveCertVerifierError> {
        let signing_ca_cert_pem = read(config.signing_ca_cert_path.as_ref())?;

        let mut root_cert_store = RootCertStore::empty();
        root_cert_store
            .add_pem_file(&mut signing_ca_cert_pem.as_ref())
            .map_err(|_| EnclaveCertVerifierError::CertificateParsingError)?;

        let mut valid_enclave_quote_statuses =
            HashSet::with_capacity(config.valid_enclave_quote_statuses.as_ref().len());

        for status in config.valid_enclave_quote_statuses.as_ref() {
            valid_enclave_quote_statuses.insert(status.clone().into_owned());
        }

        Ok(Self {
            root_cert_store,
            valid_enclave_quote_statuses,
        })
    }

    /// Verifies certificate
    fn verify_cert(&self, certificate: &[u8]) -> Result<(), EnclaveCertVerifierError> {
        let (_, certificate) = parse_x509_der(certificate)
            .map_err(|_| EnclaveCertVerifierError::CertificateParsingError)?;

        if certificate
            .tbs_certificate
            .validity
            .time_to_expiration()
            .is_none()
        {
            return Err(EnclaveCertVerifierError::CertificateExpired);
        }

        let attestation_report_oid = Oid::from(OID_EXTENSION_ATTESTATION_REPORT);
        let mut attestation_report_received = false;

        let public_key_hash = sha256(
            certificate
                .tbs_certificate
                .subject_pki
                .subject_public_key
                .data
        );

        for extension in certificate.tbs_certificate.extensions {
            if extension.oid == attestation_report_oid {
                attestation_report_received = true;
                self.verify_attestation_report(extension.value, public_key_hash)?;
            }
        }

        if attestation_report_received {
            Ok(())
        } else {
            Err(EnclaveCertVerifierError::MissingAttestationReport)
        }
    }

    /// Verifies attestation report
    fn verify_attestation_report(
        &self,
        attestation_report: &[u8],
        public_key_hash: [u8; 32],
    ) -> Result<(), EnclaveCertVerifierError> {
        log::info!("Verifying attestation report");

        let trust_anchors: Vec<TrustAnchor> = self
            .root_cert_store
            .roots
            .iter()
            .map(|cert| cert.to_trust_anchor())
            .collect();
        let time =
            Time::try_from(SystemTime::now()).map_err(|_| EnclaveCertVerifierError::TimeError)?;

        let attestation_report: AttestationReport = bincode::deserialize(attestation_report)?;

        let signing_certs = certs(&mut attestation_report.signing_cert.as_ref())
            .map_err(|_| EnclaveCertVerifierError::CertificateParsingError)?;

        for signing_cert in signing_certs {
            let signing_cert = EndEntityCert::from(&signing_cert.0)?;

            signing_cert.verify_is_valid_tls_server_cert(
                SUPPORTED_SIG_ALGS,
                &TLSServerTrustAnchors(&trust_anchors),
                &[],
                time,
            )?;

            signing_cert.verify_signature(
                &RSA_PKCS1_2048_8192_SHA256,
                &attestation_report.body,
                &attestation_report.signature,
            )?;
        }

        self.verify_attestation_report_body(&attestation_report.body, public_key_hash)?;

        log::info!("Attestation report is valid!");
        Ok(())
    }

    fn verify_attestation_report_body(
        &self,
        attestation_report_body: &[u8],
        public_key_hash: [u8; 32],
    ) -> Result<(), EnclaveCertVerifierError> {
        let attestation_report_body: AttestationReportBody =
            serde_json::from_slice(attestation_report_body)?;

        if !self
            .valid_enclave_quote_statuses
            .contains(&attestation_report_body.isv_enclave_quote_status)
        {
            return Err(EnclaveCertVerifierError::InvalidEnclaveQuoteStatus(
                attestation_report_body.isv_enclave_quote_status,
            ));
        }

        let quote = attestation_report_body.get_quote()?;

        if &quote.report_body.report_data[..32] != &public_key_hash {
            return Err(EnclaveCertVerifierError::PublicKeyHashMismatch);
        }

        Ok(())
    }
}

impl ServerCertVerifier for EnclaveCertVerifier {
    fn verify_server_cert(
        &self,
        _roots: &RootCertStore,
        presented_certs: &[Certificate],
        _dns_name: DNSNameRef,
        _ocsp_response: &[u8],
    ) -> Result<ServerCertVerified, TLSError> {
        if presented_certs.is_empty() {
            return Err(TLSError::NoCertificatesPresented);
        }

        for cert in presented_certs {
            self.verify_cert(&cert.0)?;
        }

        Ok(ServerCertVerified::assertion())
    }
}

impl From<EnclaveCertVerifier> for ClientConfig {
    fn from(verifier: EnclaveCertVerifier) -> Self {
        let mut config = Self::new();
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(verifier));
        config
    }
}

fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.input(input);
    hasher.result().into()
}

#[derive(Debug, Error)]
pub enum EnclaveCertVerifierError {
    #[error("Bincode error: {0}")]
    BincodeError(#[from] bincode::Error),
    #[error("Enclave certificate expired")]
    CertificateExpired,
    #[error("Failed to parse server certificate")]
    CertificateParsingError,
    #[error("Invalid enclave quote status: {0}")]
    InvalidEnclaveQuoteStatus(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Attestation report not available in server certificate")]
    MissingAttestationReport,
    #[error("Hash of public key in certificate does not match with the one in enclave quote")]
    PublicKeyHashMismatch,
    #[error("Unable to parse quote from attestation report body: {0}")]
    QuoteParsingError(#[from] ra_common::report::QuoteParsingError),
    #[error("Unable to get current time")]
    TimeError,
    #[error("Webpki error: {0}")]
    WebpkiError(#[from] webpki::Error),
}

impl From<EnclaveCertVerifierError> for TLSError {
    fn from(e: EnclaveCertVerifierError) -> Self {
        TLSError::General(e.to_string())
    }
}
