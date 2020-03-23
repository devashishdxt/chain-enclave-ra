use rustls::{Certificate, RootCertStore, ServerCertVerified, ServerCertVerifier, TLSError};
use thiserror::Error;
use webpki::DNSNameRef;
use x509_parser::parse_x509_der;

pub struct EnclaveCertVerifier {
    /// time provider
    pub time: fn() -> Result<webpki::Time, TLSError>,
}

impl EnclaveCertVerifier {
    /// Creates a new enclave certificate verifier
    pub fn new() -> Self {
        Self { time: try_now }
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
            verify_cert(&cert.0)?;
        }

        Ok(ServerCertVerified::assertion())
    }
}

fn verify_cert(certificate: &[u8]) -> Result<(), EnclaveCertVerifierError> {
    let (_, certificate) = parse_x509_der(certificate)
        .map_err(|_| EnclaveCertVerifierError::CertificateParsingError)?;
    todo!()
}

#[derive(Debug, Error)]
pub enum EnclaveCertVerifierError {
    #[error("Failed to parse certificate")]
    CertificateParsingError,
}

impl From<EnclaveCertVerifierError> for TLSError {
    fn from(e: EnclaveCertVerifierError) -> Self {
        TLSError::General(e.to_string())
    }
}
