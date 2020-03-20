use chrono::{DateTime, Duration, Utc};
use rustls::{Certificate as RustlsCertificate, PrivateKey};

#[derive(Debug, Clone)]
/// Holds a X.509 certificate and its creation time
pub struct Certificate {
    /// X.509 certificate
    pub certificate: RustlsCertificate,
    /// Certificate creation time
    pub created: DateTime<Utc>,
    /// Private key used for signing certificate
    pub private_key: PrivateKey,
}

impl Certificate {
    /// Checks if current certificate is valid or not
    pub fn is_valid(&self, validity_duration: Duration) -> bool {
        let current_time = Utc::now();
        self.created + validity_duration >= current_time
    }
}
