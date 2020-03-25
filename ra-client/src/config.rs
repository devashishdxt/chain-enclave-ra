use std::borrow::Cow;

pub struct EnclaveCertVerifierConfig<'a> {
    /// Path to PEM file containing attestation report signing CA certificate
    pub signing_ca_cert_path: Cow<'a, str>,
    /// List of all the enclave quote statuses which should be marked as valid
    pub valid_enclave_quote_statuses: Cow<'a, [Cow<'a, str>]>,
}
