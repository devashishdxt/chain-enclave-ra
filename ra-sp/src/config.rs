/// Configuration required by SP for remote attestation
#[derive(Debug)]
pub struct SpRaConfig {
    /// IAS API key
    pub ias_key: String,
    /// SPID
    pub spid: String,
    /// Quote type (possible values: `Linkable` or `Unlinkable`)
    pub quote_type: String,
}
