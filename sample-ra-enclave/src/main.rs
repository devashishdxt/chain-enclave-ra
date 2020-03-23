use ra_enclave::{EnclaveRaConfig, EnclaveRaContext};

fn main() {
    let config = EnclaveRaConfig {
        sp_addr: "0.0.0.0:8989".to_string(),
        certificate_validity_secs: 86400,
    };

    let context = EnclaveRaContext::new(&config).unwrap();
    let certificate = context.get_certificate().unwrap();
}
