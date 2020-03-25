use std::{io::Read, net::TcpStream, sync::Arc};

use ra_client::{EnclaveCertVerifier, EnclaveCertVerifierConfig};
use rustls::{ClientConfig, ClientSession, StreamOwned};
use webpki::DNSNameRef;

fn main() {
    env_logger::init();

    let addrs = "0.0.0.0:9090";
    let tcp_stream = TcpStream::connect(addrs).unwrap();

    let verifier_config = EnclaveCertVerifierConfig {
        signing_ca_cert_path: "./data/Intel_SGX_Attestation_RootCA.pem".into(),
        valid_enclave_quote_statuses: vec!["OK".into(), "GROUP_OUT_OF_DATE".into()].into(),
    };
    let verifier = EnclaveCertVerifier::new(verifier_config).unwrap();

    let tls_client_config: Arc<ClientConfig> = Arc::new(verifier.into());
    let session = ClientSession::new(
        &tls_client_config,
        DNSNameRef::try_from_ascii_str("localhost").unwrap(),
    );
    let mut stream = StreamOwned::new(session, tcp_stream);

    let mut sample = [0u8; 5];
    stream.read(&mut sample).unwrap();

    println!("Sample: {:?}", sample);
}
