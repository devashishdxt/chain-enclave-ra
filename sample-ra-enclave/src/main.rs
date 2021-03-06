use std::{
    convert::TryInto,
    io::{Read, Write},
    net::TcpListener,
    sync::Arc,
    thread,
};

use ra_enclave::{EnclaveRaConfig, EnclaveRaContext};
use rustls::{ServerConfig, ServerSession, StreamOwned};

fn main() {
    std::env::set_var("RUST_LOG", "debug");

    env_logger::init();

    let config = EnclaveRaConfig {
        sp_addr: "0.0.0.0:8989".to_string(),
        certificate_validity_secs: 86400,
    };

    let context = EnclaveRaContext::new(&config).unwrap();
    let certificate = context.get_certificate().unwrap();
    let tls_server_config: Arc<ServerConfig> = Arc::new(certificate.try_into().unwrap());

    log::info!("Successfully created certificate!");

    let addrs = "0.0.0.0:9090";
    log::info!("Starting TLS Server at: {}", addrs);

    let listener = TcpListener::bind(addrs).unwrap();

    for stream in listener.incoming() {
        let tls_server_config = tls_server_config.clone();

        thread::spawn(move || {
            let tls_session = ServerSession::new(&tls_server_config);
            let stream = StreamOwned::new(tls_session, stream.unwrap());

            handle_connection(stream);
        });
    }
}

fn handle_connection<T: Read + Write>(mut stream: T) {
    log::info!("Sending sample data!");
    stream.write(&[1u8; 5][..]).unwrap();
}
