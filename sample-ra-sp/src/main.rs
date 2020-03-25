use ra_sp::{SpRaConfig, SpRaServer};

fn main() {
    env_logger::init();

    let config = SpRaConfig {
        ias_key: "<some key>".to_string(),
        spid: "<some key>".to_string(),
        quote_type: "Unlinkable".to_string(),
    };
    let address = "0.0.0.0:8989";

    let server = SpRaServer::new(config).unwrap();
    server.run(address).unwrap();
}
