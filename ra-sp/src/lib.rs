//! This crate provides typrs for running SP server (proxy for AESM and IAS) which can be used for Intel SGX remote
//! attestation.
//!
//! # Usage
//!
//! ```rust,no_run
//! use ra_sp::{SpRaConfig, SpRaServer};
//!
//! let config = SpRaConfig { ias_key: "<IAS Key>".to_string(), spid: "<SPID>".to_string() };
//! let address = "0.0.0.0:8989";
//!
//! let server = SpRaServer::new(config).unwrap();
//! server.run(address).unwrap();
//! ```
pub mod config;
pub mod context;
pub mod ias_client;
pub mod protocol;
pub mod server;
pub mod types;

pub use self::{
    config::SpRaConfig,
    server::{SpRaServer, SpRaServerError},
};
