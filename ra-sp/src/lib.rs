//! This crate provides typrs for running SP server (proxy for AESM and IAS) which can be used for Intel SGX remote
//! attestation.
//!
//! # Usage
//!
//! This crate can be used in two modes: `server` and `client` which can be enabled by their respective Cargo features.
//!
//! ## Running SP server for remote attestation (`"server"` feature must be enabled)
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
//!
//! ## Calling SP server to get attestation report (`"client"` feature must be enabled)
//!
//! ```rust,no_run
//! use ra_sp::SpRaClient;
//!
//! let address = "0.0.0.0:8989";
//! let client = SpRaClient::connect(address).unwrap();
//!
//! let target_info = client.get_target_info().unwrap();
//!
//! // Generate a enclave report using received target info
//! let report = vec![];
//!
//! let quote_result = client.get_quote(report).unwrap();
//!
//! // Verify the QE report in `quote_result`
//! let attestation_report = client.get_attestation_report(quote_result.quote).unwrap();
//! ```
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "server")]
pub mod config;
#[cfg(feature = "server")]
pub mod context;
#[cfg(feature = "server")]
pub mod ias_client;
pub mod protocol;
#[cfg(feature = "server")]
pub mod server;
pub mod types;

#[cfg(feature = "client")]
pub use self::client::SpRaClient;
#[cfg(feature = "server")]
pub use self::{
    config::SpRaConfig,
    server::{SpRaServer, SpRaServerError},
};
