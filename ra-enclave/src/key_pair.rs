use ring::{
    pkcs8::Document,
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_ASN1_SIGNING},
};
use rustls::PrivateKey;
use sha2::{Digest, Sha256};

/// Holds a pair of ECDSA (private, public) key based on the NSA Suite B P-256 (secp256r1) curve
///
/// # Note
///
/// The enclave generates a new public-private RA-TLS key pair at every startup. The key-pair need not be persisted
/// since generating a fresh key on startup is reasonably cheap.
///
/// RA-TLS links the RA-TLS key and enclave by including a hash of the RA-TLS public key as user-data into the Intel SGX
/// report.
pub struct KeyPair {
    document: Document,
    key_pair: EcdsaKeyPair,
}

impl KeyPair {
    /// Creates a new key pair
    pub fn new() -> Option<Self> {
        let rng = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).ok()?;
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref()).ok()?;

        Some(Self { document, key_pair })
    }

    /// Returns the private key (for use in TLS server configuration)
    pub fn pkcs8(&self) -> Vec<u8> {
        self.document.as_ref().to_vec()
    }

    /// Returns the public key (for use in TLS certificate creation)
    pub fn public_key(&self) -> &[u8] {
        self.key_pair.public_key().as_ref()
    }

    /// Returns the SHA-256 hash of public key
    pub fn public_key_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.input(self.public_key());
        hasher.result().into()
    }
}
