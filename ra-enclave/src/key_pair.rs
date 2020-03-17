use ring::{
    agreement::{EphemeralPrivateKey, PublicKey, ECDH_P256},
    rand::SystemRandom,
};
use sha2::{Digest, Sha256};

/// Holds a pair of ECDH (private, public) key based on the NSA Suite B P-256 (secp256r1) curve
///
/// # Note
///
/// The enclave generates a new public-private RA-TLS key pair at every startup. The key-pair need not be persisted
/// since generating a fresh key on startup is reasonably cheap.
///
/// RA-TLS links the RA-TLS key and enclave by including a hash of the RA-TLS public key as user-data into the Intel SGX
/// report.
pub struct KeyPair {
    private_key: EphemeralPrivateKey,
    public_key: PublicKey,
}

impl KeyPair {
    /// Creates a new key pair
    pub fn new() -> Option<Self> {
        let rng = SystemRandom::new();

        let private_key = EphemeralPrivateKey::generate(&ECDH_P256, &rng).ok()?;
        let public_key = private_key.compute_public_key().ok()?;

        Some(Self {
            private_key,
            public_key,
        })
    }

    /// Returns the SHA-256 hash of public key
    pub fn public_key_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.input(&self.public_key);
        hasher.result().into()
    }
}
