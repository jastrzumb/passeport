use data_encoding::BASE32;
use ed25519_dalek::SigningKey;
use sha3::{Digest, Sha3_256};

use crate::error::Error;

pub struct OnionKeys {
    /// The .onion address (without .onion suffix).
    pub hostname: String,
    /// Full .onion address (with suffix).
    pub address: String,
    /// Tor-format secret key file contents (header + expanded key).
    pub secret_key_file: Vec<u8>,
    /// Tor-format public key file contents (header + public key).
    pub public_key_file: Vec<u8>,
}

/// Generate a Tor v3 onion service identity from a 32-byte Ed25519 seed.
///
/// The .onion address is: base32(pubkey || checksum || version)
/// where checksum = SHA3-256(".onion checksum" || pubkey || version)[0..2]
/// and version = 0x03.
pub fn generate(seed: &[u8; 32]) -> Result<OnionKeys, Error> {
    let signing_key = SigningKey::from_bytes(seed);
    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes = verifying_key.to_bytes();

    // Compute checksum per Tor rend-spec-v3
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey_bytes);
    hasher.update([0x03u8]); // version
    let checksum = hasher.finalize();

    // address = base32(pubkey || checksum[0..2] || version)
    let mut raw = Vec::with_capacity(35);
    raw.extend_from_slice(&pubkey_bytes);
    raw.extend_from_slice(&checksum[..2]);
    raw.push(0x03);

    let hostname = BASE32.encode(&raw).to_lowercase();
    let address = format!("{hostname}.onion");

    // Tor hs_ed25519_secret_key format:
    //   32-byte header: "== ed25519v1-secret: type0 ==\x00\x00\x00"
    //   64-byte expanded secret key (seed || public key)
    let secret_header = b"== ed25519v1-secret: type0 ==\x00\x00\x00";
    let mut secret_key_file = Vec::with_capacity(96);
    secret_key_file.extend_from_slice(secret_header);
    secret_key_file.extend_from_slice(seed);
    secret_key_file.extend_from_slice(&pubkey_bytes);

    // Tor hs_ed25519_public_key format:
    //   32-byte header: "== ed25519v1-public: type0 ==\x00\x00\x00"
    //   32-byte public key
    let public_header = b"== ed25519v1-public: type0 ==\x00\x00\x00";
    let mut public_key_file = Vec::with_capacity(64);
    public_key_file.extend_from_slice(public_header);
    public_key_file.extend_from_slice(&pubkey_bytes);

    Ok(OnionKeys {
        hostname,
        address,
        secret_key_file,
        public_key_file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_onion_key() {
        let seed = [0x42u8; 32];
        let keys1 = generate(&seed).unwrap();
        let keys2 = generate(&seed).unwrap();
        assert_eq!(keys1.address, keys2.address);
    }

    #[test]
    fn valid_onion_format() {
        let seed = [0x42u8; 32];
        let keys = generate(&seed).unwrap();
        assert!(keys.address.ends_with(".onion"));
        // v3 onion: 56 chars hostname
        assert_eq!(keys.hostname.len(), 56);
    }

    #[test]
    fn different_seeds_different_addresses() {
        let keys1 = generate(&[0x42u8; 32]).unwrap();
        let keys2 = generate(&[0x43u8; 32]).unwrap();
        assert_ne!(keys1.address, keys2.address);
    }

    #[test]
    fn tor_secret_key_file_format() {
        let seed = [0x42u8; 32];
        let keys = generate(&seed).unwrap();
        // 32-byte header + 64-byte expanded key = 96 bytes
        assert_eq!(keys.secret_key_file.len(), 96);
        assert!(
            keys.secret_key_file
                .starts_with(b"== ed25519v1-secret: type0 ==")
        );
    }

    #[test]
    fn tor_public_key_file_format() {
        let seed = [0x42u8; 32];
        let keys = generate(&seed).unwrap();
        // 32-byte header + 32-byte public key = 64 bytes
        assert_eq!(keys.public_key_file.len(), 64);
        assert!(
            keys.public_key_file
                .starts_with(b"== ed25519v1-public: type0 ==")
        );
    }
}
