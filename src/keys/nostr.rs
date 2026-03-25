use bech32::{ToBase32, Variant};
use k256::SecretKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;

use crate::error::Error;

pub struct NostrKeys {
    /// Private key in nsec (bech32) format.
    pub nsec: String,
    /// Public key in npub (bech32) format.
    pub npub: String,
    /// Raw hex private key (for clients that expect hex).
    pub secret_hex: String,
    /// Raw hex public key (x-only, 32 bytes).
    pub public_hex: String,
}

/// Generate a Nostr secp256k1 keypair from a 32-byte seed.
///
/// Nostr uses "schnorr-style" x-only public keys (BIP-340).
/// The nsec/npub formats are bech32-encoded raw key bytes.
pub fn generate(seed: &[u8; 32]) -> Result<NostrKeys, Error> {
    let secret_key = SecretKey::from_bytes(seed.into()).map_err(|e| Error::Nostr(e.to_string()))?;
    let public_key = secret_key.public_key();

    // X-only public key (32 bytes) — drop the parity prefix
    let point = public_key.to_encoded_point(false);
    let x_bytes: [u8; 32] = point
        .x()
        .expect("non-identity point")
        .as_slice()
        .try_into()
        .unwrap();

    let nsec = bech32::encode("nsec", seed.to_base32(), Variant::Bech32)
        .map_err(|e| Error::Nostr(e.to_string()))?;
    let npub = bech32::encode("npub", x_bytes.to_base32(), Variant::Bech32)
        .map_err(|e| Error::Nostr(e.to_string()))?;

    let secret_hex = hex_encode(seed);
    let public_hex = hex_encode(&x_bytes);

    Ok(NostrKeys {
        nsec,
        npub,
        secret_hex,
        public_hex,
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_nostr_key() {
        let seed = [0x42u8; 32];
        let keys1 = generate(&seed).unwrap();
        let keys2 = generate(&seed).unwrap();
        assert_eq!(keys1.nsec, keys2.nsec);
        assert_eq!(keys1.npub, keys2.npub);
    }

    #[test]
    fn valid_nostr_format() {
        let seed = [0x42u8; 32];
        let keys = generate(&seed).unwrap();
        assert!(keys.nsec.starts_with("nsec1"));
        assert!(keys.npub.starts_with("npub1"));
        assert_eq!(keys.secret_hex.len(), 64);
        assert_eq!(keys.public_hex.len(), 64);
    }
}
