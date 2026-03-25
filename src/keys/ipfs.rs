use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use crate::error::Error;

pub struct IpfsKeys {
    /// libp2p peer ID (base58btc-encoded multihash).
    pub peer_id: String,
    /// Protobuf-encoded private key (for IPFS key import).
    pub protobuf_key: Vec<u8>,
}

/// Generate an IPFS/libp2p Ed25519 identity from a 32-byte seed.
///
/// The peer ID is derived from the protobuf-encoded public key:
///   - Protobuf: field 1 (KeyType) = 1 (Ed25519), field 2 (Data) = public key bytes
///   - If encoded key <= 42 bytes: identity multihash (0x00, length, data)
///   - Otherwise: SHA-256 multihash (0x12, 0x20, sha256(data))
pub fn generate(seed: &[u8; 32]) -> Result<IpfsKeys, Error> {
    let signing_key = SigningKey::from_bytes(seed);
    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes = verifying_key.to_bytes();

    // Protobuf-encode the public key
    // KeyType.Ed25519 = 1: varint field 1 = 0x08, value 0x01
    // Data (field 2, length-delimited): 0x12, length, bytes
    let mut proto_pubkey = Vec::with_capacity(36);
    proto_pubkey.extend_from_slice(&[0x08, 0x01]); // field 1 = Ed25519
    proto_pubkey.push(0x12); // field 2, length-delimited
    proto_pubkey.push(pubkey_bytes.len() as u8); // length
    proto_pubkey.extend_from_slice(&pubkey_bytes);

    // For Ed25519 keys, the protobuf-encoded public key is 36 bytes (≤ 42),
    // so we use the identity multihash.
    let multihash = if proto_pubkey.len() <= 42 {
        let mut mh = Vec::with_capacity(2 + proto_pubkey.len());
        mh.push(0x00); // identity hash function code
        mh.push(proto_pubkey.len() as u8); // digest length
        mh.extend_from_slice(&proto_pubkey);
        mh
    } else {
        let digest = Sha256::digest(&proto_pubkey);
        let mut mh = Vec::with_capacity(34);
        mh.push(0x12); // SHA-256 hash function code
        mh.push(0x20); // 32-byte digest
        mh.extend_from_slice(&digest);
        mh
    };

    let peer_id = bs58::encode(&multihash).into_string();

    // Protobuf-encoded private key for IPFS key import:
    // KeyType = Ed25519 (1), Data = seed || pubkey (64 bytes, IPFS convention)
    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(seed);
    combined.extend_from_slice(&pubkey_bytes);

    let mut protobuf_key = Vec::with_capacity(70);
    protobuf_key.extend_from_slice(&[0x08, 0x01]); // field 1 = Ed25519
    protobuf_key.push(0x12); // field 2, length-delimited
    protobuf_key.push(combined.len() as u8); // length = 64
    protobuf_key.extend_from_slice(&combined);

    Ok(IpfsKeys {
        peer_id,
        protobuf_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_ipfs_key() {
        let seed = [0x42u8; 32];
        let keys1 = generate(&seed).unwrap();
        let keys2 = generate(&seed).unwrap();
        assert_eq!(keys1.peer_id, keys2.peer_id);
    }

    #[test]
    fn valid_peer_id_format() {
        let seed = [0x42u8; 32];
        let keys = generate(&seed).unwrap();
        // Identity multihash peer IDs start with "12D3KooW" in base58btc
        assert!(
            keys.peer_id.starts_with("12D3KooW"),
            "got: {}",
            keys.peer_id
        );
    }

    #[test]
    fn different_seeds_different_peer_ids() {
        let keys1 = generate(&[0x42u8; 32]).unwrap();
        let keys2 = generate(&[0x43u8; 32]).unwrap();
        assert_ne!(keys1.peer_id, keys2.peer_id);
    }

    #[test]
    fn protobuf_key_format() {
        let seed = [0x42u8; 32];
        let keys = generate(&seed).unwrap();
        // 2 bytes header + 1 byte field tag + 1 byte length + 64 bytes data = 68 bytes
        assert_eq!(keys.protobuf_key.len(), 68);
        // Starts with KeyType = Ed25519
        assert_eq!(&keys.protobuf_key[..2], &[0x08, 0x01]);
        // Data field tag and length
        assert_eq!(keys.protobuf_key[2], 0x12);
        assert_eq!(keys.protobuf_key[3], 64);
    }
}
