use passeport::derive::derive_keys;
use passeport::keys::{age, ipfs, nostr, onion, pgp, ssh};
use passeport::mnemonic::mnemonic_to_seed;

const VECTORS: &str = include_str!("vectors.json");

#[derive(serde::Deserialize)]
struct TestVectors {
    mnemonic: String,
    passphrase: String,
    user_id: String,
    comment: String,
    expected: Expected,
}

#[derive(serde::Deserialize)]
struct Expected {
    ssh_fingerprint: String,
    ssh_public_key: String,
    age_recipient: String,
    age_identity: String,
    pgp_fingerprint: String,
    nostr_npub: String,
    nostr_nsec: String,
    onion_address: String,
    ipfs_peer_id: String,
}

#[test]
fn test_vectors() {
    let vectors: TestVectors = serde_json::from_str(VECTORS).expect("valid test vectors JSON");

    let seed = mnemonic_to_seed(&vectors.mnemonic, &vectors.passphrase).unwrap();
    let keys = derive_keys(&seed).unwrap();

    // SSH
    let ssh_keys = ssh::generate(&keys.ssh, &vectors.comment).unwrap();
    let pub_key = ssh_key::PublicKey::from_openssh(&ssh_keys.public_key).unwrap();
    let ssh_fp = pub_key.fingerprint(ssh_key::HashAlg::Sha256).to_string();
    assert_eq!(
        ssh_fp, vectors.expected.ssh_fingerprint,
        "SSH fingerprint mismatch"
    );
    assert_eq!(
        ssh_keys.public_key, vectors.expected.ssh_public_key,
        "SSH public key mismatch"
    );

    // AGE
    let age_keys = age::generate(&keys.age).unwrap();
    assert_eq!(
        age_keys.recipient, vectors.expected.age_recipient,
        "AGE recipient mismatch"
    );
    assert_eq!(
        age_keys.identity, vectors.expected.age_identity,
        "AGE identity mismatch"
    );

    // PGP — now uses a fixed creation timestamp, so fingerprint is deterministic
    let pgp_keys = pgp::generate(&keys.pgp, &vectors.user_id).unwrap();
    let pgp_fp = pgp::fingerprint(&pgp_keys.public_key).unwrap();
    assert_eq!(
        pgp_fp, vectors.expected.pgp_fingerprint,
        "PGP fingerprint mismatch"
    );

    // Nostr
    let nostr_keys = nostr::generate(&keys.nostr).unwrap();
    assert_eq!(
        nostr_keys.npub, vectors.expected.nostr_npub,
        "Nostr npub mismatch"
    );
    assert_eq!(
        nostr_keys.nsec, vectors.expected.nostr_nsec,
        "Nostr nsec mismatch"
    );

    // Onion
    let onion_keys = onion::generate(&keys.onion).unwrap();
    assert_eq!(
        onion_keys.address, vectors.expected.onion_address,
        "Onion address mismatch"
    );

    // IPFS
    let ipfs_keys = ipfs::generate(&keys.ipfs).unwrap();
    assert_eq!(
        ipfs_keys.peer_id, vectors.expected.ipfs_peer_id,
        "IPFS PeerID mismatch"
    );
}
