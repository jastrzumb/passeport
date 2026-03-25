use std::io::Cursor;

use chrono::TimeZone;
use pgp::Deserializable;
pub use pgp::SignedPublicKey;
use pgp::composed::KeyType;
use pgp::composed::key::{SecretKeyParamsBuilder, SubkeyParamsBuilder};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::types::PublicKeyTrait;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::error::Error;

/// Fixed creation timestamp for deterministic PGP fingerprints.
/// 2001-04-25 — the French theatrical release of "Le Fabuleux Destin d'Amélie Poulain".
fn epoch() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc.with_ymd_and_hms(2001, 4, 25, 0, 0, 0).unwrap()
}

pub struct PgpKeys {
    pub secret_key: String,
    pub public_key: String,
}

/// Parse an armored PGP public key and return its fingerprint as a hex string.
pub fn fingerprint(armored_pubkey: &str) -> Result<String, Error> {
    let (signed_pub, _) = SignedPublicKey::from_armor_single(Cursor::new(armored_pubkey))?;
    Ok(format!("{:?}", signed_pub.fingerprint()))
}

/// Generate a PGP key with full capabilities:
///   - Primary key: Ed25519 (SC — sign + certify)
///   - Subkey 1: ECDH Cv25519 (E — encrypt)
///   - Subkey 2: Ed25519 (A — authenticate)
///
/// Uses a fixed creation timestamp so that the same seed always produces
/// the same PGP fingerprint.
pub fn generate(seed: &[u8; 32], user_id: &str) -> Result<PgpKeys, Error> {
    let mut rng = ChaCha20Rng::from_seed(*seed);
    let created = epoch();

    let mut builder = SecretKeyParamsBuilder::default();
    builder
        .key_type(KeyType::EdDSALegacy)
        .can_certify(true)
        .can_sign(true)
        .created_at(created)
        .primary_user_id(user_id.to_string())
        .subkey(
            SubkeyParamsBuilder::default()
                .key_type(KeyType::ECDH(ECCCurve::Curve25519))
                .can_encrypt(true)
                .created_at(created)
                .build()
                .map_err(|e| Error::Derivation(e.to_string()))?,
        )
        .subkey(
            SubkeyParamsBuilder::default()
                .key_type(KeyType::EdDSALegacy)
                .can_authenticate(true)
                .created_at(created)
                .build()
                .map_err(|e| Error::Derivation(e.to_string()))?,
        );

    let params = builder
        .build()
        .map_err(|e| Error::Derivation(e.to_string()))?;
    let key = params.generate(&mut rng)?;
    let signed_key = key.sign(&mut rng, || "".to_string())?;

    let secret_armored = signed_key.to_armored_string(None.into())?;
    let public_key: SignedPublicKey = signed_key.clone().into();
    let public_armored = public_key.to_armored_string(None.into())?;

    Ok(PgpKeys {
        secret_key: secret_armored,
        public_key: public_armored,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_pgp_key() {
        let seed = [0x42u8; 32];
        let keys1 = generate(&seed, "Test <test@example.com>").unwrap();
        let keys2 = generate(&seed, "Test <test@example.com>").unwrap();
        assert_eq!(keys1.public_key, keys2.public_key);
    }

    #[test]
    fn deterministic_pgp_fingerprint() {
        let seed = [0x42u8; 32];
        let keys1 = generate(&seed, "Test <test@example.com>").unwrap();
        let keys2 = generate(&seed, "Test <test@example.com>").unwrap();
        let fp1 = fingerprint(&keys1.public_key).unwrap();
        let fp2 = fingerprint(&keys2.public_key).unwrap();
        assert_eq!(
            fp1, fp2,
            "PGP fingerprint should be deterministic across invocations"
        );
    }

    #[test]
    fn valid_pgp_armor() {
        let seed = [0x42u8; 32];
        let keys = generate(&seed, "Test <test@example.com>").unwrap();
        assert!(keys.secret_key.contains("BEGIN PGP PRIVATE KEY BLOCK"));
        assert!(keys.public_key.contains("BEGIN PGP PUBLIC KEY BLOCK"));
    }

    #[test]
    fn fingerprint_works() {
        let seed = [0x42u8; 32];
        let keys = generate(&seed, "Test <test@example.com>").unwrap();
        let fp = fingerprint(&keys.public_key).unwrap();
        assert!(!fp.is_empty());
    }
}
