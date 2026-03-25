use bech32::{ToBase32, Variant};

use crate::error::Error;

pub struct AgeKeys {
    pub identity: String,
    pub recipient: String,
}

/// Generate an AGE X25519 identity from a 32-byte seed.
///
/// We bech32-encode the raw bytes into the AGE-SECRET-KEY-1... format,
/// then parse it with the age crate to derive the public recipient.
pub fn generate(seed: &[u8; 32]) -> Result<AgeKeys, Error> {
    let encoded = bech32::encode("age-secret-key-", seed.to_base32(), Variant::Bech32)
        .map_err(|e| Error::Age(e.to_string()))?;
    let identity_str = encoded.to_uppercase();

    let identity: age::x25519::Identity = identity_str
        .parse()
        .map_err(|e: &str| Error::Age(e.to_string()))?;

    let recipient = identity.to_public().to_string();

    Ok(AgeKeys {
        identity: identity_str,
        recipient,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_age_key() {
        let seed = [0x42u8; 32];
        let keys1 = generate(&seed).unwrap();
        let keys2 = generate(&seed).unwrap();
        assert_eq!(keys1.identity, keys2.identity);
        assert_eq!(keys1.recipient, keys2.recipient);
    }

    #[test]
    fn valid_age_format() {
        let seed = [0x42u8; 32];
        let keys = generate(&seed).unwrap();
        assert!(keys.identity.starts_with("AGE-SECRET-KEY-1"));
        assert!(keys.recipient.starts_with("age1"));
    }
}
