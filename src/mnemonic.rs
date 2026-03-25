use bip39::Mnemonic;
use zeroize::Zeroizing;

use crate::error::Error;

/// Generate a fresh 24-word BIP-39 mnemonic (256-bit entropy).
pub fn generate_mnemonic() -> String {
    use rand::RngCore;
    let mut entropy = [0u8; 32]; // 256 bits → 24 words
    rand::thread_rng().fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy).expect("valid entropy length");
    mnemonic.to_string()
}

/// Parse and validate a 24-word BIP-39 mnemonic, then derive a 512-bit seed.
pub fn mnemonic_to_seed(phrase: &str, passphrase: &str) -> Result<Zeroizing<[u8; 64]>, Error> {
    let mnemonic = Mnemonic::parse(phrase).map_err(|e| Error::Mnemonic(e.to_string()))?;

    if mnemonic.word_count() != 24 {
        return Err(Error::Mnemonic(format!(
            "expected 24 words, got {}",
            mnemonic.word_count()
        )));
    }

    let seed = mnemonic.to_seed(passphrase);
    Ok(Zeroizing::new(seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Standard BIP-39 test vector (24 words)
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn valid_mnemonic_produces_seed() {
        let seed = mnemonic_to_seed(TEST_MNEMONIC, "").unwrap();
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn same_mnemonic_same_seed() {
        let seed1 = mnemonic_to_seed(TEST_MNEMONIC, "").unwrap();
        let seed2 = mnemonic_to_seed(TEST_MNEMONIC, "").unwrap();
        assert_eq!(*seed1, *seed2);
    }

    #[test]
    fn passphrase_changes_seed() {
        let seed1 = mnemonic_to_seed(TEST_MNEMONIC, "").unwrap();
        let seed2 = mnemonic_to_seed(TEST_MNEMONIC, "mypassphrase").unwrap();
        assert_ne!(*seed1, *seed2);
    }

    #[test]
    fn rejects_12_word_mnemonic() {
        let short = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result = mnemonic_to_seed(short, "");
        assert!(result.is_err());
    }

    #[test]
    fn rejects_invalid_words() {
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzzzz";
        let result = mnemonic_to_seed(bad, "");
        assert!(result.is_err());
    }

    #[test]
    fn generate_produces_valid_24_word_mnemonic() {
        let phrase = generate_mnemonic();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24);
        // Should be valid and parseable
        let seed = mnemonic_to_seed(&phrase, "");
        assert!(seed.is_ok());
    }

    #[test]
    fn generate_produces_unique_mnemonics() {
        let m1 = generate_mnemonic();
        let m2 = generate_mnemonic();
        assert_ne!(m1, m2);
    }
}
