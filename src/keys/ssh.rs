use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::{LineEnding, PrivateKey};

use crate::error::Error;

pub struct SshKeys {
    pub private_key: String,
    pub public_key: String,
}

/// Generate an Ed25519 SSH keypair from a 32-byte seed.
pub fn generate(seed: &[u8; 32], comment: &str) -> Result<SshKeys, Error> {
    let keypair = Ed25519Keypair::from_seed(seed);
    let private = PrivateKey::new(KeypairData::Ed25519(keypair), comment)?;

    let private_key = private.to_openssh(LineEnding::LF)?.to_string();
    let public_key = private.public_key().to_openssh()?;

    Ok(SshKeys {
        private_key,
        public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_ssh_key() {
        let seed = [0x42u8; 32];
        let keys1 = generate(&seed, "test").unwrap();
        let keys2 = generate(&seed, "test").unwrap();
        assert_eq!(keys1.private_key, keys2.private_key);
        assert_eq!(keys1.public_key, keys2.public_key);
    }

    #[test]
    fn valid_openssh_format() {
        let seed = [0x42u8; 32];
        let keys = generate(&seed, "passeport").unwrap();
        assert!(
            keys.private_key
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        );
        assert!(keys.public_key.starts_with("ssh-ed25519 "));
    }
}
