use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid mnemonic: {0}")]
    Mnemonic(String),

    #[error("Key derivation failed: {0}")]
    Derivation(String),

    #[error("PGP key generation failed: {0}")]
    Pgp(#[from] pgp::errors::Error),

    #[error("SSH key generation failed: {0}")]
    Ssh(#[from] ssh_key::Error),

    #[error("AGE key generation failed: {0}")]
    Age(String),

    #[error("Nostr key generation failed: {0}")]
    Nostr(String),

    #[error("Onion key generation failed: {0}")]
    Onion(String),

    #[error("IPFS key generation failed: {0}")]
    Ipfs(String),

    #[error("Agent error: {0}")]
    Agent(String),

    #[error("Vault error: {0}")]
    Vault(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
