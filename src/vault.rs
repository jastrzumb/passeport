use std::io::{Read, Write};

use age::secrecy::SecretString;
use keyring::Entry;

use crate::error::Error;

const DEFAULT_SERVICE: &str = "passeport";
const USER: &str = "mnemonic";
const ENCRYPTED_PREFIX: &str = "age-encrypted:";

/// Handle to a credential store entry.
pub struct Vault {
    service: String,
}

impl Default for Vault {
    fn default() -> Self {
        Self {
            service: DEFAULT_SERVICE.to_string(),
        }
    }
}

impl Vault {
    /// Create a vault with a custom service name (for testing).
    pub fn with_service(service: &str) -> Self {
        Self {
            service: service.to_string(),
        }
    }

    fn entry(&self) -> Result<Entry, Error> {
        Entry::new(&self.service, USER).map_err(|e| Error::Vault(e.to_string()))
    }

    /// Store a mnemonic in the OS credential store (plaintext).
    pub fn store(&self, mnemonic: &str) -> Result<(), Error> {
        self.entry()?
            .set_password(mnemonic)
            .map_err(|e| Error::Vault(e.to_string()))
    }

    /// Store a mnemonic encrypted with a passphrase in the OS credential store.
    pub fn store_encrypted(&self, mnemonic: &str, passphrase: &str) -> Result<(), Error> {
        let encrypted = age_encrypt_passphrase(mnemonic.as_bytes(), passphrase)
            .map_err(|e| Error::Vault(e.to_string()))?;

        let encoded = format!(
            "{}{}",
            ENCRYPTED_PREFIX,
            data_encoding::BASE64.encode(&encrypted)
        );

        self.entry()?
            .set_password(&encoded)
            .map_err(|e| Error::Vault(e.to_string()))
    }

    /// Retrieve the mnemonic from the OS credential store.
    /// Returns None if no credential is stored.
    /// If encrypted, prompts for passphrase to decrypt.
    pub fn load(&self) -> Result<Option<String>, Error> {
        let raw = match self.entry()?.get_password() {
            Ok(password) => password,
            Err(keyring::Error::NoEntry) => return Ok(None),
            Err(e) => return Err(Error::Vault(e.to_string())),
        };

        if let Some(b64) = raw.strip_prefix(ENCRYPTED_PREFIX) {
            let encrypted = data_encoding::BASE64
                .decode(b64.as_bytes())
                .map_err(|e| Error::Vault(format!("corrupt vault data: {e}")))?;

            let passphrase =
                prompt_passphrase("Vault passphrase: ").map_err(|e| Error::Vault(e.to_string()))?;

            let decrypted = age_decrypt_passphrase(&encrypted, &passphrase)
                .map_err(|e| Error::Vault(format!("decryption failed: {e}")))?;

            let mnemonic = String::from_utf8(decrypted)
                .map_err(|e| Error::Vault(format!("invalid UTF-8 in decrypted data: {e}")))?;

            Ok(Some(mnemonic))
        } else {
            Ok(Some(raw))
        }
    }

    /// Delete the mnemonic from the OS credential store.
    pub fn delete(&self) -> Result<(), Error> {
        match self.entry()?.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()), // already gone
            Err(e) => Err(Error::Vault(e.to_string())),
        }
    }

    /// Check whether a mnemonic is stored.
    pub fn is_stored(&self) -> Result<bool, Error> {
        match self.entry()?.get_password() {
            Ok(_) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(Error::Vault(e.to_string())),
        }
    }

    /// Check whether the stored mnemonic is encrypted.
    pub fn is_encrypted(&self) -> Result<bool, Error> {
        match self.entry()?.get_password() {
            Ok(raw) => Ok(raw.starts_with(ENCRYPTED_PREFIX)),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(Error::Vault(e.to_string())),
        }
    }
}

// Convenience functions using the default vault (for production use)
pub fn store(mnemonic: &str) -> Result<(), Error> {
    Vault::default().store(mnemonic)
}
pub fn store_encrypted(mnemonic: &str, passphrase: &str) -> Result<(), Error> {
    Vault::default().store_encrypted(mnemonic, passphrase)
}
pub fn load() -> Result<Option<String>, Error> {
    Vault::default().load()
}
pub fn delete() -> Result<(), Error> {
    Vault::default().delete()
}
pub fn is_stored() -> Result<bool, Error> {
    Vault::default().is_stored()
}
pub fn is_encrypted() -> Result<bool, Error> {
    Vault::default().is_encrypted()
}

fn prompt_passphrase(prompt: &str) -> Result<String, String> {
    eprint!("{prompt}");
    std::io::stderr().flush().map_err(|e| e.to_string())?;
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| e.to_string())?;
    Ok(input.trim().to_string())
}

fn age_encrypt_passphrase(data: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    let encryptor =
        age::Encryptor::with_user_passphrase(SecretString::from(passphrase.to_string()));
    let mut encrypted = vec![];
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| e.to_string())?;
    writer.write_all(data).map_err(|e| e.to_string())?;
    writer.finish().map_err(|e| e.to_string())?;
    Ok(encrypted)
}

fn age_decrypt_passphrase(data: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    let decryptor = age::Decryptor::new(data).map_err(|e| e.to_string())?;
    let identity = age::scrypt::Identity::new(SecretString::from(passphrase.to_string()));
    let mut decrypted = vec![];
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| e.to_string())?;
    reader
        .read_to_end(&mut decrypted)
        .map_err(|e| e.to_string())?;
    Ok(decrypted)
}
