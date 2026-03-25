use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::Error;

const SALT: &[u8] = b"passeport-v1";
const INFO_PGP: &[u8] = b"passeport-pgp-v1";
const INFO_SSH: &[u8] = b"passeport-ssh-v1";
const INFO_AGE: &[u8] = b"passeport-age-v1";
const INFO_NOSTR: &[u8] = b"passeport-nostr-v1";
const INFO_ONION: &[u8] = b"passeport-onion-v1";
const INFO_IPFS: &[u8] = b"passeport-ipfs-v1";

/// All derived 32-byte key seeds for each key type.
pub struct DerivedKeys {
    pub pgp: Zeroizing<[u8; 32]>,
    pub ssh: Zeroizing<[u8; 32]>,
    pub age: Zeroizing<[u8; 32]>,
    pub nostr: Zeroizing<[u8; 32]>,
    pub onion: Zeroizing<[u8; 32]>,
    pub ipfs: Zeroizing<[u8; 32]>,
}

/// Derive per-key material from a 512-bit BIP-39 seed using HKDF-SHA256.
pub fn derive_keys(seed: &[u8; 64]) -> Result<DerivedKeys, Error> {
    let hk = Hkdf::<Sha256>::new(Some(SALT), seed);

    let expand = |info: &[u8]| -> Result<Zeroizing<[u8; 32]>, Error> {
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(info, okm.as_mut())
            .map_err(|e| Error::Derivation(e.to_string()))?;
        Ok(okm)
    };

    Ok(DerivedKeys {
        pgp: expand(INFO_PGP)?,
        ssh: expand(INFO_SSH)?,
        age: expand(INFO_AGE)?,
        nostr: expand(INFO_NOSTR)?,
        onion: expand(INFO_ONION)?,
        ipfs: expand(INFO_IPFS)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_derivation() {
        let seed = [0xABu8; 64];
        let keys1 = derive_keys(&seed).unwrap();
        let keys2 = derive_keys(&seed).unwrap();
        assert_eq!(*keys1.pgp, *keys2.pgp);
        assert_eq!(*keys1.ssh, *keys2.ssh);
        assert_eq!(*keys1.age, *keys2.age);
    }

    #[test]
    fn different_keys_per_type() {
        let seed = [0xABu8; 64];
        let keys = derive_keys(&seed).unwrap();
        let all = [
            &keys.pgp,
            &keys.ssh,
            &keys.age,
            &keys.nostr,
            &keys.onion,
            &keys.ipfs,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(**all[i], **all[j], "key {i} and {j} should differ");
            }
        }
    }

    #[test]
    fn different_seed_different_keys() {
        let seed1 = [0xABu8; 64];
        let seed2 = [0xCDu8; 64];
        let keys1 = derive_keys(&seed1).unwrap();
        let keys2 = derive_keys(&seed2).unwrap();
        assert_ne!(*keys1.pgp, *keys2.pgp);
    }
}
