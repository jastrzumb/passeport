# Passeport Derivation Specification (v1)

This document defines the key derivation process used by Passeport. It serves as a **stability contract**: any Passeport release with the same major version (v1) will produce identical keys from identical inputs.

## Overview

```
24-word BIP-39 mnemonic + optional passphrase
        |
   BIP-39 PBKDF2 (2048 rounds, HMAC-SHA512)
        |
   512-bit seed
        |
   HKDF-SHA256 (salt: "passeport-v1")
        |
        +-- info: "passeport-pgp-v1"   -> 32-byte seed -> Ed25519 PGP key
        +-- info: "passeport-ssh-v1"   -> 32-byte seed -> Ed25519 SSH key
        +-- info: "passeport-age-v1"   -> 32-byte seed -> X25519 AGE identity
        +-- info: "passeport-nostr-v1" -> 32-byte seed -> secp256k1 Nostr keypair
        +-- info: "passeport-onion-v1" -> 32-byte seed -> Ed25519 Tor v3 onion service
        +-- info: "passeport-ipfs-v1"  -> 32-byte seed -> Ed25519 IPFS/libp2p peer ID
```

## Step 1: Mnemonic to Seed

The mnemonic is a 24-word BIP-39 phrase (256 bits of entropy). It is converted to a 512-bit seed using the standard BIP-39 seed derivation:

- **Algorithm**: PBKDF2 with HMAC-SHA512
- **Iterations**: 2048
- **Salt**: `"mnemonic" + passphrase` (passphrase defaults to empty string)
- **Output**: 64 bytes (512 bits)

This step is implemented by the `bip39` crate and follows the [BIP-39 specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) exactly.

## Step 2: Seed to Per-Key Material (HKDF)

Each key type gets its own 32-byte derivation via HKDF-SHA256:

- **Algorithm**: HKDF-SHA256 (RFC 5869)
- **Salt**: `"passeport-v1"` (fixed, ASCII bytes)
- **IKM** (input key material): the 512-bit seed from Step 1
- **Info strings** (one per key type):

| Key Type | Info String | Output Use |
|----------|-------------|------------|
| PGP | `"passeport-pgp-v1"` | Seed for ChaCha20Rng → rpgp key generation |
| SSH | `"passeport-ssh-v1"` | Ed25519 signing key seed (32 bytes) |
| AGE | `"passeport-age-v1"` | X25519 secret key (bech32-encoded as AGE-SECRET-KEY) |
| Nostr | `"passeport-nostr-v1"` | secp256k1 secret key (bech32-encoded as nsec) |
| Tor Onion | `"passeport-onion-v1"` | Ed25519 signing key seed → .onion v3 address |
| IPFS | `"passeport-ipfs-v1"` | Ed25519 signing key seed → libp2p peer ID |

- **Output length**: 32 bytes per key type

Each info string is unique, ensuring independent key material even though all keys derive from the same seed.

## Step 3: Key Generation

### SSH (Ed25519)
The 32-byte seed is used directly as an Ed25519 signing key via `ed25519-dalek`. The output is in OpenSSH format.

### AGE (X25519)
The 32-byte seed is bech32-encoded with the HRP `"age-secret-key-"` to produce an AGE identity string. The `age` crate derives the corresponding X25519 public key (recipient).

### PGP (Ed25519 + Cv25519)
The 32-byte seed initializes a `ChaCha20Rng` CSPRNG. The `rpgp` crate consumes randomness from this RNG to generate:
- **Primary key**: Ed25519 (Sign + Certify)
- **Subkey 1**: ECDH Curve25519 (Encrypt)
- **Subkey 2**: Ed25519 (Authenticate)

> **Note**: PGP key determinism depends on the rpgp crate consuming RNG bytes in the same order across versions. A fixed creation timestamp (2001-04-25T00:00:00Z) is used so that the PGP fingerprint is fully deterministic — the same seed always produces the same fingerprint.

### Nostr (secp256k1)
The 32-byte seed is used directly as a secp256k1 secret key via the `k256` crate. The x-only public key (BIP-340 style, 32 bytes) is computed from the secret key.
- **nsec**: bech32-encoded secret key (HRP: `"nsec"`)
- **npub**: bech32-encoded x-only public key (HRP: `"npub"`)

### Tor Onion Service (Ed25519)
The 32-byte seed is used as an Ed25519 signing key. The v3 .onion address is computed per the Tor rend-spec-v3:
- `address = base32(pubkey || checksum || version)`
- `checksum = SHA3-256(".onion checksum" || pubkey || 0x03)[0..2]`
- `version = 0x03`

### IPFS/libp2p (Ed25519)
The 32-byte seed is used as an Ed25519 signing key. The peer ID is computed as:
1. Protobuf-encode the public key: `{KeyType: Ed25519(1), Data: pubkey_bytes}`
2. Apply identity multihash (since encoded key ≤ 42 bytes): `0x00 || length || data`
3. Base58btc-encode the multihash

## Stability Guarantees

Within a major version (v1):

1. **Same mnemonic + passphrase = same keys.** Always. This is the core invariant.
2. **Info strings are immutable.** The strings listed above will never change in v1.
3. **Salt is immutable.** `"passeport-v1"` will never change in v1.
4. **New key types may be added** with new info strings, but existing derivations are never modified.

### What can change in v1
- New key types (new HKDF info strings)
- Output formatting (e.g., different PGP armor headers)
- CLI flags and UX

### What requires v2
- Changing the HKDF salt
- Changing any existing info string
- Changing the derivation algorithm (e.g., switching from HKDF-SHA256 to Argon2)
- Changing how a 32-byte seed maps to a key (e.g., different Ed25519 implementation)

## Test Vectors

See `tests/vectors.json` for a complete set of expected outputs from the standard BIP-39 test mnemonic (`"abandon ... art"`). These vectors are checked on every test run.

## References

- [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) — Mnemonic code for generating deterministic keys
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) — HKDF: HMAC-based Extract-and-Expand Key Derivation Function
- [Tor rend-spec-v3](https://spec.torproject.org/rend-spec-v3) — Tor onion service v3 specification
- [libp2p peer ID spec](https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md) — libp2p peer identity
- [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) — Nostr basic protocol / key format
- [NIP-19](https://github.com/nostr-protocol/nips/blob/master/19.md) — Nostr bech32-encoded entities (npub/nsec)
