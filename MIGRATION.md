# Passeport Migration Guide

This document explains what to expect if the derivation scheme changes between major versions.

## Current Version: v1

All current derivation uses:
- **Salt**: `"passeport-v1"`
- **Info strings**: `"passeport-{type}-v1"` (e.g., `"passeport-ssh-v1"`)

See [DERIVATION.md](DERIVATION.md) for the full specification.

## When Would v2 Happen?

A new major derivation version would only be introduced if:

1. A cryptographic weakness is discovered in HKDF-SHA256 that requires switching algorithms
2. A fundamental change to the derivation structure is needed (e.g., adding a mandatory key-stretching step)
3. An upstream library change makes it impossible to maintain byte-for-byte compatibility

**Adding new key types does NOT require v2.** New key types simply get new info strings (e.g., `"passeport-newtype-v1"`) and are additive.

## What v2 Would Change

If v2 is introduced:

- The HKDF salt would change to `"passeport-v2"`
- Some or all info strings would change to `"passeport-{type}-v2"`
- The same mnemonic would produce **different keys** under v2

## Migration Plan

If v2 is ever released, Passeport will:

1. **Support both versions simultaneously.** A `--derivation-version` flag (or similar) will allow generating v1 keys indefinitely.
2. **Default to v2 for new operations** but warn if a vault-stored mnemonic was previously used with v1.
3. **Provide a migration command** (`ppt migrate`) that:
   - Generates both v1 and v2 key fingerprints side by side
   - Helps you update SSH authorized_keys, PGP keyservers, etc.
4. **Never delete v1 support.** Since the derivation is purely computational (no state), v1 can be supported forever.

## What You Should Do

- **Keep your mnemonic safe.** Your mnemonic is version-agnostic — it works with any derivation version.
- **Note your derivation version.** If you record key fingerprints, note they are v1-derived.
- **Don't worry.** v2 is not planned. This document exists for completeness. The v1 derivation is built on well-established cryptographic primitives (HKDF-SHA256, BIP-39 PBKDF2) that are not expected to require replacement.

## PGP Determinism Note

Passeport uses a fixed creation timestamp for PGP keys, making fingerprints fully deterministic. However, PGP key determinism also depends on the `rpgp` library consuming RNG bytes in the same order across versions — this is why `rpgp` is pinned to a specific version (see `Cargo.toml`).
