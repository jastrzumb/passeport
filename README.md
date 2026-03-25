# Passeport

Derive PGP, SSH, AGE, Nostr, Tor, and IPFS keys from a single BIP-39 mnemonic. Back up 24 words, recover all your cryptographic identities.

## Install

```
cargo install --path .
```

Binary name: `ppt`

## Quick Start

```bash
# Generate a new 24-word mnemonic
ppt init

# Store it in your OS credential store (Windows Credential Manager / macOS Keychain / Linux keyutils)
ppt vault store

# Derive all keys
ppt key all -o ./keys

# Or derive individually
ppt key ssh -o ./keys
ppt key pgp -u "Your Name <you@example.com>" -o ./keys
ppt key age -o ./keys
ppt key nostr
ppt key onion
ppt key ipfs

# Copy SSH public key to clipboard
ppt key ssh --copy

# Verify your mnemonic — prints all public key fingerprints
ppt verify
```

## Sign & Encrypt

```bash
# Sign a file (Ed25519 detached signature, 64 bytes)
ppt sign message.txt                          # writes message.txt.sig
ppt sign message.txt --output custom.sig
ppt sign message.txt -f pgp                   # PGP armored signature

# Verify a signature
ppt verify-sig message.txt --sig message.txt.sig
ppt verify-sig -f pgp message.txt --sig message.txt.asc

# Encrypt with AGE (default)
ppt encrypt secret.txt                        # writes secret.txt.age
ppt encrypt secret.txt -r age1...             # add extra recipients

# Encrypt with PGP
ppt encrypt -f pgp secret.txt                 # writes secret.txt.pgp

# Decrypt (specify format to match)
ppt decrypt secret.txt.age                    # AGE (default)
ppt decrypt -f pgp secret.txt.pgp             # PGP
ppt decrypt secret.txt.age --output secret.txt
```

## SSH Agent

Run a persistent SSH agent that holds your derived Ed25519 key in memory:

```bash
# Start the agent (auto-locks after 30 minutes, uses pinentry for unlock)
ppt agent -t 30

# On Unix, use eval to set SSH_AUTH_SOCK automatically
eval $(ppt agent -t 30)

# Verify it works
ssh-add -l
```

The agent auto-detects `pinentry` from PATH for lock challenges. Override with `--pinentry-program <path>`.

## Git SSH Signing

```bash
# One-time setup — configures git globally for SSH commit signing
ppt init git

# Or configure for a single repo
ppt init git --local

# Make sure the agent is running, then commit as usual
git commit -m "signed commit"
```

## Vault

The OS credential store lets you skip the mnemonic prompt entirely:

```bash
ppt vault store              # save mnemonic to OS credential store
ppt vault store --encrypt    # save encrypted (prompts for passphrase)
ppt vault status             # check if a mnemonic is stored
ppt vault delete             # remove it
```

Once stored, all commands (`key`, `agent`, `verify`, etc.) use it automatically.

## Mnemonic Input

When the vault is empty, Passeport prompts for the mnemonic interactively with masked feedback (first 2 characters visible per word). For automation, pipe via stdin:

```bash
echo "word1 word2 ... word24" | ppt agent
cat mnemonic.txt | ppt key all -o ./keys
```

## Key Derivation

```
24-word mnemonic + optional passphrase
        |
   BIP-39 PBKDF2 -> 512-bit seed
        |
   HKDF-SHA256 (salt: "passeport-v1")
        |
        +-- info: "passeport-pgp-v1"   -> Ed25519 PGP key (SC) + Cv25519 (E) + Ed25519 (A)
        +-- info: "passeport-ssh-v1"   -> Ed25519 SSH key
        +-- info: "passeport-age-v1"   -> X25519 AGE identity
        +-- info: "passeport-nostr-v1" -> secp256k1 Nostr identity (npub/nsec)
        +-- info: "passeport-onion-v1" -> Ed25519 Tor v3 onion service
        +-- info: "passeport-ipfs-v1"  -> Ed25519 IPFS/libp2p peer identity
```

Same mnemonic + passphrase always produces identical keys.

## Shell Completions

```bash
# Bash
ppt completions bash > ~/.bash_completion.d/ppt

# Zsh
ppt completions zsh > ~/.zfunc/_ppt

# Fish
ppt completions fish > ~/.config/fish/completions/ppt.fish

# PowerShell
ppt completions powershell > ppt.ps1
```

## License

MIT
