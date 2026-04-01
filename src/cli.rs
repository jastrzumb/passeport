use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "ppt",
    version,
    about = "Passeport — Derive PGP, SSH, AGE, Nostr, Tor, and IPFS keys from a BIP-39 mnemonic"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// BIP-39 passphrase (default: empty)
    #[arg(short, long, global = true, default_value = "")]
    pub passphrase: String,

    /// Output directory for key files (default: print to stdout)
    #[arg(short, long, global = true)]
    pub output_dir: Option<PathBuf>,

    /// User ID for PGP key (e.g. "Name <email>")
    #[arg(
        short,
        long,
        global = true,
        default_value = "passeport <passeport@localhost>"
    )]
    pub user_id: String,

    /// Comment for SSH key
    #[arg(short, long, global = true, default_value = "passeport")]
    pub comment: String,

    /// Suppress informational output
    #[arg(short, long, global = true)]
    pub quiet: bool,
}

#[derive(Subcommand)]
pub enum Command {
    /// Generate a fresh mnemonic or set up integrations
    #[command(
        after_help = "Examples:\n  ppt init\n  ppt init > mnemonic.txt\n  ppt init git\n  ppt init git --local"
    )]
    Init {
        #[command(subcommand)]
        action: Option<InitAction>,
    },

    /// Derive cryptographic keys from your mnemonic
    #[command(
        after_help = "Examples:\n  ppt key all\n  ppt key all -o ./keys\n  ppt key ssh --copy\n  ppt key nostr"
    )]
    Key {
        #[command(subcommand)]
        key_type: KeyCommand,
    },

    /// Sign a file with the derived Ed25519 key
    #[command(
        after_help = "Examples:\n  ppt sign message.txt\n  ppt sign message.txt --output message.txt.sig\n  echo \"hello\" | ppt sign\n  ppt sign --format pgp message.txt"
    )]
    Sign {
        /// File to sign (reads from stdin if omitted)
        file: Option<PathBuf>,

        /// Output signature file (default: <file>.sig, or stdout if reading stdin)
        #[arg(long)]
        output: Option<PathBuf>,

        /// Signature format
        #[arg(short, long, default_value = "raw")]
        format: SignatureFormat,
    },

    /// Verify a signature against the derived public key
    #[command(
        name = "verify-sig",
        after_help = "Examples:\n  ppt verify-sig message.txt --sig message.txt.sig\n  ppt verify-sig -f pgp message.txt --sig message.txt.asc"
    )]
    VerifySig {
        /// File that was signed
        file: PathBuf,

        /// Signature file
        #[arg(long)]
        sig: PathBuf,

        /// Signature format
        #[arg(short, long, default_value = "raw")]
        format: SignatureFormat,
    },

    /// Encrypt a file using the derived key
    #[command(
        after_help = "Examples:\n  ppt encrypt secret.txt\n  ppt encrypt secret.txt --output secret.txt.age\n  ppt encrypt -f pgp secret.txt\n  ppt encrypt -r age1... secret.txt"
    )]
    Encrypt {
        /// File to encrypt (reads from stdin if omitted)
        file: Option<PathBuf>,

        /// Output file (default: <file>.age or <file>.pgp, or stdout if reading stdin)
        #[arg(long)]
        output: Option<PathBuf>,

        /// Encryption format
        #[arg(short, long, default_value = "age")]
        format: EncryptionFormat,

        /// Additional AGE recipient public keys (can be specified multiple times, AGE only)
        #[arg(short, long)]
        recipient: Vec<String>,
    },

    /// Decrypt a file using the derived key
    #[command(
        after_help = "Examples:\n  ppt decrypt secret.txt.age\n  ppt decrypt -f pgp secret.txt.pgp\n  ppt decrypt secret.txt.age --output secret.txt"
    )]
    Decrypt {
        /// File to decrypt (reads from stdin if omitted)
        file: Option<PathBuf>,

        /// Output file (default: stdout)
        #[arg(long)]
        output: Option<PathBuf>,

        /// Decryption format
        #[arg(short, long, default_value = "age")]
        format: EncryptionFormat,
    },

    /// Run as an SSH agent daemon
    #[command(
        after_help = "Examples:\n  ppt agent\n  ppt agent -t 30\n  eval $(ppt agent -t 30)\n  ppt agent --pinentry-program pinentry-mac\n  ppt agent -d   # stay in foreground"
    )]
    Agent {
        /// Lock timeout in minutes (0 = never lock)
        #[arg(short = 't', long, default_value = "0")]
        timeout: u64,

        /// Path to pinentry program for unlock challenges (e.g. "pinentry", "pinentry-mac").
        /// Auto-detected from PATH if not specified. Falls back to built-in terminal prompt.
        #[arg(long)]
        pinentry_program: Option<String>,

        /// Run in the foreground (do not fork). Useful for debugging.
        #[arg(short = 'd', long)]
        foreground: bool,
    },

    /// Validate a mnemonic and print all public key fingerprints
    #[command(after_help = "Examples:\n  ppt verify\n  echo \"word1 ... word24\" | ppt verify")]
    Verify,

    /// Manage the OS credential store (keychain)
    #[command(after_help = "Examples:\n  ppt vault store\n  ppt vault status\n  ppt vault delete")]
    Vault {
        #[command(subcommand)]
        action: VaultAction,
    },

    /// Generate shell completions
    #[command(
        after_help = "Examples:\n  ppt completions bash > ~/.bash_completion.d/ppt\n  ppt completions zsh > ~/.zfunc/_ppt\n  ppt completions fish > ~/.config/fish/completions/ppt.fish\n  ppt completions powershell > ppt.ps1"
    )]
    Completions {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
    },

    /// Generate a man page
    #[command(
        name = "man-page",
        after_help = "Examples:\n  ppt man-page > ppt.1\n  ppt man-page | man -l -"
    )]
    ManPage,
}

#[derive(Subcommand)]
pub enum InitAction {
    /// Configure Git for SSH commit signing using the derived key
    #[command(after_help = "Examples:\n  ppt init git\n  ppt init git --local")]
    Git {
        /// Apply config to the local repo instead of global
        #[arg(long)]
        local: bool,
    },
}

#[derive(Subcommand)]
pub enum KeyCommand {
    /// Derive all keys (PGP + SSH + AGE + Nostr + Onion + IPFS)
    #[command(
        after_help = "Examples:\n  ppt key all\n  ppt key all -o ./keys\n  ppt key all -u \"Alice <alice@example.com>\" -o ./keys"
    )]
    All,

    /// Derive only PGP keys
    #[command(
        after_help = "Examples:\n  ppt key pgp\n  ppt key pgp --copy\n  ppt key pgp -u \"Alice <alice@example.com>\" -o ./keys"
    )]
    Pgp {
        /// Copy public key to clipboard
        #[arg(long)]
        copy: bool,
    },

    /// Derive only SSH key
    #[command(
        after_help = "Examples:\n  ppt key ssh\n  ppt key ssh -o ./keys\n  ppt key ssh --copy"
    )]
    Ssh {
        /// Copy public key to clipboard
        #[arg(long)]
        copy: bool,
    },

    /// Derive only AGE identity
    #[command(after_help = "Examples:\n  ppt key age\n  ppt key age -o ./keys")]
    Age,

    /// Derive only Nostr identity (secp256k1)
    #[command(
        after_help = "Examples:\n  ppt key nostr\n  echo \"word1 ... word24\" | ppt key nostr"
    )]
    Nostr,

    /// Derive only Tor onion service identity (Ed25519)
    #[command(after_help = "Examples:\n  ppt key onion")]
    Onion,

    /// Derive only IPFS/libp2p identity (Ed25519)
    #[command(after_help = "Examples:\n  ppt key ipfs")]
    Ipfs,
}

#[derive(Subcommand)]
pub enum VaultAction {
    /// Store a mnemonic in the OS credential store
    Store {
        /// Encrypt the mnemonic with a passphrase before storing
        #[arg(long)]
        encrypt: bool,
    },
    /// Remove the mnemonic from the OS credential store
    Delete,
    /// Check whether a mnemonic is stored
    Status,
}

#[derive(Clone, ValueEnum)]
pub enum SignatureFormat {
    /// Raw Ed25519 signature (64 bytes)
    Raw,
    /// PGP-style armored detached signature
    Pgp,
}

#[derive(Clone, ValueEnum)]
pub enum EncryptionFormat {
    /// AGE encryption (X25519, modern)
    Age,
    /// PGP encryption (ECDH Cv25519, armored)
    Pgp,
}
