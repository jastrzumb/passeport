use std::io::{self, Read, Write};
use std::path::PathBuf;

use crate::cli::{Cli, EncryptionFormat, KeyCommand, SignatureFormat, VaultAction};
use crate::derive::{DerivedKeys, derive_keys};
use crate::error::Error;
use crate::keys::{age as age_keys, ipfs, nostr, onion, pgp, ssh};
use crate::mnemonic::mnemonic_to_seed;
use crate::prompt;

/// Load the mnemonic: vault → stdin pipe → interactive prompt (in that order).
pub fn load_mnemonic() -> Result<String, Error> {
    // 1. Try the OS credential store
    if let Some(stored) = crate::vault::load()? {
        eprintln!("Using mnemonic from OS credential store.");
        return Ok(stored);
    }

    // 2. If stdin is piped, read from it
    if !std::io::IsTerminal::is_terminal(&io::stdin()) {
        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        return Ok(buf.trim().to_string());
    }

    // 3. Interactive prompt
    prompt::prompt_mnemonic()
}

pub fn cmd_generate(keys: &DerivedKeys, key_cmd: &KeyCommand, cli: &Cli) -> Result<(), Error> {
    let do_pgp = matches!(key_cmd, KeyCommand::All | KeyCommand::Pgp { .. });
    let do_ssh = matches!(key_cmd, KeyCommand::All | KeyCommand::Ssh { .. });
    let do_age = matches!(key_cmd, KeyCommand::All | KeyCommand::Age);
    let do_nostr = matches!(key_cmd, KeyCommand::All | KeyCommand::Nostr);
    let do_onion = matches!(key_cmd, KeyCommand::All | KeyCommand::Onion);
    let do_ipfs = matches!(key_cmd, KeyCommand::All | KeyCommand::Ipfs);

    if do_pgp {
        let pgp_keys = pgp::generate(&keys.pgp, &cli.user_id)?;
        let copy = matches!(key_cmd, KeyCommand::Pgp { copy: true });
        output(
            cli,
            "pgp_secret.asc",
            &pgp_keys.secret_key,
            "PGP Secret Key",
        )?;
        output(
            cli,
            "pgp_public.asc",
            &pgp_keys.public_key,
            "PGP Public Key",
        )?;
        if copy {
            copy_to_clipboard(&pgp_keys.public_key)?;
            eprintln!("PGP public key copied to clipboard.");
        }
    }

    if do_ssh {
        let ssh_keys = ssh::generate(&keys.ssh, &cli.comment)?;
        let copy = matches!(key_cmd, KeyCommand::Ssh { copy: true });
        output(cli, "id_ed25519", &ssh_keys.private_key, "SSH Private Key")?;
        output(
            cli,
            "id_ed25519.pub",
            &ssh_keys.public_key,
            "SSH Public Key",
        )?;
        if copy {
            copy_to_clipboard(&ssh_keys.public_key)?;
            eprintln!("SSH public key copied to clipboard.");
        }
    }

    if do_age {
        let ak = age_keys::generate(&keys.age)?;
        let identity_file = format!("# public key: {}\n{}\n", ak.recipient, ak.identity);
        output(cli, "age_identity.txt", &identity_file, "AGE Identity")?;
    }

    if do_nostr {
        let nostr_keys = nostr::generate(&keys.nostr)?;
        let nostr_file = format!(
            "npub: {}\nnsec: {}\npublic (hex): {}\nsecret (hex): {}\n",
            nostr_keys.npub, nostr_keys.nsec, nostr_keys.public_hex, nostr_keys.secret_hex
        );
        output(cli, "nostr_identity.txt", &nostr_file, "Nostr Identity")?;
    }

    if do_onion {
        let onion_keys = onion::generate(&keys.onion)?;
        let hostname_file = format!("{}\n", onion_keys.address);
        output(cli, "hostname", &hostname_file, "Tor Onion Hostname")?;
        output_binary(
            cli,
            "hs_ed25519_secret_key",
            &onion_keys.secret_key_file,
            "Tor Secret Key",
        )?;
        output_binary(
            cli,
            "hs_ed25519_public_key",
            &onion_keys.public_key_file,
            "Tor Public Key",
        )?;
    }

    if do_ipfs {
        let ipfs_keys = ipfs::generate(&keys.ipfs)?;
        let peer_id_file = format!("{}\n", ipfs_keys.peer_id);
        output(cli, "ipfs_peer_id.txt", &peer_id_file, "IPFS Peer ID")?;
        output_binary(
            cli,
            "ipfs_key.protobuf",
            &ipfs_keys.protobuf_key,
            "IPFS Private Key",
        )?;
    }

    Ok(())
}

pub fn cmd_verify(keys: &DerivedKeys, cli: &Cli) -> Result<(), Error> {
    eprintln!("Mnemonic is valid.\n");

    // SSH
    let ssh_keys = ssh::generate(&keys.ssh, &cli.comment)?;
    let pub_key = ssh_key::PublicKey::from_openssh(&ssh_keys.public_key)?;
    let fp = pub_key.fingerprint(ssh_key::HashAlg::Sha256);
    eprintln!("SSH:   {fp}");
    eprintln!("       {}", ssh_keys.public_key);

    // AGE
    let ak = age_keys::generate(&keys.age)?;
    eprintln!("AGE:   {}", ak.recipient);

    // PGP
    let pgp_keys = pgp::generate(&keys.pgp, &cli.user_id)?;
    let pgp_fp = pgp::fingerprint(&pgp_keys.public_key)?;
    eprintln!("PGP:   {pgp_fp}");

    // Nostr
    let nostr_keys = nostr::generate(&keys.nostr)?;
    eprintln!("Nostr: {}", nostr_keys.npub);

    // Onion
    let onion_keys = onion::generate(&keys.onion)?;
    eprintln!("Onion: {}", onion_keys.address);

    // IPFS
    let ipfs_keys = ipfs::generate(&keys.ipfs)?;
    eprintln!("IPFS:  {}", ipfs_keys.peer_id);

    Ok(())
}

pub fn cmd_vault(action: &VaultAction) -> Result<(), Error> {
    match action {
        VaultAction::Store { encrypt } => {
            let mnemonic = if std::io::IsTerminal::is_terminal(&io::stdin()) {
                prompt::prompt_mnemonic()?
            } else {
                let mut buf = String::new();
                io::stdin().read_line(&mut buf)?;
                buf.trim().to_string()
            };

            // Validate before storing
            mnemonic_to_seed(&mnemonic, "")?;

            // Confirmation: ask for a random word
            if std::io::IsTerminal::is_terminal(&io::stdin()) {
                use rand::Rng;
                let words: Vec<&str> = mnemonic.split_whitespace().collect();
                let idx = rand::thread_rng().gen_range(0..words.len());
                let expected = words[idx];

                let answer = prompt::prompt_confirm_word(idx + 1)?;
                if answer != expected {
                    return Err(Error::Command(
                        "confirmation failed — word did not match".into(),
                    ));
                }
            }

            if *encrypt {
                let passphrase = prompt::prompt_passphrase("Set vault passphrase: ")?;
                if passphrase.is_empty() {
                    return Err(Error::Command("passphrase cannot be empty".into()));
                }
                let confirm = prompt::prompt_passphrase("Confirm passphrase: ")?;
                if passphrase != confirm {
                    return Err(Error::Command("passphrases do not match".into()));
                }
                crate::vault::store_encrypted(&mnemonic, &passphrase)?;
                eprintln!("Mnemonic encrypted and stored in OS credential store.");
            } else {
                crate::vault::store(&mnemonic)?;
                eprintln!("Mnemonic stored in OS credential store.");
            }
        }
        VaultAction::Delete => {
            crate::vault::delete()?;
            eprintln!("Mnemonic removed from OS credential store.");
        }
        VaultAction::Status => {
            if crate::vault::is_stored()? {
                if crate::vault::is_encrypted()? {
                    eprintln!("A mnemonic is stored in the OS credential store (encrypted).");
                } else {
                    eprintln!("A mnemonic is stored in the OS credential store.");
                }
            } else {
                eprintln!("No mnemonic stored.");
            }
        }
    }
    Ok(())
}

pub fn cmd_git_setup(cli: &Cli, local: bool) -> Result<(), Error> {
    let scope = if local { "local" } else { "global" };
    eprintln!("This will configure Git ({scope}) to use SSH signing with your Passeport key.\n");

    let mnemonic = load_mnemonic()?;
    let seed = mnemonic_to_seed(&mnemonic, &cli.passphrase)?;
    let keys = derive_keys(&seed)?;
    let ssh_keys = ssh::generate(&keys.ssh, &cli.comment)?;

    let scope_flag = if local { "--local" } else { "--global" };

    let configs = [
        ("gpg.format", "ssh"),
        ("user.signingkey", &ssh_keys.public_key),
        ("commit.gpgsign", "true"),
        ("tag.gpgsign", "true"),
    ];

    for (key, value) in &configs {
        let status = std::process::Command::new("git")
            .args(["config", scope_flag, key, value])
            .status()?;
        if !status.success() {
            return Err(Error::Command(format!("failed to set git config {key}")));
        }
        eprintln!("  git config {scope_flag} {key} {value}");
    }

    eprintln!("\nGit is now configured for SSH commit signing ({scope}).");
    eprintln!("Make sure the Passeport SSH agent is running when you commit.");

    Ok(())
}

/// Search PATH for a pinentry program. Tries common names in order.
pub fn find_pinentry() -> Option<String> {
    let candidates = [
        "pinentry",
        "pinentry-mac",
        "pinentry-gtk-2",
        "pinentry-gnome3",
        "pinentry-qt",
        "pinentry-curses",
        "pinentry-tty",
    ];

    for name in &candidates {
        if which_exists(name) {
            return Some(name.to_string());
        }
    }
    None
}

fn which_exists(program: &str) -> bool {
    #[cfg(windows)]
    {
        std::process::Command::new("where")
            .arg(program)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        std::process::Command::new("which")
            .arg(program)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

fn output(cli: &Cli, filename: &str, content: &str, label: &str) -> Result<(), Error> {
    if let Some(ref dir) = cli.output_dir {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(filename);
        std::fs::write(&path, content)?;
        if !cli.quiet {
            eprintln!("Wrote {label} to {}", path.display());
        }
    } else {
        if !cli.quiet {
            eprintln!("--- {label} ---");
        }
        print!("{content}");
    }
    Ok(())
}

fn output_binary(cli: &Cli, filename: &str, data: &[u8], label: &str) -> Result<(), Error> {
    if let Some(ref dir) = cli.output_dir {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(filename);
        std::fs::write(&path, data)?;
        if !cli.quiet {
            eprintln!("Wrote {label} to {}", path.display());
        }
    } else {
        if !cli.quiet {
            eprintln!("(binary {label} — use -o to write to file)");
        }
    }
    Ok(())
}

pub fn cmd_sign(
    keys: &DerivedKeys,
    file: &Option<PathBuf>,
    output: &Option<PathBuf>,
    format: &SignatureFormat,
    cli: &Cli,
) -> Result<(), Error> {
    use ed25519_dalek::Signer;

    let data = read_input(file)?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&keys.ssh);
    let signature = signing_key.sign(&data);

    match format {
        SignatureFormat::Raw => {
            let sig_bytes = signature.to_bytes();
            let output_path = output.clone().or_else(|| {
                file.as_ref().map(|f| {
                    let mut p = f.as_os_str().to_owned();
                    p.push(".sig");
                    PathBuf::from(p)
                })
            });
            write_output_bytes(&sig_bytes, &output_path)?;
            if !cli.quiet
                && let Some(ref p) = output_path
            {
                eprintln!("Signature written to {}", p.display());
            }
        }
        SignatureFormat::Pgp => {
            let pgp_keys = pgp::generate(&keys.pgp, &cli.user_id)?;
            let signed = pgp_sign_detached(&pgp_keys.secret_key, &data)?;
            let output_path = output.clone().or_else(|| {
                file.as_ref().map(|f| {
                    let mut p = f.as_os_str().to_owned();
                    p.push(".asc");
                    PathBuf::from(p)
                })
            });
            write_output_str(&signed, &output_path)?;
            if !cli.quiet
                && let Some(ref p) = output_path
            {
                eprintln!("PGP signature written to {}", p.display());
            }
        }
    }

    Ok(())
}

pub fn cmd_verify_sig(
    keys: &DerivedKeys,
    file: &PathBuf,
    sig_path: &PathBuf,
    format: &SignatureFormat,
    cli: &Cli,
) -> Result<(), Error> {
    let data = std::fs::read(file)?;
    let sig_data = std::fs::read(sig_path)?;

    match format {
        SignatureFormat::Raw => {
            use ed25519_dalek::Verifier;
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&keys.ssh);
            let verifying_key = signing_key.verifying_key();
            let sig_bytes: [u8; 64] = sig_data.as_slice().try_into().map_err(|_| {
                Error::Command(format!(
                    "invalid signature: expected 64 bytes, got {}",
                    sig_data.len()
                ))
            })?;
            let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
            verifying_key.verify(&data, &signature)?;
        }
        SignatureFormat::Pgp => {
            pgp_verify_detached(&keys.pgp, &cli.user_id, &data, &sig_data)?;
        }
    }

    eprintln!("Signature is valid.");
    Ok(())
}

fn pgp_verify_detached(
    seed: &[u8; 32],
    user_id: &str,
    data: &[u8],
    sig_data: &[u8],
) -> Result<(), Error> {
    use ::pgp::composed::{Deserializable, SignedPublicKey, StandaloneSignature};

    let pgp_keys = pgp::generate(seed, user_id)?;
    let (pub_key, _) =
        SignedPublicKey::from_armor_single(std::io::Cursor::new(&pgp_keys.public_key))?;

    let sig_str = String::from_utf8_lossy(sig_data);
    let (standalone, _) =
        StandaloneSignature::from_armor_single(std::io::Cursor::new(sig_str.as_ref()))?;
    standalone.verify(&pub_key, data)?;

    Ok(())
}

fn pgp_sign_detached(armored_secret: &str, data: &[u8]) -> Result<String, Error> {
    use ::pgp::composed::{Deserializable, SignedSecretKey};
    use ::pgp::crypto::hash::HashAlgorithm;
    use ::pgp::packet::SignatureConfig;
    use ::pgp::types::PublicKeyTrait;

    let (signed_key, _) = SignedSecretKey::from_armor_single(std::io::Cursor::new(armored_secret))?;

    let sig_config = SignatureConfig::v4(
        ::pgp::packet::SignatureType::Binary,
        signed_key.algorithm(),
        HashAlgorithm::SHA2_256,
    );
    let signature = sig_config.sign(&signed_key, || "".to_string(), data)?;
    let standalone = ::pgp::StandaloneSignature::new(signature);
    let armored = standalone.to_armored_string(None.into())?;
    Ok(armored)
}

pub fn cmd_encrypt(
    keys: &DerivedKeys,
    file: &Option<PathBuf>,
    output: &Option<PathBuf>,
    format: &EncryptionFormat,
    extra_recipients: &[String],
    cli: &Cli,
) -> Result<(), Error> {
    let data = read_input(file)?;

    match format {
        EncryptionFormat::Age => {
            let ak = age_keys::generate(&keys.age)?;

            let mut recipients: Vec<Box<dyn ::age::Recipient + Send>> = Vec::new();
            let own: ::age::x25519::Recipient = ak
                .recipient
                .parse()
                .map_err(|e: &str| Error::Age(e.to_string()))?;
            recipients.push(Box::new(own));

            for r in extra_recipients {
                let recipient: ::age::x25519::Recipient =
                    r.parse().map_err(|e: &str| Error::Age(e.to_string()))?;
                recipients.push(Box::new(recipient));
            }

            let encryptor = ::age::Encryptor::with_recipients(
                recipients
                    .iter()
                    .map(|r| r.as_ref() as &dyn ::age::Recipient),
            )?;
            let mut encrypted = vec![];
            let mut writer = encryptor.wrap_output(&mut encrypted)?;
            writer.write_all(&data)?;
            writer.finish()?;

            let output_path = output.clone().or_else(|| {
                file.as_ref().map(|f| {
                    let mut p = f.as_os_str().to_owned();
                    p.push(".age");
                    PathBuf::from(p)
                })
            });
            write_output_bytes(&encrypted, &output_path)?;
            if !cli.quiet
                && let Some(ref p) = output_path
            {
                eprintln!("Encrypted to {}", p.display());
            }
        }
        EncryptionFormat::Pgp => {
            let encrypted = pgp_encrypt(&keys.pgp, &cli.user_id, &data)?;
            let output_path = output.clone().or_else(|| {
                file.as_ref().map(|f| {
                    let mut p = f.as_os_str().to_owned();
                    p.push(".pgp");
                    PathBuf::from(p)
                })
            });
            write_output_str(&encrypted, &output_path)?;
            if !cli.quiet
                && let Some(ref p) = output_path
            {
                eprintln!("PGP encrypted to {}", p.display());
            }
        }
    }

    Ok(())
}

pub fn cmd_decrypt(
    keys: &DerivedKeys,
    file: &Option<PathBuf>,
    output: &Option<PathBuf>,
    format: &EncryptionFormat,
    cli: &Cli,
) -> Result<(), Error> {
    let data = read_input(file)?;

    match format {
        EncryptionFormat::Age => {
            let ak = age_keys::generate(&keys.age)?;
            let identity: ::age::x25519::Identity = ak
                .identity
                .parse()
                .map_err(|e: &str| Error::Age(e.to_string()))?;

            let decryptor = ::age::Decryptor::new(&data[..])?;

            let mut decrypted = vec![];
            let mut reader =
                decryptor.decrypt(std::iter::once(&identity as &dyn ::age::Identity))?;
            reader.read_to_end(&mut decrypted)?;

            write_output_bytes(&decrypted, output)?;
        }
        EncryptionFormat::Pgp => {
            let decrypted = pgp_decrypt(&keys.pgp, &cli.user_id, &data)?;
            write_output_bytes(&decrypted, output)?;
        }
    }

    if !cli.quiet
        && let Some(p) = output
    {
        eprintln!("Decrypted to {}", p.display());
    }

    Ok(())
}

fn pgp_encrypt(seed: &[u8; 32], user_id: &str, data: &[u8]) -> Result<String, Error> {
    use ::pgp::Message;
    use ::pgp::composed::{Deserializable, SignedPublicKey};
    use ::pgp::crypto::sym::SymmetricKeyAlgorithm;
    use ::pgp::types::PublicKeyTrait;

    let pgp_keys = pgp::generate(seed, user_id)?;
    let (pub_key, _) =
        SignedPublicKey::from_armor_single(std::io::Cursor::new(&pgp_keys.public_key))?;

    // Find the ECDH encryption subkey (primary is EdDSA sign-only)
    let enc_subkey = pub_key
        .public_subkeys
        .iter()
        .find(|sk| sk.is_encryption_key())
        .ok_or(Error::Command("no encryption-capable subkey found".into()))?;

    let message = Message::new_literal_bytes("", data);
    let mut rng = rand::thread_rng();
    let encrypted =
        message.encrypt_to_keys_seipdv1(&mut rng, SymmetricKeyAlgorithm::AES256, &[enc_subkey])?;

    Ok(encrypted.to_armored_string(None.into())?)
}

fn pgp_decrypt(seed: &[u8; 32], user_id: &str, data: &[u8]) -> Result<Vec<u8>, Error> {
    use ::pgp::Message;
    use ::pgp::composed::{Deserializable, SignedSecretKey};

    let pgp_keys = pgp::generate(seed, user_id)?;
    let (secret_key, _) =
        SignedSecretKey::from_armor_single(std::io::Cursor::new(&pgp_keys.secret_key))?;

    // Parse the armored PGP message
    let input = String::from_utf8_lossy(data);
    let (message, _) = Message::from_armor_single(std::io::Cursor::new(input.as_ref()))?;

    let (decrypted_msg, _key_ids) = message.decrypt(|| "".to_string(), &[&secret_key])?;

    decrypted_msg
        .get_content()?
        .ok_or_else(|| Error::Command("PGP message contained no data".into()))
}

fn read_input(file: &Option<PathBuf>) -> Result<Vec<u8>, Error> {
    match file {
        Some(path) => Ok(std::fs::read(path)?),
        None => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

fn write_output_bytes(data: &[u8], path: &Option<PathBuf>) -> Result<(), Error> {
    match path {
        Some(p) => {
            std::fs::write(p, data)?;
        }
        None => {
            io::stdout().write_all(data)?;
            io::stdout().flush()?;
        }
    }
    Ok(())
}

fn write_output_str(data: &str, path: &Option<PathBuf>) -> Result<(), Error> {
    write_output_bytes(data.as_bytes(), path)
}

fn copy_to_clipboard(text: &str) -> Result<(), Error> {
    use arboard::Clipboard;
    let mut clipboard = Clipboard::new()?;
    clipboard.set_text(text)?;
    Ok(())
}
