use assert_cmd::Command;
use predicates::prelude::*;

const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

fn ppt() -> Command {
    Command::cargo_bin("ppt").unwrap()
}

/// Check if the OS vault has a stored mnemonic (which takes priority over stdin).
fn vault_has_mnemonic() -> bool {
    let output = ppt().args(["vault", "status"]).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    stderr.contains("A mnemonic is stored")
}

// ---------- init ----------

#[test]
fn init_produces_24_words() {
    let output = ppt().arg("init").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let words: Vec<&str> = stdout.trim().split_whitespace().collect();
    assert_eq!(
        words.len(),
        24,
        "init should produce 24 words, got: {}",
        words.len()
    );
}

#[test]
fn init_produces_valid_mnemonic() {
    let init_output = ppt().arg("init").output().unwrap();
    assert!(init_output.status.success());
    let mnemonic = String::from_utf8_lossy(&init_output.stdout)
        .trim()
        .to_string();

    let verify_output = ppt()
        .arg("verify")
        .write_stdin(format!("{mnemonic}\n"))
        .output()
        .unwrap();
    assert!(verify_output.status.success());
}

// ---------- verify ----------

#[test]
fn verify_prints_all_fingerprints() {
    ppt()
        .arg("verify")
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .success()
        .stderr(
            predicate::str::contains("SSH:")
                .and(predicate::str::contains("AGE:"))
                .and(predicate::str::contains("PGP:"))
                .and(predicate::str::contains("Nostr:"))
                .and(predicate::str::contains("Onion:"))
                .and(predicate::str::contains("IPFS:"))
                .and(predicate::str::contains("Mnemonic is valid.")),
        );
}

#[test]
fn verify_rejects_invalid_mnemonic() {
    if vault_has_mnemonic() {
        eprintln!("skipping: vault mnemonic present");
        return;
    }
    ppt()
        .arg("verify")
        .write_stdin("bad words here\n")
        .assert()
        .failure();
}

#[test]
fn verify_rejects_12_word_mnemonic() {
    if vault_has_mnemonic() {
        eprintln!("skipping: vault mnemonic present");
        return;
    }
    ppt()
        .arg("verify")
        .write_stdin("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n")
        .assert()
        .failure();
}

// ---------- key ssh ----------

#[test]
fn ssh_outputs_keypair() {
    ppt()
        .args(["key", "ssh"])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .success()
        .stdout(
            predicate::str::contains("BEGIN OPENSSH PRIVATE KEY")
                .and(predicate::str::contains("ssh-ed25519")),
        );
}

#[test]
fn ssh_deterministic() {
    let out1 = ppt()
        .args(["key", "ssh", "-q"])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .output()
        .unwrap();
    let out2 = ppt()
        .args(["key", "ssh", "-q"])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .output()
        .unwrap();
    assert_eq!(
        out1.stdout, out2.stdout,
        "SSH output should be deterministic"
    );
}

// ---------- key pgp ----------

#[test]
fn pgp_outputs_armored_keys() {
    ppt()
        .args(["key", "pgp"])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .success()
        .stdout(
            predicate::str::contains("BEGIN PGP PRIVATE KEY BLOCK")
                .and(predicate::str::contains("BEGIN PGP PUBLIC KEY BLOCK")),
        );
}

// ---------- key age ----------

#[test]
fn age_outputs_identity() {
    ppt()
        .args(["key", "age"])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("AGE-SECRET-KEY-").and(predicate::str::contains("age1")));
}

// ---------- key nostr ----------

#[test]
fn nostr_outputs_keys() {
    ppt()
        .args(["key", "nostr"])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("npub1").and(predicate::str::contains("nsec1")));
}

// ---------- key onion ----------

#[test]
fn onion_outputs_address() {
    ppt()
        .args(["key", "onion"])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains(".onion"));
}

// ---------- key ipfs ----------

#[test]
fn ipfs_outputs_peer_id() {
    ppt()
        .args(["key", "ipfs"])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("12D3KooW"));
}

// ---------- key all ----------

#[test]
fn key_all_outputs_all_keys() {
    ppt()
        .args(["key", "all"])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .success()
        .stdout(
            predicate::str::contains("BEGIN OPENSSH PRIVATE KEY")
                .and(predicate::str::contains("ssh-ed25519"))
                .and(predicate::str::contains("BEGIN PGP PRIVATE KEY BLOCK"))
                .and(predicate::str::contains("AGE-SECRET-KEY-"))
                .and(predicate::str::contains("npub1"))
                .and(predicate::str::contains(".onion"))
                .and(predicate::str::contains("12D3KooW")),
        );
}

// ---------- key all -o ----------

#[test]
fn key_all_to_output_dir() {
    let tmp = std::env::temp_dir().join("ppt-test-output");
    let _ = std::fs::remove_dir_all(&tmp);

    ppt()
        .args(["key", "all", "-o", tmp.to_str().unwrap()])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .success();

    assert!(
        tmp.join("id_ed25519").exists(),
        "SSH private key file missing"
    );
    assert!(
        tmp.join("id_ed25519.pub").exists(),
        "SSH public key file missing"
    );
    assert!(
        tmp.join("pgp_secret.asc").exists(),
        "PGP secret key file missing"
    );
    assert!(
        tmp.join("pgp_public.asc").exists(),
        "PGP public key file missing"
    );
    assert!(
        tmp.join("age_identity.txt").exists(),
        "AGE identity file missing"
    );
    assert!(
        tmp.join("nostr_identity.txt").exists(),
        "Nostr identity file missing"
    );
    assert!(tmp.join("hostname").exists(), "Tor hostname file missing");
    assert!(
        tmp.join("hs_ed25519_secret_key").exists(),
        "Tor secret key file missing"
    );
    assert!(
        tmp.join("hs_ed25519_public_key").exists(),
        "Tor public key file missing"
    );
    assert!(
        tmp.join("ipfs_peer_id.txt").exists(),
        "IPFS peer ID file missing"
    );
    assert!(
        tmp.join("ipfs_key.protobuf").exists(),
        "IPFS protobuf key file missing"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------- quiet flag ----------

#[test]
fn quiet_suppresses_labels() {
    let output = ppt()
        .args(["key", "ssh", "-q"])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("--- SSH"),
        "quiet flag should suppress labels"
    );
}

// ---------- passphrase ----------

#[test]
fn passphrase_changes_output() {
    let out_no_pass = ppt()
        .args(["key", "ssh", "-q"])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .output()
        .unwrap();
    let out_with_pass = ppt()
        .args(["key", "ssh", "-q", "-p", "mypassphrase"])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .output()
        .unwrap();
    assert_ne!(
        out_no_pass.stdout, out_with_pass.stdout,
        "different passphrase should produce different keys"
    );
}

// ---------- sign ----------

#[test]
fn sign_produces_64_byte_signature() {
    let tmp = std::env::temp_dir().join("ppt-test-sign-input.txt");
    std::fs::write(&tmp, b"hello world\n").unwrap();
    let sig_path = std::env::temp_dir().join("ppt-test-sign-output.sig");
    let _ = std::fs::remove_file(&sig_path);

    ppt()
        .args([
            "sign",
            tmp.to_str().unwrap(),
            "--output",
            sig_path.to_str().unwrap(),
        ])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .success();

    let sig = std::fs::read(&sig_path).unwrap();
    assert_eq!(sig.len(), 64, "Ed25519 signature should be 64 bytes");

    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_file(&sig_path);
}

#[test]
fn sign_pgp_produces_armored_output() {
    let tmp = std::env::temp_dir().join("ppt-test-sign-pgp.txt");
    std::fs::write(&tmp, b"hello world\n").unwrap();

    let output = ppt()
        .args(["sign", tmp.to_str().unwrap(), "-f", "pgp"])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .output()
        .unwrap();
    assert!(output.status.success());

    let asc_path = std::env::temp_dir().join("ppt-test-sign-pgp.txt.asc");
    if asc_path.exists() {
        let content = std::fs::read_to_string(&asc_path).unwrap();
        assert!(
            content.contains("BEGIN PGP SIGNATURE"),
            "should be PGP armored"
        );
        let _ = std::fs::remove_file(&asc_path);
    }

    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn sign_deterministic() {
    let tmp = std::env::temp_dir().join("ppt-test-sign-det.txt");
    std::fs::write(&tmp, b"determinism test\n").unwrap();
    let sig1_path = std::env::temp_dir().join("ppt-test-sign-det1.sig");
    let sig2_path = std::env::temp_dir().join("ppt-test-sign-det2.sig");

    ppt()
        .args([
            "sign",
            tmp.to_str().unwrap(),
            "--output",
            sig1_path.to_str().unwrap(),
        ])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .success();
    ppt()
        .args([
            "sign",
            tmp.to_str().unwrap(),
            "--output",
            sig2_path.to_str().unwrap(),
        ])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .success();

    let sig1 = std::fs::read(&sig1_path).unwrap();
    let sig2 = std::fs::read(&sig2_path).unwrap();
    assert_eq!(sig1, sig2, "signatures should be deterministic");

    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_file(&sig1_path);
    let _ = std::fs::remove_file(&sig2_path);
}

// ---------- encrypt / decrypt ----------

#[test]
fn encrypt_decrypt_round_trip() {
    let plaintext = b"secret message for round-trip test";
    let input_path = std::env::temp_dir().join("ppt-test-enc-input.txt");
    let enc_path = std::env::temp_dir().join("ppt-test-enc-output.age");
    let dec_path = std::env::temp_dir().join("ppt-test-dec-output.txt");
    std::fs::write(&input_path, plaintext).unwrap();

    ppt()
        .args([
            "encrypt",
            input_path.to_str().unwrap(),
            "--output",
            enc_path.to_str().unwrap(),
        ])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .success();

    assert!(enc_path.exists(), "encrypted file should exist");
    let enc_data = std::fs::read(&enc_path).unwrap();
    assert_ne!(
        enc_data, plaintext,
        "encrypted data should differ from plaintext"
    );

    ppt()
        .args([
            "decrypt",
            enc_path.to_str().unwrap(),
            "--output",
            dec_path.to_str().unwrap(),
        ])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .success();

    let decrypted = std::fs::read(&dec_path).unwrap();
    assert_eq!(decrypted, plaintext, "decrypted data should match original");

    let _ = std::fs::remove_file(&input_path);
    let _ = std::fs::remove_file(&enc_path);
    let _ = std::fs::remove_file(&dec_path);
}

#[test]
fn pgp_encrypt_decrypt_round_trip() {
    let plaintext = b"pgp round-trip secret";
    let input_path = std::env::temp_dir().join("ppt-test-pgp-enc-input.txt");
    let enc_path = std::env::temp_dir().join("ppt-test-pgp-enc-output.pgp");
    let dec_path = std::env::temp_dir().join("ppt-test-pgp-dec-output.txt");
    std::fs::write(&input_path, plaintext).unwrap();

    ppt()
        .args([
            "encrypt",
            "-f",
            "pgp",
            input_path.to_str().unwrap(),
            "--output",
            enc_path.to_str().unwrap(),
        ])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .success();

    let enc_data = std::fs::read_to_string(&enc_path).unwrap();
    assert!(
        enc_data.contains("BEGIN PGP MESSAGE"),
        "should be PGP armored message"
    );

    ppt()
        .args([
            "decrypt",
            "-f",
            "pgp",
            enc_path.to_str().unwrap(),
            "--output",
            dec_path.to_str().unwrap(),
        ])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .success();

    let decrypted = std::fs::read(&dec_path).unwrap();
    assert_eq!(
        decrypted, plaintext,
        "PGP decrypted data should match original"
    );

    let _ = std::fs::remove_file(&input_path);
    let _ = std::fs::remove_file(&enc_path);
    let _ = std::fs::remove_file(&dec_path);
}

#[test]
fn decrypt_with_wrong_passphrase_fails() {
    let input_path = std::env::temp_dir().join("ppt-test-enc-wrong.txt");
    let enc_path = std::env::temp_dir().join("ppt-test-enc-wrong.age");
    std::fs::write(&input_path, b"secret").unwrap();

    ppt()
        .args([
            "encrypt",
            input_path.to_str().unwrap(),
            "--output",
            enc_path.to_str().unwrap(),
        ])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .success();

    ppt()
        .args([
            "decrypt",
            enc_path.to_str().unwrap(),
            "-p",
            "wrongpassphrase",
        ])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .failure();

    let _ = std::fs::remove_file(&input_path);
    let _ = std::fs::remove_file(&enc_path);
}

// ---------- verify-sig ----------

#[test]
fn verify_sig_raw_round_trip() {
    let msg_path = std::env::temp_dir().join("ppt-test-vsig-msg.txt");
    let sig_path = std::env::temp_dir().join("ppt-test-vsig-msg.sig");
    std::fs::write(&msg_path, b"verify me\n").unwrap();

    // Sign
    ppt()
        .args([
            "sign",
            msg_path.to_str().unwrap(),
            "--output",
            sig_path.to_str().unwrap(),
        ])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .success();

    // Verify
    ppt()
        .args([
            "verify-sig",
            msg_path.to_str().unwrap(),
            "--sig",
            sig_path.to_str().unwrap(),
        ])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .success()
        .stderr(predicate::str::contains("Signature is valid"));

    let _ = std::fs::remove_file(&msg_path);
    let _ = std::fs::remove_file(&sig_path);
}

#[test]
fn verify_sig_pgp_round_trip() {
    let msg_path = std::env::temp_dir().join("ppt-test-vsig-pgp-msg.txt");
    let sig_path = std::env::temp_dir().join("ppt-test-vsig-pgp-msg.asc");
    std::fs::write(&msg_path, b"verify pgp\n").unwrap();

    // Sign with PGP
    ppt()
        .args([
            "sign",
            "-f",
            "pgp",
            msg_path.to_str().unwrap(),
            "--output",
            sig_path.to_str().unwrap(),
        ])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .success();

    // Verify with PGP
    ppt()
        .args([
            "verify-sig",
            "-f",
            "pgp",
            msg_path.to_str().unwrap(),
            "--sig",
            sig_path.to_str().unwrap(),
        ])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .success()
        .stderr(predicate::str::contains("Signature is valid"));

    let _ = std::fs::remove_file(&msg_path);
    let _ = std::fs::remove_file(&sig_path);
}

#[test]
fn verify_sig_rejects_tampered_file() {
    let msg_path = std::env::temp_dir().join("ppt-test-vsig-tamper.txt");
    let sig_path = std::env::temp_dir().join("ppt-test-vsig-tamper.sig");
    std::fs::write(&msg_path, b"original content\n").unwrap();

    // Sign
    ppt()
        .args([
            "sign",
            msg_path.to_str().unwrap(),
            "--output",
            sig_path.to_str().unwrap(),
        ])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .success();

    // Tamper with the file
    std::fs::write(&msg_path, b"tampered content\n").unwrap();

    // Verify should fail
    ppt()
        .args([
            "verify-sig",
            msg_path.to_str().unwrap(),
            "--sig",
            sig_path.to_str().unwrap(),
        ])
        .write_stdin(format!("{TEST_MNEMONIC}\n"))
        .assert()
        .failure();

    let _ = std::fs::remove_file(&msg_path);
    let _ = std::fs::remove_file(&sig_path);
}

// ---------- completions ----------

#[test]
fn completions_bash() {
    ppt()
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("complete"));
}

// ---------- vault status ----------

#[test]
fn vault_status_when_empty() {
    let output = ppt().args(["vault", "status"]).output().unwrap();
    assert!(output.status.success());
}
