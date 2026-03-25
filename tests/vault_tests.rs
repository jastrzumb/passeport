/// Vault round-trip tests.
///
/// Each test uses its own isolated credential store entry via
/// `Vault::with_service()` so tests can run in parallel without
/// interfering with each other or the user's real stored mnemonic.
///
/// Run locally with:
///   cargo test --test vault_tests -- --ignored
use passeport::vault::Vault;

const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

/// Full round-trip: store → load → is_stored → delete → load (None).
#[test]
#[ignore = "requires OS credential store — run with: cargo test --test vault_tests -- --ignored"]
fn vault_round_trip() {
    let v = Vault::with_service("passeport-test-round-trip");
    let _ = v.delete();

    assert!(!v.is_stored().unwrap(), "vault should start empty");
    assert!(v.load().unwrap().is_none(), "load should return None");

    v.store(TEST_MNEMONIC).unwrap();
    assert!(v.is_stored().unwrap(), "vault should report stored");

    let loaded = v.load().unwrap();
    assert_eq!(
        loaded.as_deref(),
        Some(TEST_MNEMONIC),
        "loaded mnemonic should match stored"
    );

    v.delete().unwrap();
    assert!(
        !v.is_stored().unwrap(),
        "vault should be empty after delete"
    );
    assert!(
        v.load().unwrap().is_none(),
        "load should return None after delete"
    );
}

/// Deleting when nothing is stored should not error.
#[test]
#[ignore = "requires OS credential store — run with: cargo test --test vault_tests -- --ignored"]
fn vault_delete_when_empty() {
    let v = Vault::with_service("passeport-test-delete-empty");
    let _ = v.delete();
    v.delete().unwrap();
}

/// Storing twice should overwrite without error.
#[test]
#[ignore = "requires OS credential store — run with: cargo test --test vault_tests -- --ignored"]
fn vault_overwrite() {
    let v = Vault::with_service("passeport-test-overwrite");
    let _ = v.delete();

    let mnemonic_a = TEST_MNEMONIC;
    let mnemonic_b = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";

    v.store(mnemonic_a).unwrap();
    assert_eq!(v.load().unwrap().as_deref(), Some(mnemonic_a));

    v.store(mnemonic_b).unwrap();
    assert_eq!(v.load().unwrap().as_deref(), Some(mnemonic_b));

    v.delete().unwrap();
}
