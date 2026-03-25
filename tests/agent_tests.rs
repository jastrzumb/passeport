use std::time::Duration;

use passeport::agent::{AgentConfig, PasseportAgent, assuan_encode};
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::proto::SignRequest;
use ssh_key::public::{Ed25519PublicKey, KeyData};

fn test_seed() -> [u8; 32] {
    [0x42u8; 32]
}

fn test_words() -> Vec<String> {
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        .split_whitespace()
        .map(String::from)
        .collect()
}

fn make_agent(timeout: Option<Duration>) -> PasseportAgent {
    PasseportAgent::new(
        &test_seed(),
        "test".to_string(),
        test_words(),
        AgentConfig {
            timeout,
            pinentry_program: None,
        },
    )
}

// ---------- request_identities ----------

#[tokio::test]
async fn request_identities_returns_one_key() {
    let mut agent = make_agent(None);
    let identities = agent.request_identities().await.unwrap();
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].comment, "test");
}

#[tokio::test]
async fn request_identities_returns_ed25519_key() {
    let mut agent = make_agent(None);
    let identities = agent.request_identities().await.unwrap();
    assert!(
        matches!(identities[0].pubkey, KeyData::Ed25519(_)),
        "expected Ed25519 key"
    );
}

#[tokio::test]
async fn request_identities_deterministic() {
    let mut agent1 = make_agent(None);
    let mut agent2 = make_agent(None);
    let ids1 = agent1.request_identities().await.unwrap();
    let ids2 = agent2.request_identities().await.unwrap();
    assert_eq!(ids1[0].pubkey, ids2[0].pubkey);
}

// ---------- sign ----------

#[tokio::test]
async fn sign_with_correct_key_succeeds() {
    let mut agent = make_agent(None);
    let identities = agent.request_identities().await.unwrap();
    let pubkey = identities[0].pubkey.clone();

    let request = SignRequest {
        pubkey,
        data: b"hello world".to_vec(),
        flags: 0,
    };

    let signature = agent.sign(request).await.unwrap();
    assert_eq!(signature.algorithm(), ssh_key::Algorithm::Ed25519);
    assert!(!signature.as_bytes().is_empty());
}

#[tokio::test]
async fn sign_with_wrong_key_fails() {
    let mut agent = make_agent(None);

    // Use a different public key
    let wrong_key = KeyData::Ed25519(Ed25519PublicKey([0xFFu8; 32]));
    let request = SignRequest {
        pubkey: wrong_key,
        data: b"hello".to_vec(),
        flags: 0,
    };

    let result = agent.sign(request).await;
    assert!(result.is_err(), "signing with wrong key should fail");
}

#[tokio::test]
async fn sign_produces_valid_ed25519_signature() {
    let mut agent = make_agent(None);
    let identities = agent.request_identities().await.unwrap();
    let pubkey = identities[0].pubkey.clone();

    let data = b"test message for signing";
    let request = SignRequest {
        pubkey,
        data: data.to_vec(),
        flags: 0,
    };

    let signature = agent.sign(request).await.unwrap();

    // Ed25519 signatures are 64 bytes
    assert_eq!(signature.as_bytes().len(), 64);
}

#[tokio::test]
async fn sign_deterministic_for_same_data() {
    let mut agent1 = make_agent(None);
    let mut agent2 = make_agent(None);
    let ids = agent1.request_identities().await.unwrap();
    let pubkey = ids[0].pubkey.clone();

    let data = b"determinism test";

    let sig1 = agent1
        .sign(SignRequest {
            pubkey: pubkey.clone(),
            data: data.to_vec(),
            flags: 0,
        })
        .await
        .unwrap();

    let sig2 = agent2
        .sign(SignRequest {
            pubkey,
            data: data.to_vec(),
            flags: 0,
        })
        .await
        .unwrap();

    assert_eq!(sig1.as_bytes(), sig2.as_bytes());
}

#[tokio::test]
async fn sign_different_data_different_signatures() {
    let mut agent = make_agent(None);
    let ids = agent.request_identities().await.unwrap();
    let pubkey = ids[0].pubkey.clone();

    let sig1 = agent
        .sign(SignRequest {
            pubkey: pubkey.clone(),
            data: b"message one".to_vec(),
            flags: 0,
        })
        .await
        .unwrap();

    let sig2 = agent
        .sign(SignRequest {
            pubkey,
            data: b"message two".to_vec(),
            flags: 0,
        })
        .await
        .unwrap();

    assert_ne!(sig1.as_bytes(), sig2.as_bytes());
}

// ---------- assuan_encode ----------

#[test]
fn assuan_encode_plain_text() {
    assert_eq!(assuan_encode("hello world"), "hello world");
}

#[test]
fn assuan_encode_percent() {
    assert_eq!(assuan_encode("100%"), "100%25");
}

#[test]
fn assuan_encode_newlines() {
    assert_eq!(
        assuan_encode("line1\nline2\r\nline3"),
        "line1%0Aline2%0D%0Aline3"
    );
}

#[test]
fn assuan_encode_mixed() {
    assert_eq!(
        assuan_encode("100% done\nnext line"),
        "100%25 done%0Anext line"
    );
}

#[test]
fn assuan_encode_empty() {
    assert_eq!(assuan_encode(""), "");
}
