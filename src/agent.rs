use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::Signer;
use ssh_agent_lib::agent::{Session, listen};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, SignRequest};
use ssh_key::public::{Ed25519PublicKey, KeyData};
use ssh_key::{Algorithm, Signature};
use tokio::sync::Mutex;

/// Simple error wrapper for AgentError::other which requires std::error::Error.
#[derive(Debug)]
struct AgentErr(String);
impl std::fmt::Display for AgentErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for AgentErr {}

/// Configuration for the agent's challenge/lock behavior.
#[derive(Clone)]
pub struct AgentConfig {
    /// How long before the agent locks and requires re-verification.
    /// None = never lock.
    pub timeout: Option<Duration>,
    /// Path to pinentry program (e.g. "pinentry", "pinentry-mac", "pinentry-gtk-2").
    /// None = use built-in terminal prompt.
    pub pinentry_program: Option<String>,
}

/// SSH agent that holds a single Ed25519 key derived from a mnemonic,
/// with optional timeout-based locking and pinentry challenge.
#[derive(Clone)]
pub struct PasseportAgent {
    signing_key: Arc<ed25519_dalek::SigningKey>,
    public_key: KeyData,
    comment: String,
    /// The mnemonic words, kept for challenge verification.
    mnemonic_words: Arc<Vec<String>>,
    /// Timestamp of last successful signing or unlock.
    last_activity: Arc<Mutex<Instant>>,
    config: AgentConfig,
}

impl PasseportAgent {
    pub fn new(
        seed: &[u8; 32],
        comment: String,
        mnemonic_words: Vec<String>,
        config: AgentConfig,
    ) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        let public_key = KeyData::Ed25519(Ed25519PublicKey(verifying_key.to_bytes()));

        let signing_key = Arc::new(signing_key);
        let mnemonic_words = Arc::new(mnemonic_words);

        // Best-effort mlock to prevent key material from being swapped to disk
        crate::mlock::mlock_value(signing_key.as_ref());
        crate::mlock::mlock_value(mnemonic_words.as_ref());

        Self {
            signing_key,
            public_key,
            comment,
            mnemonic_words,
            last_activity: Arc::new(Mutex::new(Instant::now())),
            config,
        }
    }

    /// Check if the agent is locked (timeout expired) and if so, challenge.
    /// Returns Ok(()) if unlocked or challenge passed, Err if challenge failed.
    async fn ensure_unlocked(&self) -> Result<(), AgentError> {
        let timeout = match self.config.timeout {
            Some(t) => t,
            None => return Ok(()), // no timeout configured
        };

        let mut last = self.last_activity.lock().await;
        let elapsed = last.elapsed();
        if elapsed < timeout {
            // Warn when 60 seconds or less remain
            let remaining = timeout - elapsed;
            if remaining <= Duration::from_secs(60) {
                eprintln!("Warning: agent will lock in {}s", remaining.as_secs());
            }
            return Ok(());
        }

        // Locked — need to challenge
        eprintln!("Agent locked (timeout). Requesting verification...");

        let challenge_result = tokio::task::spawn_blocking({
            let words = self.mnemonic_words.clone();
            let pinentry = self.config.pinentry_program.clone();
            move || run_challenge(&words, pinentry.as_deref())
        })
        .await
        .map_err(|e| AgentError::other(AgentErr(e.to_string())))?;

        match challenge_result {
            Ok(()) => {
                *last = Instant::now();
                eprintln!("Verification successful. Agent unlocked.");
                Ok(())
            }
            Err(e) => {
                eprintln!("Verification failed: {e}");
                Err(AgentError::other(AgentErr(format!(
                    "verification failed: {e}"
                ))))
            }
        }
    }
}

#[ssh_agent_lib::async_trait]
impl Session for PasseportAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        // Always return identities, even when locked — clients need to know
        // which keys are available before requesting a signature.
        Ok(vec![Identity {
            pubkey: self.public_key.clone(),
            comment: self.comment.clone(),
        }])
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        if request.pubkey != self.public_key {
            return Err(AgentError::other(AgentErr("unknown key".into())));
        }

        // Challenge if locked
        self.ensure_unlocked().await?;

        // Update activity timestamp
        *self.last_activity.lock().await = Instant::now();

        let signature = self.signing_key.sign(&request.data);
        Signature::new(Algorithm::Ed25519, signature.to_bytes().to_vec())
            .map_err(|e| AgentError::other(AgentErr(e.to_string())))
    }
}

/// Pick a random word index and verify the user knows it.
fn run_challenge(words: &[String], pinentry_program: Option<&str>) -> Result<(), String> {
    use rand::Rng;
    let idx = rand::thread_rng().gen_range(0..words.len());
    let expected = &words[idx];
    let word_num = idx + 1;

    let answer = match pinentry_program {
        Some(program) => pinentry_ask(
            program,
            &format!(
                "Passeport agent is locked.\nEnter word #{word_num} of your mnemonic to unlock."
            ),
            &format!("Word #{word_num}:"),
        )?,
        None => terminal_ask(&format!(
            "Agent locked. Enter word #{word_num} of your mnemonic: "
        ))?,
    };

    if answer.trim() == expected.as_str() {
        Ok(())
    } else {
        Err("incorrect word".into())
    }
}

/// Ask for a word using the pinentry protocol.
fn pinentry_ask(program: &str, description: &str, prompt: &str) -> Result<String, String> {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};

    let mut child = Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn {program}: {e}"))?;

    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let mut reader = BufReader::new(stdout);

    // Read initial OK
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("read error: {e}"))?;
    if !line.starts_with("OK") {
        return Err(format!("pinentry didn't greet with OK: {line}"));
    }

    // Percent-encode description and prompt for Assuan
    let desc_encoded = assuan_encode(description);
    let prompt_encoded = assuan_encode(prompt);

    let commands = format!(
        "SETTITLE Passeport\nSETDESC {desc_encoded}\nSETPROMPT {prompt_encoded}\nGETPIN\nBYE\n"
    );
    stdin
        .write_all(commands.as_bytes())
        .map_err(|e| format!("write error: {e}"))?;
    stdin.flush().map_err(|e| format!("flush error: {e}"))?;
    drop(stdin);

    // Read responses until we get D <data> or ERR
    let mut pin = None;
    for resp in reader.lines() {
        let resp = resp.map_err(|e| format!("read error: {e}"))?;
        if let Some(data) = resp.strip_prefix("D ") {
            pin = Some(data.to_string());
        } else if resp.starts_with("ERR") {
            return Err("pinentry cancelled or failed".into());
        }
    }

    let _ = child.wait();
    pin.ok_or_else(|| "no PIN received from pinentry".into())
}

/// Percent-encode a string for the Assuan protocol.
pub fn assuan_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '%' => out.push_str("%25"),
            '\n' => out.push_str("%0A"),
            '\r' => out.push_str("%0D"),
            _ => out.push(c),
        }
    }
    out
}

/// Fallback: ask on the terminal directly (only works if agent has a terminal).
fn terminal_ask(prompt: &str) -> Result<String, String> {
    use std::io::{self, BufRead, Write};

    let mut stderr = io::stderr();
    stderr
        .write_all(prompt.as_bytes())
        .map_err(|e| format!("write error: {e}"))?;
    stderr.flush().map_err(|e| format!("flush error: {e}"))?;

    let mut answer = String::new();
    io::stdin()
        .lock()
        .read_line(&mut answer)
        .map_err(|e| format!("read error: {e}"))?;
    Ok(answer.trim().to_string())
}

/// Fork to background like ssh-agent. Must be called before creating a tokio
/// runtime (forking after threads are spawned is unsafe).
///
/// The parent process prints `SSH_AUTH_SOCK` and `SSH_AGENT_PID` to stdout
/// (suitable for `eval $(ppt agent)`) and exits. The child continues and
/// should proceed to call [`run`].
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn daemonize(ssh_seed: &[u8; 32], comment: &str) -> Result<(), crate::error::Error> {
    let socket_path = get_socket_path_unix();

    // Check before forking so the parent can exit quickly.
    if is_agent_running(&socket_path) {
        println!("SSH_AUTH_SOCK={socket_path}; export SSH_AUTH_SOCK;");
        eprintln!("# Agent already running on {socket_path}");
        std::process::exit(0);
    }

    // Print key info before forking so the user sees it.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(ssh_seed);
    let verifying_key = signing_key.verifying_key();
    let public_key = KeyData::Ed25519(Ed25519PublicKey(verifying_key.to_bytes()));
    let pub_key = ssh_key::PublicKey::new(public_key, comment);
    let fingerprint = pub_key.fingerprint(ssh_key::HashAlg::Sha256);
    eprintln!("# SSH key loaded: {fingerprint}");

    // SAFETY: called before any threads are spawned (no tokio runtime yet).
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => {
            Err(crate::error::Error::Agent("fork() failed".into()))
        }
        0 => {
            // Child: new session, detach from terminal, redirect fds.
            unsafe { libc::setsid() };

            // Redirect stdin/stdout/stderr to /dev/null.
            let devnull = std::fs::File::open("/dev/null").ok();
            if let Some(f) = &devnull {
                use std::os::unix::io::AsRawFd;
                let fd = f.as_raw_fd();
                unsafe {
                    libc::dup2(fd, 0); // stdin
                    libc::dup2(fd, 1); // stdout
                    libc::dup2(fd, 2); // stderr
                }
            }

            // Child continues — caller will create the runtime and call run().
            Ok(())
        }
        child_pid => {
            // Parent: print env vars and exit.
            println!("SSH_AUTH_SOCK={socket_path}; export SSH_AUTH_SOCK;");
            println!("SSH_AGENT_PID={child_pid}; export SSH_AGENT_PID;");
            std::process::exit(0);
        }
    }
}

/// Run the SSH agent, listening for connections until interrupted.
pub async fn run(
    seed: &[u8; 32],
    comment: String,
    mnemonic_words: Vec<String>,
    config: AgentConfig,
) -> Result<(), crate::error::Error> {
    let agent = PasseportAgent::new(seed, comment.clone(), mnemonic_words, config.clone());

    // Print public key info to stderr
    let pub_key = ssh_key::PublicKey::new(agent.public_key.clone(), &comment);
    let fingerprint = pub_key.fingerprint(ssh_key::HashAlg::Sha256);
    eprintln!("# SSH key loaded: {fingerprint}");
    eprintln!("# Public key: {}", pub_key.to_openssh()?);
    if let Some(timeout) = config.timeout {
        eprintln!("# Lock timeout: {}s", timeout.as_secs());
        if let Some(ref prog) = config.pinentry_program {
            eprintln!("# Pinentry: {prog}");
        } else {
            eprintln!("# Pinentry: (built-in terminal prompt)");
        }
    } else {
        eprintln!("# Lock timeout: disabled");
    }

    #[cfg(unix)]
    {
        let socket_path = get_socket_path_unix();

        // If an agent is already running on this socket, just print the
        // SSH_AUTH_SOCK line and exit successfully so `eval $(ppt agent)`
        // works idempotently (important for login services / shell profiles).
        if is_agent_running(&socket_path) {
            println!("SSH_AUTH_SOCK={socket_path}; export SSH_AUTH_SOCK;");
            eprintln!("# Agent already running on {socket_path}");
            return Ok(());
        }

        // Clean up stale socket
        let _ = std::fs::remove_file(&socket_path);

        let listener = tokio::net::UnixListener::bind(&socket_path)?;

        // Print SSH_AUTH_SOCK for eval
        println!("SSH_AUTH_SOCK={socket_path}; export SSH_AUTH_SOCK;");
        eprintln!("# Agent listening on {socket_path}");
        eprintln!("# Run: eval $(ppt agent)");
        eprintln!("# Press Ctrl+C to stop.");

        tokio::select! {
            result = listen(listener, agent) => {
                result.map_err(|e| crate::error::Error::Agent(e.to_string()))?;
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nShutting down...");
            }
        }

        // Cleanup socket
        let _ = std::fs::remove_file(&socket_path);
    }

    #[cfg(windows)]
    {
        use ssh_agent_lib::agent::NamedPipeListener;

        let pipe_name = r"\\.\pipe\passeport-ssh-agent";
        let listener = NamedPipeListener::bind(pipe_name)?;

        println!("$env:SSH_AUTH_SOCK=\"{pipe_name}\"");
        eprintln!("# Agent listening on {pipe_name}");
        eprintln!("# Press Ctrl+C to stop.");

        tokio::select! {
            result = listen(listener, agent) => {
                result.map_err(|e| crate::error::Error::Agent(e.to_string()))?;
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nShutting down...");
            }
        }
    }

    Ok(())
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn get_socket_path_unix() -> String {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        format!("{runtime_dir}/passeport-agent.sock")
    } else {
        // SAFETY: libc::getuid() is a trivial syscall with no invariants.
        let uid = unsafe { libc::getuid() };
        format!("/tmp/passeport-agent-{uid}.sock")
    }
}

/// Check if an agent is already listening on the given socket path.
#[cfg(unix)]
fn is_agent_running(socket_path: &str) -> bool {
    std::os::unix::net::UnixStream::connect(socket_path).is_ok()
}
