use clap::{CommandFactory, Parser};

use passeport::cli::{Cli, Command, InitAction};
use passeport::commands::{
    cmd_decrypt, cmd_encrypt, cmd_generate, cmd_git_setup, cmd_sign, cmd_vault, cmd_verify,
    cmd_verify_sig, find_pinentry, load_mnemonic,
};
use passeport::derive::derive_keys;
use passeport::mnemonic::{generate_mnemonic, mnemonic_to_seed};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Commands that don't need a mnemonic
    match &cli.command {
        Command::Init { action: None } => {
            let phrase = generate_mnemonic();
            println!("{phrase}");
            return Ok(());
        }
        Command::Init {
            action: Some(InitAction::Git { local }),
        } => {
            cmd_git_setup(&cli, *local)?;
            return Ok(());
        }
        Command::Vault { action } => {
            cmd_vault(action)?;
            return Ok(());
        }
        Command::Completions { shell } => {
            clap_complete::generate(*shell, &mut Cli::command(), "ppt", &mut std::io::stdout());
            return Ok(());
        }
        Command::ManPage => {
            let man = clap_mangen::Man::new(Cli::command());
            man.render(&mut std::io::stdout())?;
            return Ok(());
        }
        _ => {}
    }

    // All other commands need the mnemonic
    let mnemonic = load_mnemonic()?;

    let seed = mnemonic_to_seed(&mnemonic, &cli.passphrase)?;
    let keys = derive_keys(&seed)?;

    let mnemonic_words: Vec<String> = mnemonic.split_whitespace().map(String::from).collect();

    match &cli.command {
        Command::Agent {
            timeout,
            pinentry_program,
        } => {
            let config = passeport::agent::AgentConfig {
                timeout: if *timeout > 0 {
                    Some(std::time::Duration::from_secs(timeout * 60))
                } else {
                    None
                },
                pinentry_program: pinentry_program.clone().or_else(find_pinentry),
            };
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(passeport::agent::run(
                &keys.ssh,
                cli.comment.clone(),
                mnemonic_words,
                config,
            ))?;
        }
        Command::Verify => {
            cmd_verify(&keys, &cli)?;
        }
        Command::Key { key_type } => {
            cmd_generate(&keys, key_type, &cli)?;
        }
        Command::Sign {
            file,
            output,
            format,
        } => {
            cmd_sign(&keys, file, output, format, &cli)?;
        }
        Command::VerifySig { file, sig, format } => {
            cmd_verify_sig(&keys, file, sig, format, &cli)?;
        }
        Command::Encrypt {
            file,
            output,
            format,
            recipient,
        } => {
            cmd_encrypt(&keys, file, output, format, recipient, &cli)?;
        }
        Command::Decrypt {
            file,
            output,
            format,
        } => {
            cmd_decrypt(&keys, file, output, format, &cli)?;
        }
        Command::Init { .. }
        | Command::Vault { .. }
        | Command::Completions { .. }
        | Command::ManPage => {
            unreachable!()
        }
    }

    Ok(())
}
