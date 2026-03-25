use std::io::{self, Write};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal;

/// Mask a word: show first 2 chars, replace the rest with '*'.
fn mask_word(word: &str) -> String {
    let chars: Vec<char> = word.chars().collect();
    if chars.len() <= 2 {
        "*".repeat(chars.len())
    } else {
        let prefix: String = chars[..2].iter().collect();
        format!("{}{}", prefix, "*".repeat(chars.len() - 2))
    }
}

/// Build the masked words status string, wrapping to multiple lines if needed.
fn build_status_lines(words: &[String], term_width: usize) -> Vec<String> {
    if words.is_empty() {
        return vec!["  (no words entered yet)".to_string()];
    }

    let mut lines = Vec::new();
    let mut current_line = String::from("  ");

    for (i, w) in words.iter().enumerate() {
        let token = format!("{}:{}", i + 1, mask_word(w));
        // +1 for the separating space (if not the first token on the line)
        let needed = if current_line.len() > 2 {
            token.len() + 1
        } else {
            token.len()
        };

        if current_line.len() + needed > term_width && current_line.len() > 2 {
            lines.push(current_line);
            current_line = format!("  {token}");
        } else {
            if current_line.len() > 2 {
                current_line.push(' ');
            }
            current_line.push_str(&token);
        }
    }
    lines.push(current_line);
    lines
}

/// Build the input prompt string.
fn build_input_line(words: &[String], current: &str) -> String {
    let word_num = words.len() + 1;
    format!("  Word {word_num:>2}/24: {current}")
}

/// Get terminal width, clamped to a sensible minimum.
fn term_width() -> usize {
    terminal::size()
        .map(|(w, _)| w as usize)
        .unwrap_or(80)
        .max(40)
}

/// Calculate how many terminal rows a string occupies given a terminal width.
fn row_count(text_len: usize, tw: usize) -> usize {
    if text_len == 0 {
        1
    } else {
        text_len.div_ceil(tw)
    }
}

/// Redraw the display:
///   Status lines: masked completed words (may span multiple lines)
///   Input line: "Word N/24: <current input>"
///
/// `prev_rows` is the total number of terminal rows the previous draw occupied,
/// so we know how far up to move the cursor.
fn redraw(words: &[String], current: &str, prev_rows: usize) -> usize {
    let mut stderr = io::stderr();
    let tw = term_width();

    // Move cursor up to the start of our previously drawn area
    if prev_rows > 1 {
        eprint!("\x1b[{}A", prev_rows - 1);
    }
    // Clear from cursor to end of screen
    eprint!("\r\x1b[J");

    // Draw status lines (masked words, with line-wrapping at word boundaries)
    let status_lines = build_status_lines(words, tw);
    for (i, line) in status_lines.iter().enumerate() {
        if i > 0 {
            eprint!("\r\n");
        }
        eprint!("{line}");
    }

    // Draw input line on next line
    let input = build_input_line(words, current);
    eprint!("\r\n{input}");

    let _ = stderr.flush();

    // Total rows: each status line may itself wrap, plus the input line
    let mut total_rows = 0;
    for line in &status_lines {
        total_rows += row_count(line.len(), tw);
    }
    total_rows += row_count(input.len(), tw);
    total_rows
}

/// Try to commit the current word buffer. Returns true if word was committed.
fn try_commit_word(current: &mut String, words: &mut Vec<String>) -> bool {
    let word = current.trim().to_string();
    if !word.is_empty() {
        words.push(word);
        current.clear();
        return true;
    }
    false
}

/// Interactively prompt for 24 mnemonic words one at a time.
///
/// Words are shown in full as you type, then masked once confirmed
/// (first 2 chars visible, rest replaced with *).
pub fn prompt_mnemonic() -> Result<String, Box<dyn std::error::Error>> {
    eprintln!("Enter your 24-word mnemonic (press Space or Enter after each word).");
    eprintln!("Ctrl+C to abort. Backspace to undo.\n");

    let mut words: Vec<String> = Vec::with_capacity(24);
    let mut current = String::new();

    terminal::enable_raw_mode()?;
    let mut prev_rows = redraw(&words, &current, 0);

    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        loop {
            let ev = event::read()?;
            match ev {
                Event::Key(key_event) => {
                    if key_event.kind != KeyEventKind::Press {
                        continue;
                    }

                    match key_event.code {
                        KeyCode::Char('c')
                            if key_event.modifiers.contains(KeyModifiers::CONTROL) =>
                        {
                            return Err("aborted".into());
                        }
                        KeyCode::Char(c) if c == ' ' || c == '\t' => {
                            if try_commit_word(&mut current, &mut words) && words.len() == 24 {
                                prev_rows = redraw(&words, &current, prev_rows);
                                return Ok(());
                            }
                        }
                        KeyCode::Enter => {
                            if try_commit_word(&mut current, &mut words) && words.len() == 24 {
                                prev_rows = redraw(&words, &current, prev_rows);
                                return Ok(());
                            }
                        }
                        KeyCode::Char(c) => {
                            current.push(c);
                        }
                        KeyCode::Backspace => {
                            if !current.is_empty() {
                                current.pop();
                            } else if !words.is_empty() {
                                current = words.pop().unwrap();
                            }
                        }
                        _ => {}
                    }
                    prev_rows = redraw(&words, &current, prev_rows);
                }
                Event::Resize(_, _) => {
                    // Terminal resized — redraw with new dimensions
                    prev_rows = redraw(&words, &current, prev_rows);
                }
                _ => {}
            }
        }
    })();

    let _ = terminal::disable_raw_mode();
    eprint!("\r\n\r\n");
    let _ = io::stderr().flush();

    result?;
    Ok(words.join(" "))
}

/// Prompt for a specific word number for vault store confirmation.
pub fn prompt_confirm_word(word_num: usize) -> Result<String, Box<dyn std::error::Error>> {
    eprint!("  Confirm word #{word_num}: ");
    io::stderr().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

/// Prompt for a passphrase (visible input).
pub fn prompt_passphrase(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    eprint!("{prompt}");
    io::stderr().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}
