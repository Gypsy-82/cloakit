//! Interactive passphrase entry. Never via CLI flag or env var:
//! `/proc/<pid>/cmdline` and `/proc/<pid>/environ` are readable, and flags land
//! in shell history. The passphrase exists only as long as it must, wrapped in
//! `Zeroizing` so it is wiped from memory on drop.

use anyhow::{Result, bail};
use zeroize::Zeroizing;

/// Prompt once for an existing passphrase (unlock, or the current one on change).
pub fn existing(prompt: &str) -> Result<Zeroizing<String>> {
    let pw = rpassword::prompt_password(prompt)?;
    Ok(Zeroizing::new(pw))
}

/// Prompt twice for a new passphrase and require the two entries to match.
/// Rejects an empty passphrase; warns (does not block) on short ones.
pub fn new_passphrase() -> Result<Zeroizing<String>> {
    let first = Zeroizing::new(rpassword::prompt_password("new passphrase: ")?);
    if first.is_empty() {
        bail!("passphrase cannot be empty");
    }
    if first.len() < 8 {
        eprintln!("cloakit: warning — short passphrase; longer is stronger");
    }
    let second = Zeroizing::new(rpassword::prompt_password("confirm passphrase: ")?);
    if first.as_str() != second.as_str() {
        bail!("passphrases did not match");
    }
    Ok(first)
}
