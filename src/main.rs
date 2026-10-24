//! CLI entry point: parse the action, prompt for the passphrase, and drive the
//! `Vault` core. All prompting lives here; the core never reads a terminal.

mod cli;

use anyhow::{Context, Result};

use cloakit::Vault;
use cloakit::util::{self, display, prompt};
use cloakit::vault::{manifest::Kind, paths};

use clap::Parser;
use cli::{Action, Cli};

fn main() {
    if let Err(e) = run() {
        eprintln!("cloakit: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let action = Cli::parse().action()?;
    let dir = paths::vault_dir()?;

    match action {
        Action::List => list(&dir),
        Action::Cloak(path) => cloak(&dir, &path),
        Action::Uncloak(id) => uncloak(&dir, id),
        Action::Passwd => passwd(&dir),
        Action::Purge(id) => purge(&dir, id),
    }
}

/// Bare `cloakit`: read-only. If no vault exists yet, print a friendly hint
/// rather than an error.
fn list(dir: &std::path::Path) -> Result<()> {
    if !Vault::exists(dir) {
        println!("no vault yet — `cloakit -e <path>` to cloak your first item");
        return Ok(());
    }
    let pw = prompt::existing("magic word is? ")?;
    let vault = Vault::open(dir, pw.as_bytes())?;

    let entries = vault.entries();
    if entries.is_empty() {
        println!("vault is empty");
        return Ok(());
    }

    let mut rows: Vec<_> = entries.iter().collect();
    rows.sort_by_key(|e| e.id);
    println!("{:>10}  {:<32}  {:>10}", "ID", "NAME", "SIZE");
    for e in rows {
        let mark = if e.kind == Kind::Dir { "/" } else { "" };
        let name = format!("{}{}", display::safe(&e.name), mark);
        println!(
            "{:>10}  {:<32}  {:>10}",
            e.id,
            name,
            util::human_size(e.size)
        );
    }
    Ok(())
}

/// `-e`: cloak. Creates the vault on first use (prompting for a new passphrase).
fn cloak(dir: &std::path::Path, path: &std::path::Path) -> Result<()> {
    let mut vault = if Vault::exists(dir) {
        let pw = prompt::existing("magic word is? ")?;
        Vault::open(dir, pw.as_bytes())?
    } else {
        println!("no vault yet — creating one at {}", dir.display());
        let pw = prompt::new_passphrase()?;
        Vault::init(dir, pw.as_bytes())?
    };

    let id = vault
        .cloak(path)
        .with_context(|| format!("cloaking {}", path.display()))?;
    println!("cloaked {} -> {}", path.display(), id);
    Ok(())
}

/// `-d`: uncloak by id.
fn uncloak(dir: &std::path::Path, id: u64) -> Result<()> {
    if !Vault::exists(dir) {
        anyhow::bail!("no vault at {}", dir.display());
    }
    let pw = prompt::existing("magic word is? ")?;
    let mut vault = Vault::open(dir, pw.as_bytes())?;
    let target = vault.uncloak(id)?;
    println!("uncloaked {} -> {}", id, target.display());
    Ok(())
}

/// `--purge`: permanently destroy a cloaked item without restoring it. Requires
/// the passphrase (needed to rewrite the encrypted manifest) and a typed id
/// confirmation, because it cannot be undone.
fn purge(dir: &std::path::Path, id: u64) -> Result<()> {
    if !Vault::exists(dir) {
        anyhow::bail!("no vault at {}", dir.display());
    }
    let pw = prompt::existing("magic word is? ")?;
    let mut vault = Vault::open(dir, pw.as_bytes())?;

    eprintln!(
        "WARNING: purge permanently destroys item {id}. It will NOT be restored, and this cannot be undone."
    );
    eprint!("type the id again to confirm: ");
    use std::io::Write;
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    if line.trim() != id.to_string() {
        anyhow::bail!("confirmation did not match; nothing purged");
    }

    let name = vault.purge(id)?;
    println!("purged {} ({})", id, display::safe(&name));
    Ok(())
}

/// `-p`: change the passphrase. Requires the current one (authentication), then
/// the new one entered twice.
fn passwd(dir: &std::path::Path) -> Result<()> {
    if !Vault::exists(dir) {
        anyhow::bail!("no vault at {}", dir.display());
    }
    let current = prompt::existing("current passphrase: ")?;
    let mut vault = Vault::open(dir, current.as_bytes())?;
    let new = prompt::new_passphrase()?;
    vault.change_password(new.as_bytes())?;
    println!("passphrase changed");
    Ok(())
}
