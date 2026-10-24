//! Command-line surface.
//!
//! Bare `cloakit` lists (read-only). `-e`/`-d`/`-p` are the three actions, and
//! exactly one may be given at a time. The passphrase is NEVER a flag — it is
//! prompted interactively (see `util::prompt`).

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "cloakit",
    about = "Cloak files and folders into an encrypted vault whose names and inventory are also hidden.",
    long_about = None,
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Cloak a file or directory into the vault.
    #[arg(short = 'e', long = "cloak", value_name = "PATH")]
    pub cloak: Option<PathBuf>,

    /// Uncloak an item by its id, restoring it to its original location.
    #[arg(short = 'd', long = "uncloak", value_name = "ID")]
    pub uncloak: Option<u64>,

    /// Change the vault passphrase (re-wraps the master key; blobs untouched).
    #[arg(short = 'p', long = "passwd")]
    pub passwd: bool,

    /// Permanently destroy a cloaked item by id WITHOUT restoring it. Irreversible.
    /// Long-form only, on purpose — this one should take deliberate typing.
    #[arg(long = "purge", value_name = "ID")]
    pub purge: Option<u64>,
}

/// The single action chosen on the command line.
pub enum Action {
    List,
    Cloak(PathBuf),
    Uncloak(u64),
    Passwd,
    Purge(u64),
}

impl Cli {
    /// Resolve to exactly one action, rejecting combinations.
    pub fn action(self) -> anyhow::Result<Action> {
        let chosen = [
            self.cloak.is_some(),
            self.uncloak.is_some(),
            self.passwd,
            self.purge.is_some(),
        ]
        .iter()
        .filter(|b| **b)
        .count();
        if chosen > 1 {
            anyhow::bail!("choose only one of -e (cloak), -d (uncloak), -p (passwd), or --purge");
        }
        Ok(if let Some(p) = self.cloak {
            Action::Cloak(p)
        } else if let Some(id) = self.uncloak {
            Action::Uncloak(id)
        } else if self.passwd {
            Action::Passwd
        } else if let Some(id) = self.purge {
            Action::Purge(id)
        } else {
            Action::List
        })
    }
}
