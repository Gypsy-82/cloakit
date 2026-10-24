//! Where the vault lives on disk, and how its pieces are named.
//!
//! Default: `$XDG_DATA_HOME/cloakit` or `~/.local/share/cloakit`, mode 0700.
//! `CLOAKIT_VAULT_DIR` overrides it — used by tests so they never touch a real
//! vault, and handy for a portable vault on removable media.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// On-disk format version. Bump only with a migration path.
pub const FORMAT_VERSION: u32 = 1;

/// Resolve the vault directory (does not create it).
pub fn vault_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("CLOAKIT_VAULT_DIR") {
        return Ok(PathBuf::from(dir));
    }
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME")
        && !xdg.is_empty()
    {
        return Ok(PathBuf::from(xdg).join("cloakit"));
    }
    let home = std::env::var_os("HOME").context("HOME is not set; cannot locate vault")?;
    Ok(PathBuf::from(home).join(".local/share/cloakit"))
}

pub fn toml_path(dir: &Path) -> PathBuf {
    dir.join("vault.toml")
}

pub fn manifest_path(dir: &Path) -> PathBuf {
    dir.join("manifest.bin")
}

pub fn objects_dir(dir: &Path) -> PathBuf {
    dir.join("objects")
}

pub fn object_path(dir: &Path, id: u64) -> PathBuf {
    objects_dir(dir).join(id.to_string())
}

/// True if a vault already exists at `dir` (its vault.toml is present).
pub fn exists(dir: &Path) -> bool {
    toml_path(dir).is_file()
}
