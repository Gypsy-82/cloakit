//! Crash-safe writes: write a temp file in the same directory, fsync it, then
//! atomically rename it into place and fsync the directory. A rename within one
//! filesystem is atomic, so a reader ever sees either the whole old file or the
//! whole new one — never a half-written splice.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use tempfile::NamedTempFile;

/// Open `dir` and fsync it, so a rename/create/unlink inside it is durable.
fn fsync_dir(dir: &Path) -> Result<()> {
    File::open(dir)
        .with_context(|| format!("open dir for fsync: {}", dir.display()))?
        .sync_all()
        .with_context(|| format!("fsync dir: {}", dir.display()))?;
    Ok(())
}

/// Atomically write `data` to `target`. Overwrites any existing file.
pub fn write(target: &Path, data: &[u8]) -> Result<()> {
    let dir = target
        .parent()
        .context("target path has no parent directory")?;
    let mut tmp = NamedTempFile::new_in(dir).context("create temp file")?;
    tmp.write_all(data).context("write temp file")?;
    tmp.as_file().sync_all().context("fsync temp file")?;
    // persist() does an atomic rename onto `target`.
    tmp.persist(target)
        .map_err(|e| e.error)
        .with_context(|| format!("persist temp -> {}", target.display()))?;
    fsync_dir(dir)?;
    Ok(())
}

/// Like [`write`], but first rolls any existing `target` to `target` + `.bak`,
/// keeping exactly one backup generation. Used for the manifest and vault.toml,
/// where losing the file orphans every blob.
pub fn write_with_backup(target: &Path, data: &[u8]) -> Result<()> {
    let dir = target
        .parent()
        .context("target path has no parent directory")?;
    let mut tmp = NamedTempFile::new_in(dir).context("create temp file")?;
    tmp.write_all(data).context("write temp file")?;
    tmp.as_file().sync_all().context("fsync temp file")?;

    if target.exists() {
        let bak = target.with_extension("bak");
        fs::rename(target, &bak)
            .with_context(|| format!("roll {} -> {}", target.display(), bak.display()))?;
    }
    tmp.persist(target)
        .map_err(|e| e.error)
        .with_context(|| format!("persist temp -> {}", target.display()))?;
    fsync_dir(dir)?;
    Ok(())
}

/// Remove a file and fsync its directory so the unlink is durable.
pub fn remove(target: &Path) -> Result<()> {
    fs::remove_file(target).with_context(|| format!("remove {}", target.display()))?;
    if let Some(dir) = target.parent() {
        fsync_dir(dir)?;
    }
    Ok(())
}
