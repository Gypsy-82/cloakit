//! The encrypted inventory. Without the master key you cannot even learn how
//! many items the vault holds.
//!
//! Filenames and origin paths are stored as RAW BYTES, never `String` — a Unix
//! filename is arbitrary bytes, and sanitizing here would destroy the real name
//! so `-d` could never restore it. Sanitizing happens only at display time
//! (`util::display`).
//!
//! On disk: `manifest.bin` = `seal(master, postcard(Manifest))`.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::util::atomic;
use crate::vault::paths;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    File,
    Dir,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Entry {
    /// Random id; also the object's filename under `objects/`.
    pub id: u64,
    /// Final path component (the display name), raw bytes.
    pub name: Vec<u8>,
    /// Absolute parent directory it was cloaked from, raw bytes.
    pub parent: Vec<u8>,
    pub kind: Kind,
    /// Original on-disk size (file length, or packed size for a directory).
    pub size: u64,
    /// Modification time, Unix seconds (best-effort; 0 if unavailable).
    pub mtime: i64,
}

#[derive(Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub entries: Vec<Entry>,
}

impl Manifest {
    fn empty() -> Self {
        Manifest {
            version: paths::FORMAT_VERSION,
            entries: Vec::new(),
        }
    }

    /// Load and decrypt the manifest. A missing file yields an empty manifest
    /// (a freshly initialized vault).
    pub fn load(dir: &Path, master: &[u8]) -> Result<Manifest> {
        let path = paths::manifest_path(dir);
        if !path.exists() {
            return Ok(Manifest::empty());
        }
        let blob = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let plain = crypto::open(master, &blob).context("decrypt manifest")?;
        let (m, rest): (Manifest, &[u8]) =
            postcard::take_from_bytes(&plain).context("deserialize manifest")?;
        // Fail closed: an authenticated manifest with trailing bytes is malformed.
        anyhow::ensure!(
            rest.is_empty(),
            "manifest has {} trailing bytes",
            rest.len()
        );
        Ok(m)
    }

    /// Encrypt and atomically write the manifest (with one backup generation).
    pub fn save(&self, dir: &Path, master: &[u8]) -> Result<()> {
        let plain = postcard::to_stdvec(self).context("serialize manifest")?;
        let blob = crypto::seal(master, &plain)?;
        atomic::write_with_backup(&paths::manifest_path(dir), &blob)?;
        Ok(())
    }

    pub fn find(&self, id: u64) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn contains(&self, id: u64) -> bool {
        self.entries.iter().any(|e| e.id == id)
    }

    pub fn remove(&mut self, id: u64) {
        self.entries.retain(|e| e.id != id);
    }
}
