//! Blob storage: one encrypted object per cloaked item, named by a random id
//! with no extension, so nothing on disk hints at what it is.
//!
//! `put` enforces the verify-before-delete rule at the storage layer: it writes
//! the blob, fsyncs it, reads it back, decrypts it, and confirms the plaintext
//! matches byte-for-byte. Only a caller that sees `put` succeed may remove the
//! original.

use std::path::Path;

use anyhow::{Result, ensure};

use crate::crypto;
use crate::util::atomic;
use crate::vault::paths;

/// Ensure `objects/` exists.
pub fn ensure_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let od = paths::objects_dir(dir);
    let fresh = !od.exists();
    std::fs::create_dir_all(&od)?;
    // Lock the objects directory to the owner regardless of umask.
    if fresh {
        std::fs::set_permissions(&od, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Encrypt `plaintext`, write it as object `id`, then read it back and verify it
/// decrypts to exactly `plaintext`. Returns only after the blob is proven good.
pub fn put(dir: &Path, master: &[u8], id: u64, plaintext: &[u8]) -> Result<()> {
    ensure_dir(dir)?;
    let path = paths::object_path(dir, id);
    let blob = crypto::seal(master, plaintext)?;
    atomic::write(&path, &blob)?;

    // Read-back verification: prove the on-disk blob round-trips before the
    // caller is allowed to delete the original.
    let back = std::fs::read(&path)?;
    let decrypted = crypto::open(master, &back)?;
    ensure!(
        decrypted == plaintext,
        "verification failed: read-back of object {id} does not match original"
    );
    Ok(())
}

/// Read and decrypt object `id`. Fails closed on tampering or wrong key.
pub fn get(dir: &Path, master: &[u8], id: u64) -> Result<Vec<u8>> {
    let path = paths::object_path(dir, id);
    let blob = std::fs::read(&path)?;
    crypto::open(master, &blob)
}

/// Delete object `id`.
pub fn remove(dir: &Path, id: u64) -> Result<()> {
    atomic::remove(&paths::object_path(dir, id))
}

/// True if object `id` exists on disk.
pub fn exists(dir: &Path, id: u64) -> bool {
    paths::object_path(dir, id).is_file()
}
