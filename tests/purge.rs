//! Purge destroys a cloaked item permanently WITHOUT restoring it: the blob is
//! gone, the entry is gone, the original does not reappear, and the id can never
//! be uncloaked again.

use std::fs;

use cloakit::Vault;
use cloakit::vault::paths;
use tempfile::tempdir;

#[test]
fn purge_destroys_without_restoring() {
    let vdir = tempdir().unwrap();
    let work = tempdir().unwrap();
    let f = work.path().join("doomed.txt");
    fs::write(&f, b"delete me forever").unwrap();

    let mut v = Vault::init(vdir.path(), b"pw").unwrap();
    let id = v.cloak(&f).unwrap();
    assert!(!f.exists(), "original gone after cloak");
    assert!(paths::object_path(vdir.path(), id).exists(), "blob exists");

    let name = v.purge(id).unwrap();
    assert_eq!(name, b"doomed.txt");

    // Blob gone, entry gone, original NOT resurrected.
    assert!(
        !paths::object_path(vdir.path(), id).exists(),
        "blob destroyed"
    );
    assert_eq!(v.entries().len(), 0, "entry removed");
    assert!(!f.exists(), "purge must never restore the original");

    // And it cannot be uncloaked anymore.
    assert!(v.uncloak(id).is_err(), "purged id is unrecoverable");
}

#[test]
fn purge_leaves_other_items_intact() {
    let vdir = tempdir().unwrap();
    let work = tempdir().unwrap();
    let keep = work.path().join("keep");
    let drop = work.path().join("drop");
    fs::write(&keep, b"keep this").unwrap();
    fs::write(&drop, b"lose this").unwrap();

    let mut v = Vault::init(vdir.path(), b"pw").unwrap();
    let keep_id = v.cloak(&keep).unwrap();
    let drop_id = v.cloak(&drop).unwrap();

    v.purge(drop_id).unwrap();
    assert_eq!(v.entries().len(), 1);

    // The survivor still restores cleanly.
    let target = v.uncloak(keep_id).unwrap();
    assert_eq!(target, keep);
    assert_eq!(fs::read(&keep).unwrap(), b"keep this");
}
