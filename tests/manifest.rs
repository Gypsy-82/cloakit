//! Manifest persistence and — the headline guarantee — that changing the
//! passphrase does NOT lock you out of data cloaked under the old one.

use std::fs;

use cloakit::Vault;
use tempfile::tempdir;

#[test]
fn manifest_persists_across_reopen() {
    let vdir = tempdir().unwrap();
    let work = tempdir().unwrap();

    let mut v = Vault::init(vdir.path(), b"pw").unwrap();
    for n in ["a", "b", "c"] {
        let f = work.path().join(n);
        fs::write(&f, n).unwrap();
        v.cloak(&f).unwrap();
    }
    assert_eq!(v.entries().len(), 3);
    drop(v);

    let v2 = Vault::open(vdir.path(), b"pw").unwrap();
    assert_eq!(v2.entries().len(), 3, "manifest must survive reopen");
}

/// This is the envelope-key promise, proven: cloak under one passphrase, rotate
/// to another, and the old data still opens under the new passphrase — with no
/// re-encryption of the blob.
#[test]
fn password_change_preserves_access() {
    let vdir = tempdir().unwrap();
    let work = tempdir().unwrap();
    let f = work.path().join("secret");
    let content: &[u8] = b"survives the rotation";
    fs::write(&f, content).unwrap();

    let id;
    {
        let mut v = Vault::init(vdir.path(), b"old-pass").unwrap();
        id = v.cloak(&f).unwrap();
        v.change_password(b"new-pass").unwrap();
    }

    assert!(
        Vault::open(vdir.path(), b"old-pass").is_err(),
        "old passphrase must stop working"
    );

    let mut v = Vault::open(vdir.path(), b"new-pass").unwrap();
    assert_eq!(v.entries().len(), 1, "old data still inventoried");
    let target = v.uncloak(id).unwrap();
    assert_eq!(target, f);
    assert_eq!(
        fs::read(&f).unwrap(),
        content,
        "data cloaked under old pass opens under new pass, byte-identical"
    );
}
