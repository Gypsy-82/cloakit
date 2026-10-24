//! Cloak then uncloak restores byte-identical data to its origin — for both a
//! single file and a nested directory.

use std::fs;

use cloakit::Vault;
use tempfile::tempdir;

#[test]
fn file_roundtrip_is_byte_identical() {
    let vdir = tempdir().unwrap();
    let work = tempdir().unwrap();
    let f = work.path().join("secret.txt");
    let content: &[u8] = b"top secret data \x00\xff and more";
    fs::write(&f, content).unwrap();

    let mut v = Vault::init(vdir.path(), b"pw").unwrap();
    let id = v.cloak(&f).unwrap();
    assert!(!f.exists(), "original must be gone after cloak");
    assert_eq!(v.entries().len(), 1);

    let target = v.uncloak(id).unwrap();
    assert_eq!(target, f, "restored to original location");
    assert_eq!(fs::read(&f).unwrap(), content, "byte-identical restore");
    assert_eq!(v.entries().len(), 0, "entry removed after uncloak");
}

#[test]
fn directory_roundtrip() {
    let vdir = tempdir().unwrap();
    let work = tempdir().unwrap();
    let d = work.path().join("folder");
    fs::create_dir(&d).unwrap();
    fs::write(d.join("a.txt"), b"alpha").unwrap();
    fs::create_dir(d.join("sub")).unwrap();
    fs::write(d.join("sub").join("b.txt"), b"beta").unwrap();

    let mut v = Vault::init(vdir.path(), b"pw").unwrap();
    let id = v.cloak(&d).unwrap();
    assert!(!d.exists(), "original directory must be gone after cloak");

    v.uncloak(id).unwrap();
    assert_eq!(fs::read(d.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(fs::read(d.join("sub").join("b.txt")).unwrap(), b"beta");
}
