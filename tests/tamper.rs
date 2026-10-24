//! SECURITY TEST: an altered blob must refuse to open rather than hand back
//! corrupted data. "Tamper-evident" is a README claim; this is its proof.

use std::fs;

use cloakit::Vault;
use cloakit::vault::paths;
use tempfile::tempdir;

#[test]
fn altered_blob_refuses_to_restore() {
    let vdir = tempdir().unwrap();
    let work = tempdir().unwrap();
    let f = work.path().join("x");
    fs::write(&f, b"the real contents").unwrap();

    let mut v = Vault::init(vdir.path(), b"pw").unwrap();
    let id = v.cloak(&f).unwrap();

    // Flip one byte in the stored object (simulate tampering on the NAS/VPS).
    let obj = paths::object_path(vdir.path(), id);
    let mut bytes = fs::read(&obj).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    fs::write(&obj, &bytes).unwrap();

    // Uncloak must fail closed, and must not have resurrected the original.
    let result = v.uncloak(id);
    assert!(result.is_err(), "tampered blob must not restore");
    assert!(!f.exists(), "no partial/forged restore on tamper");
}
