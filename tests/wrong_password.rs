//! SECURITY TEST: a wrong passphrase reveals nothing and cannot open the vault.
//! Decrypting the wrapped master key IS the authentication.

use cloakit::Vault;
use tempfile::tempdir;

#[test]
fn wrong_passphrase_is_rejected() {
    let vdir = tempdir().unwrap();
    // Create then drop, so we re-open from disk like a real second invocation.
    drop(Vault::init(vdir.path(), b"correct horse battery staple").unwrap());

    assert!(
        Vault::open(vdir.path(), b"wrong").is_err(),
        "wrong passphrase must not unlock"
    );
    assert!(
        Vault::open(vdir.path(), b"correct horse battery staple").is_ok(),
        "correct passphrase must unlock"
    );
}
