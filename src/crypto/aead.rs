//! Authenticated encryption with XChaCha20-Poly1305.
//!
//! The 192-bit (24-byte) nonce is the reason for XChaCha over AES-GCM: random
//! nonce generation is safe at volume, where AES-GCM's 96-bit nonce is risky.
//! The Poly1305 tag is what makes tampering fail *closed* — `open` returns an
//! error rather than garbage — and why a wrong key reveals nothing at all.
//!
//! On-disk/sealed layout is: `nonce (24 bytes) || ciphertext+tag`.

use anyhow::{Result, bail};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use rand::rngs::OsRng;

/// Nonce length for XChaCha20-Poly1305.
pub const NONCE_LEN: usize = 24;
/// Poly1305 authentication tag length.
pub const TAG_LEN: usize = 16;

fn cipher(key: &[u8]) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| anyhow::anyhow!("key must be 32 bytes"))
}

/// Encrypt `plaintext` under `key`, returning `nonce || ciphertext+tag`.
/// A fresh random nonce is generated per call.
pub fn seal(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let c = cipher(key)?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = c
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a `nonce || ciphertext+tag` blob produced by [`seal`].
///
/// Returns an error if the key is wrong or the data was altered — the tag
/// mismatch is indistinguishable between those cases, which is the point.
pub fn open(key: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        bail!("ciphertext too short to be valid");
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let c = cipher(key)?;
    c.decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong passphrase or tampered data"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [7u8; 32];
        let blob = seal(&key, b"attack at dawn").unwrap();
        assert_eq!(open(&key, &blob).unwrap(), b"attack at dawn");
    }

    #[test]
    fn wrong_key_fails() {
        let blob = seal(&[1u8; 32], b"secret").unwrap();
        assert!(open(&[2u8; 32], &blob).is_err());
    }

    #[test]
    fn tamper_fails() {
        let key = [3u8; 32];
        let mut blob = seal(&key, b"secret payload").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01; // flip a bit in the tag
        assert!(open(&key, &blob).is_err());
    }

    #[test]
    fn distinct_nonces() {
        let key = [9u8; 32];
        let a = seal(&key, b"x").unwrap();
        let b = seal(&key, b"x").unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN], "nonces must differ");
    }
}
