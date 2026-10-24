//! Cryptographic primitives: Argon2id key derivation and XChaCha20-Poly1305
//! authenticated encryption. Higher layers never reach for a cipher directly —
//! they go through `seal`/`open` and `derive`.

pub mod aead;
pub mod kdf;

pub use aead::{open, seal};
pub use kdf::{KdfParams, derive};

use rand::RngCore;
use rand::rngs::OsRng;

/// Fill a fresh 32-byte random key (the master key, generated once at init).
pub fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    k
}

/// Fill `n` fresh random bytes (salts, etc.).
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    v
}
