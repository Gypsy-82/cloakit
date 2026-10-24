//! Password -> key derivation with Argon2id.
//!
//! The derived key is the *key-encryption key* (KEK). Its only job is to wrap
//! the random master key (see `vault::meta`). We never store the password or a
//! hash of it — only the salt and these parameters, which are public.

use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

/// Argon2id cost parameters. Serialized into vault.toml so a future tuning can
/// never orphan an existing vault.
#[derive(Clone, Copy, Debug)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Iterations (time cost).
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // m = 64 MiB, t = 3, p = 4 — the agreed v1 cost.
        Self {
            m_cost: 64 * 1024,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

/// Derive a 32-byte KEK from `password` and `salt` under the given parameters.
/// Output is wrapped in `Zeroizing` so it is wiped on drop.
pub fn derive(password: &[u8], salt: &[u8], params: KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let p = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| anyhow::anyhow!("argon2 derivation failed: {e}"))
        .context("deriving key from passphrase")?;
    Ok(key)
}
