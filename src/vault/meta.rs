//! `vault.toml` — the public, non-secret header, plus the envelope-wrapped
//! master key.
//!
//! The password-derived KEK wraps a random 32-byte master key. Only the wrapped
//! master key, the salt, and the Argon2 parameters are stored — never the
//! password or a hash. Decrypting the wrapped master key *is* authentication:
//! if the KEK is wrong, the Poly1305 tag fails and we learn nothing.
//!
//! Changing the passphrase re-wraps the *same* master key under a new KEK. The
//! master key never changes, so not a single blob is touched. (LUKS key-slot
//! pattern.)

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, KdfParams};
use crate::util::{self, atomic};
use crate::vault::paths;

#[derive(Serialize, Deserialize)]
struct Argon2Toml {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

#[derive(Serialize, Deserialize)]
struct MasterToml {
    /// hex of `nonce || ciphertext+tag` of the 32-byte master key under the KEK.
    wrapped: String,
}

#[derive(Serialize, Deserialize)]
struct VaultToml {
    version: u32,
    salt: String, // hex
    argon2: Argon2Toml,
    master: MasterToml,
}

/// Parsed vault header plus the unwrapped master key (held in memory only for
/// the life of the process, zeroized on drop).
pub struct VaultMeta {
    version: u32,
    salt: Vec<u8>,
    params: KdfParams,
    wrapped_master: Vec<u8>,
}

impl VaultMeta {
    /// Create a brand-new vault header: fresh salt, fresh random master key,
    /// wrapped under a KEK derived from `password`. Returns the header and the
    /// (unwrapped) master key for immediate use.
    pub fn create(password: &[u8]) -> Result<(VaultMeta, Zeroizing<[u8; 32]>)> {
        let params = KdfParams::default();
        let salt = crypto::random_bytes(16);
        let kek = crypto::derive(password, &salt, params)?;
        let master = Zeroizing::new(crypto::random_key());
        let wrapped_master = crypto::seal(kek.as_ref(), master.as_ref())?;
        let meta = VaultMeta {
            version: paths::FORMAT_VERSION,
            salt,
            params,
            wrapped_master,
        };
        Ok((meta, master))
    }

    /// Load and parse `vault.toml` from `dir`.
    pub fn load(dir: &Path) -> Result<VaultMeta> {
        let path = paths::toml_path(dir);
        let text =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let v: VaultToml = toml::from_str(&text).context("parse vault.toml")?;
        if v.version != paths::FORMAT_VERSION {
            bail!(
                "vault.toml is format version {}, this build understands {}",
                v.version,
                paths::FORMAT_VERSION
            );
        }
        Ok(VaultMeta {
            version: v.version,
            salt: util::hex_decode(&v.salt).context("decode salt")?,
            params: KdfParams {
                m_cost: v.argon2.m_cost,
                t_cost: v.argon2.t_cost,
                p_cost: v.argon2.p_cost,
            },
            wrapped_master: util::hex_decode(&v.master.wrapped).context("decode wrapped key")?,
        })
    }

    /// Serialize and atomically write `vault.toml` (with one backup generation).
    pub fn save(&self, dir: &Path) -> Result<()> {
        let v = VaultToml {
            version: self.version,
            salt: util::hex_encode(&self.salt),
            argon2: Argon2Toml {
                m_cost: self.params.m_cost,
                t_cost: self.params.t_cost,
                p_cost: self.params.p_cost,
            },
            master: MasterToml {
                wrapped: util::hex_encode(&self.wrapped_master),
            },
        };
        let text = toml::to_string_pretty(&v).context("serialize vault.toml")?;
        atomic::write_with_backup(&paths::toml_path(dir), text.as_bytes())?;
        Ok(())
    }

    /// Derive the KEK from `password` and unwrap the master key. A wrong
    /// passphrase (or a tampered header) fails here — this is authentication.
    pub fn unlock(&self, password: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let kek = crypto::derive(password, &self.salt, self.params)?;
        let master = crypto::open(kek.as_ref(), &self.wrapped_master)
            .map_err(|_| anyhow::anyhow!("wrong passphrase (or vault.toml was tampered)"))?;
        if master.len() != 32 {
            bail!("unwrapped master key has wrong length");
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&master);
        Ok(key)
    }

    /// Re-wrap the given master key under a KEK derived from `new_password`,
    /// using a fresh salt. The master key itself is unchanged, so blobs and the
    /// manifest stay valid. Caller saves afterwards.
    pub fn rewrap(&mut self, master: &[u8; 32], new_password: &[u8]) -> Result<()> {
        let salt = crypto::random_bytes(16);
        let kek = crypto::derive(new_password, &salt, self.params)?;
        let wrapped = crypto::seal(kek.as_ref(), master)?;
        self.salt = salt;
        self.wrapped_master = wrapped;
        Ok(())
    }
}
