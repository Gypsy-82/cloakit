//! The vault: the testable core API. Every operation takes the passphrase (or a
//! live master key) as data — no prompting in here — so the security behaviour
//! can be tested without a human at a terminal. `main.rs` is the thin layer that
//! prompts and calls these.

pub mod manifest;
pub mod meta;
pub mod paths;
pub mod store;

use std::io::Cursor;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result, bail, ensure};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use manifest::{Entry, Kind, Manifest};
use meta::VaultMeta;

/// An open vault: header, the unwrapped master key, and the decrypted manifest.
pub struct Vault {
    dir: PathBuf,
    meta: VaultMeta,
    master: Zeroizing<[u8; 32]>,
    manifest: Manifest,
}

impl Vault {
    /// True if a vault exists at `dir`.
    pub fn exists(dir: &Path) -> bool {
        paths::exists(dir)
    }

    /// Create a new vault at `dir` with `password`. Fails if one already exists.
    pub fn init(dir: &Path, password: &[u8]) -> Result<Vault> {
        if paths::exists(dir) {
            bail!("a vault already exists at {}", dir.display());
        }
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        // Vault directory is private: 0700.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", dir.display()))?;
        store::ensure_dir(dir)?;

        let (meta, master) = VaultMeta::create(password)?;
        meta.save(dir)?;
        let manifest = Manifest {
            version: paths::FORMAT_VERSION,
            entries: Vec::new(),
        };
        manifest.save(dir, master.as_ref())?;

        Ok(Vault {
            dir: dir.to_path_buf(),
            meta,
            master,
            manifest,
        })
    }

    /// Open an existing vault at `dir`, unlocking with `password`.
    pub fn open(dir: &Path, password: &[u8]) -> Result<Vault> {
        if !paths::exists(dir) {
            bail!("no vault at {}", dir.display());
        }
        let meta = VaultMeta::load(dir)?;
        let master = meta.unlock(password)?;
        let manifest = Manifest::load(dir, master.as_ref())?;
        Ok(Vault {
            dir: dir.to_path_buf(),
            meta,
            master,
            manifest,
        })
    }

    /// The cloaked inventory, for listing.
    pub fn entries(&self) -> &[Entry] {
        &self.manifest.entries
    }

    /// Cloak a file or directory: pack -> encrypt -> store+verify -> record ->
    /// then (only then) remove the original. Returns the new id.
    pub fn cloak(&mut self, input: &Path) -> Result<u64> {
        // symlink_metadata does not follow a final symlink.
        let md = std::fs::symlink_metadata(input)
            .with_context(|| format!("stat {}", input.display()))?;
        let ft = md.file_type();
        let kind = if ft.is_file() {
            Kind::File
        } else if ft.is_dir() {
            Kind::Dir
        } else {
            bail!(
                "unsupported type (symlink or special file): {}",
                input.display()
            );
        };

        // Final component = display name. Resolve an absolute parent WITHOUT
        // following the item itself, so restore lands exactly where it came from.
        let name = input
            .file_name()
            .with_context(|| format!("path has no final component: {}", input.display()))?
            .to_os_string();
        let parent_in = input.parent().filter(|p| !p.as_os_str().is_empty());
        let abs_parent = match parent_in {
            Some(p) => std::fs::canonicalize(p)
                .with_context(|| format!("canonicalize parent {}", p.display()))?,
            None => std::env::current_dir().context("getcwd")?,
        };

        let size = match kind {
            Kind::File => md.len(),
            Kind::Dir => 0, // filled in after packing
        };
        let mtime = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        // Pack into a tar archive rooted at the item's own name. One code path
        // for files and directories, and tar carries permissions + mtime.
        let plaintext = pack(input, &name, kind)?;
        let size = if kind == Kind::Dir {
            plaintext.len() as u64
        } else {
            size
        };

        let id = self.fresh_id();

        // Store with read-back verification BEFORE we touch the original.
        store::put(&self.dir, self.master.as_ref(), id, &plaintext)?;

        // Record it, and persist the manifest, still before deleting anything.
        self.manifest.entries.push(Entry {
            id,
            name: name.as_bytes().to_vec(),
            parent: abs_parent.as_os_str().as_bytes().to_vec(),
            kind,
            size,
            mtime,
        });
        self.manifest.save(&self.dir, self.master.as_ref())?;

        // Safe to remove the original now: blob verified, manifest persisted.
        match kind {
            Kind::File => std::fs::remove_file(input)
                .with_context(|| format!("remove original {}", input.display()))?,
            Kind::Dir => std::fs::remove_dir_all(input)
                .with_context(|| format!("remove original {}", input.display()))?,
        }

        Ok(id)
    }

    /// Uncloak item `id`, restoring it byte-identical to its origin. Refuses to
    /// overwrite an existing target. Returns the restored path.
    pub fn uncloak(&mut self, id: u64) -> Result<PathBuf> {
        let entry = self
            .manifest
            .find(id)
            .with_context(|| format!("no cloaked item with id {id}"))?
            .clone();

        let plaintext = store::get(&self.dir, self.master.as_ref(), id)
            .with_context(|| format!("read object {id}"))?;

        let parent = PathBuf::from(std::ffi::OsStr::from_bytes(&entry.parent));
        let name = std::ffi::OsStr::from_bytes(&entry.name);
        let target = parent.join(name);

        ensure!(
            !target.exists(),
            "refusing to overwrite existing path: {}",
            target.display()
        );
        std::fs::create_dir_all(&parent)
            .with_context(|| format!("recreate parent {}", parent.display()))?;

        // Unpack the tar into the parent; it recreates parent/name[/...].
        let mut ar = tar::Archive::new(Cursor::new(&plaintext));
        ar.set_preserve_permissions(true);
        ar.set_preserve_mtime(true);
        ar.unpack(&parent)
            .with_context(|| format!("unpack into {}", parent.display()))?;

        ensure!(
            target.exists(),
            "restore did not produce expected path: {}",
            target.display()
        );

        // Remove the blob and the manifest entry, then persist.
        store::remove(&self.dir, id)?;
        self.manifest.remove(id);
        self.manifest.save(&self.dir, self.master.as_ref())?;

        Ok(target)
    }

    /// Permanently destroy item `id` WITHOUT restoring it: remove the encrypted
    /// blob and drop its manifest entry. Irreversible. Returns the raw name
    /// bytes of what was destroyed (for a confirmation message).
    ///
    /// This destroys ciphertext, so there is no plaintext to scrub — the data
    /// was never on disk unencrypted here. (Any lingering *original* plaintext
    /// from cloak time is a separate, SSD-level concern; see SECURITY.md.)
    pub fn purge(&mut self, id: u64) -> Result<Vec<u8>> {
        let name = self
            .manifest
            .find(id)
            .with_context(|| format!("no cloaked item with id {id}"))?
            .name
            .clone();

        // Tolerate an already-missing blob (self-heal an orphaned entry).
        if store::exists(&self.dir, id) {
            store::remove(&self.dir, id)?;
        }
        self.manifest.remove(id);
        self.manifest.save(&self.dir, self.master.as_ref())?;
        Ok(name)
    }

    /// Change the passphrase: re-wrap the same master key under a new KEK.
    /// Blobs and the manifest are untouched.
    pub fn change_password(&mut self, new_password: &[u8]) -> Result<()> {
        self.meta.rewrap(&self.master, new_password)?;
        self.meta.save(&self.dir)?;
        Ok(())
    }

    /// A random 10-digit id not already used by the manifest or on disk.
    fn fresh_id(&self) -> u64 {
        loop {
            // 10-digit decimal, like the spec's `4820193756`.
            let id = 1_000_000_000 + (OsRng.next_u64() % 9_000_000_000);
            if !self.manifest.contains(id) && !store::exists(&self.dir, id) {
                return id;
            }
        }
    }
}

/// Pack `input` into an in-memory tar archive rooted at `name`. For a file this
/// is a single-entry archive; for a directory, its full contents. Symlinks are
/// stored as links, not followed.
fn pack(input: &Path, name: &std::ffi::OsStr, kind: Kind) -> Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    builder.follow_symlinks(false);
    let arcname = Path::new(name);
    match kind {
        Kind::File => builder
            .append_path_with_name(input, arcname)
            .with_context(|| format!("tar add file {}", input.display()))?,
        Kind::Dir => builder
            .append_dir_all(arcname, input)
            .with_context(|| format!("tar add dir {}", input.display()))?,
    }
    let bytes = builder.into_inner().context("finalize tar archive")?;
    Ok(bytes)
}
