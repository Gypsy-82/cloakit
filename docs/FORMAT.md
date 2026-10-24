# On-disk format (version 1)

The format is versioned from day one. `vault.toml`'s `version` field gates
loading; a future change bumps it with a migration path so an existing vault is
never orphaned.

## Layout

```
$XDG_DATA_HOME/cloakit/   (or ~/.local/share/cloakit)   mode 0700
  vault.toml      public header + wrapped master key     mode 0600
  manifest.bin    encrypted inventory                    mode 0600
  manifest.bak    previous manifest generation           mode 0600
  objects/        mode 0700
    <id>          encrypted blob, random 10-digit id, no extension   mode 0600
```

`CLOAKIT_VAULT_DIR` overrides the location (used by tests and for portable
vaults).

## Key hierarchy (envelope key)

```
passphrase ──Argon2id(salt, m,t,p)──▶ KEK ──wraps──▶ master key (random 32 bytes)
                                                          │
                                   encrypts the manifest and every blob
```

- The **KEK** (key-encryption key) is derived per unlock and never stored.
- The **master key** is generated once at init and never changes for the life of
  the vault. Only its wrapped form is stored.
- Changing the passphrase re-derives a KEK from a fresh salt and re-wraps the
  same master key. Blobs and the manifest are untouched. (LUKS key-slot pattern.)

## `vault.toml`

```toml
version = 1
salt = "<hex>"                 # 16 random bytes, Argon2 salt

[argon2]
m_cost = 65536                 # KiB  (64 MiB)
t_cost = 3
p_cost = 4

[master]
wrapped = "<hex>"              # nonce(24) || XChaCha20-Poly1305(KEK, master key)
```

Decrypting `[master].wrapped` with the KEK **is** authentication: a wrong
passphrase (or a tampered header) fails the Poly1305 tag and reveals nothing.

## Sealed blob format

Every encrypted artifact — each object and the manifest — is:

```
nonce (24 bytes) || ciphertext+tag   (XChaCha20-Poly1305)
```

- **Objects** encrypt a **tar archive** of the item, rooted at the item's own
  final-component name. Files and directories use the same path: a file is a
  single-entry archive, a directory its full contents. tar carries permissions
  and mtime, giving byte-identical restore. Symlinks are stored, not followed.
- **The manifest** encrypts a `postcard`-serialized inventory under the master
  key.

## Manifest (plaintext, before encryption)

```
Manifest { version: u32, entries: Vec<Entry> }

Entry {
  id:     u64,       // random 10-digit; also the object filename
  name:   Vec<u8>,   // final path component, RAW BYTES (never String)
  parent: Vec<u8>,   // absolute parent directory, RAW BYTES
  kind:   File | Dir,
  size:   u64,       // original on-disk size (file length, or packed size for a dir)
  mtime:  i64,       // Unix seconds, best-effort
}
```

Names and paths are raw bytes because Unix filenames are arbitrary bytes.
Sanitizing happens only at display time (`src/util/display.rs`), never in
storage — sanitizing before writing would destroy the real name and make restore
impossible.

## Durability rules

- **Verify before delete.** An object is written, fsynced, read back, and
  decrypted-and-compared to the original before the original is removed.
- **Atomic writes.** `vault.toml` and `manifest.bin` are written to a temp file
  in the same directory, fsynced, then renamed into place; the directory is
  fsynced. The manifest keeps one backup generation (`manifest.bak`).
