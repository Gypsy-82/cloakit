# cloakit

> Turn sensitive files into sealed packages whose **labels and contents are both
> unreadable**, so that stealing your laptop, compromising your NAS, or seizing
> your VPS all yield the same thing — noise.

Terminal file/folder cloaking for Linux, in Rust. A lockbox for files and
folders: hand it a file, it locks the file inside an encrypted blob, moves it
into one vault directory, renames it to a random number, and removes the
original. Say the passphrase and it reappears exactly where it was.

What makes this more than "a zip with a password":

- **The labels are locked too.** A snooper sees numbered blobs, not
  `tax_return_2026.pdf`. The filename often gives away everything that mattered.
- **The inventory is locked.** Without the passphrase you cannot even learn how
  many items are in the vault, let alone what they are or where they came from.
- **It is tamper-evident.** If a locked blob is altered, it refuses to open
  rather than handing back corrupted data.

## Usage

```
cloakit              # prompt, then list what's cloaked (read-only)
cloakit -e <path>    # cloak a file or directory
cloakit -d <id>      # uncloak it, back to its original name and place
cloakit -p           # change the vault passphrase
cloakit --purge <id> # permanently destroy a cloaked item WITHOUT restoring it
```

`--purge` is irreversible: it erases the encrypted blob and its inventory entry
and never writes the file back to disk. It requires the passphrase and a typed
confirmation of the id.

The passphrase is **only ever entered at an interactive prompt** — never a flag
or environment variable (those leak via `/proc` and shell history).

## How it works

- **Key hierarchy (envelope key).** `passphrase → Argon2id (m=64 MiB, t=3, p=4) →
  KEK`. The KEK wraps a random 32-byte **master key** generated once. The master
  key — not the passphrase — encrypts the manifest and every blob. Changing the
  passphrase re-wraps the same master key, so **no blob is ever re-encrypted** and
  data cloaked under the old passphrase opens under the new one.
- **Cipher.** XChaCha20-Poly1305. The 192-bit nonce is safe to generate randomly;
  the Poly1305 tag is what makes tampering fail closed and a wrong passphrase
  reveal nothing — not even the item count.
- **Verify before delete.** A cloaked blob is written, fsynced, read back, and
  decrypted-and-compared to the original *before* the original is removed.
- **Atomic writes.** The manifest and `vault.toml` are written to a temp file,
  fsynced, and renamed into place, keeping one backup generation.

See [`docs/FORMAT.md`](docs/FORMAT.md) for the on-disk format and
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for what it does and does not
defend against.

## Build

```
cargo build --release    # binary at target/release/cloakit
cargo test               # includes the security tests (tamper, wrong-password, rotation)
cargo clippy --all-targets -- -D warnings
```

Requires Rust 1.97+ (edition 2024). The crate forbids `unsafe` code
(`unsafe_code = "forbid"`).

## Honest limits

cloakit protects data **at rest, while cloaked**. It does **not** protect a
machine compromised while data is uncloaked, stop a keylogger, act as a backup,
hide that encrypted data exists, or fully hide file sizes. Read
[`SECURITY.md`](SECURITY.md) before you rely on it — those limits are the
difference between using this correctly and getting hurt.

## Status

v0.1.0 — early release, not independently audited.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE),
at your option.
