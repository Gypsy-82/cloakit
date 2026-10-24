# Security

## What cloakit protects

Data **at rest, while cloaked**: contents, filenames, and the inventory itself
are encrypted with XChaCha20-Poly1305 under a key derived from your passphrase
via Argon2id. A stolen laptop, a compromised NAS, or a seized VPS yields
numbered, authenticated blobs and a header that proves nothing about what the
data is or how much of it there is.

## What cloakit does NOT do

- **Protect a machine compromised while uncloaked.** Own the session, own the
  keys. cloakit guards the locked state, not the unlocked one.
- **Stop a keylogger** capturing the passphrase as you type it.
- **Act as a backup.** Vault corruption means permanent loss — the manifest and
  the wrapped master key are single points of failure. **Back up the vault.**
- **Hide that encrypted data exists.** Root sees a `cloakit` directory of obvious
  blobs; what they cannot tell is what any of it *is*.
- **Fully hide file sizes.** A blob is roughly the size of its input. Padding is
  not implemented in v1 (see below); size is a documented leak.
- **Un-write history.** Plaintext already written to an unencrypted SSD may
  persist in unmapped NAND beyond any userspace tool's reach. Full-disk
  encryption remains the only complete answer; cloakit is complementary.

Dotfile/name hiding is tidiness, not security. Hidden volumes and plausible
deniability are out of scope.

## Known v1 limitations

- **Memory residency / swap.** Keys live in RAM and are wiped on drop
  (`zeroize`), but cloakit does **not** `mlock()` key pages — that would require
  `unsafe`, which the crate forbids. With `zram` swap (compressed RAM, no disk
  partition) or no swap, keys never reach persistent storage.
  **On a host with a disk swap partition or swapfile, a derived key could
  transiently reach swap.** If that is in your threat model, use encrypted swap
  (or `zram`). This is an honest limit, not a silent one.
- **Whole-file in memory.** v1 reads each item fully into memory to encrypt it,
  so cloaking a very large file or folder uses RAM proportional to its size.
  Streaming/chunked encryption is future work.
- **File-size leak.** No padding in v1. The manifest stores the true length, so
  bucket-padding can be added later without a format change.
- **Symlinks and special files** are rejected at the top level and stored (not
  followed) inside a cloaked directory.

## Reporting

Please **do not** open a public issue for a vulnerability. Report it privately
via GitHub's *Report a vulnerability* button on the repository's **Security**
tab (private vulnerability reporting). Include the affected version and a
description of the class of problem.
