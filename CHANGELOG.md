# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Changed
- License is now MIT only (was `MIT OR Apache-2.0`).

## [0.1.0] — 2026-10-24

Initial working implementation.

### Added
- `cloakit` (list), `-e` (cloak), `-d` (uncloak), `-p` (change passphrase),
  `--purge <id>` (permanently destroy a cloaked item without restoring it;
  requires the passphrase and a typed id confirmation).
- Envelope-key design: Argon2id-derived KEK wraps a random master key; passphrase
  change re-wraps without re-encrypting any blob.
- XChaCha20-Poly1305 authenticated encryption of blobs and the manifest.
- Encrypted manifest: filenames, origins, sizes, and item count all hidden.
- Verify-before-delete: blobs are read back and decrypted before the original is
  removed.
- Atomic writes for `vault.toml` and the manifest, with one backup generation.
- Terminal-safe display sanitizer for untrusted filename bytes.
- Versioned on-disk format (v1); `CLOAKIT_VAULT_DIR` override.
- Security tests: tamper, wrong-password, passphrase-rotation, round-trip.

### Known limitations
- No file-size padding (size leak documented).
- Whole-file in-memory encryption (RAM scales with item size).
- No `mlock()`; see `SECURITY.md` for the swap caveat.
- Licensed under `MIT OR Apache-2.0`.

[0.1.0]: https://github.com/Gypsy-82/cloakit/releases/tag/v0.1.0
