# Releasing cloakit

How a release is cut, and **why the binary is built the way it is**. The
mechanics live in [`.github/workflows/release.yml`](../.github/workflows/release.yml);
this document is the reasoning behind it.

## Cutting a release

1. Bump `version` in `Cargo.toml` and move the `CHANGELOG.md` entry from
   `unreleased` to the real date.
2. Commit, then push a matching tag:

   ```sh
   git tag v0.1.0
   git push origin v0.1.0
   ```

3. The `release` workflow fires on the `v*` tag, builds a static binary,
   packages it, and creates the GitHub Release with the tarball and its
   `.sha256` attached.

The workflow **refuses to run if the tag and `Cargo.toml` version disagree**
(e.g. pushing `v0.1.0` while the crate still says `0.0.9`), so a mislabeled
binary never ships.

## Why a static musl binary — the libc loose thread

A Rust `--release` build already produces a single self-contained executable:
your code and every Rust dependency are compiled *into* it, so whoever runs it
needs **no Rust, no cargo, and no source** — just the one file. That is the
whole appeal of shipping a binary.

The one thing that is **not** baked in by default is the C library. A normal
Linux build links dynamically against the system **glibc**. glibc is forward-
compatible but not backward-compatible: a binary built on, say, Ubuntu 24.04
records the glibc version it was built against, and on an **older** machine it
refuses to start with:

```
./cloakit: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.38' not found
```

That single detail is what turns "download and run anywhere" into a support
headache — the binary works on boxes as new as or newer than the build host and
breaks on anything older.

**The fix: build against musl libc** (`x86_64-unknown-linux-musl`). musl links
*into* the binary, producing a **fully static** executable with zero shared-
library dependencies. It then runs on any Linux kernel regardless of
distribution or age — Alpine, a decade-old CentOS, a stripped container, a NAS.
For a tool people run on assorted servers and appliances, that portability is
worth far more than the small size and speed cost of musl over glibc.

cloakit is an ideal candidate because **all of its dependencies are pure Rust**
(`argon2`, `chacha20poly1305`, and the rest — no OpenSSL or other C libraries).
So the musl build needs no C cross-toolchain (`musl-gcc`); Rust supplies its own
musl and self-links.

### Verifying "static" is real, not assumed

Two independent checks confirm it, and the workflow runs the `ldd` one as a
gate:

```sh
$ file target/x86_64-unknown-linux-musl/release/cloakit
ELF 64-bit LSB pie executable, x86-64, ... static-pie linked, stripped

$ ldd target/x86_64-unknown-linux-musl/release/cloakit
	statically linked
```

`statically linked` / `not a dynamic executable` from `ldd` is the proof that
there is no glibc (or any other shared library) dependency left to go missing.

## Release assets

Each release carries:

- `cloakit-<tag>-x86_64-linux-musl.tar.gz` — the static binary plus `README.md`,
  `CHANGELOG.md`, and both license files.
- `cloakit-<tag>-x86_64-linux-musl.tar.gz.sha256` — the checksum. `sha256sum -c`
  proves the download matches the published digest (corruption and transit
  tampering); it does **not** by itself defend against a host that replaces both
  files. See [`INSTALL.md`](INSTALL.md) for what the checksum does and does not
  prove.

## Known gaps

- **Single architecture.** Only `x86_64` is published. `aarch64-unknown-linux-musl`
  can be added as a second matrix target when there's demand (ARM servers, newer
  Raspberry Pi, Apple-silicon Linux VMs).
- **Installer vs. asset shape.** `INSTALL.md` describes an `install.sh` that
  fetches a bare binary + `.sha256` (and an optional GPG signature). This
  workflow ships a `.tar.gz` + `.sha256`. Those must be reconciled before the
  installer path in `INSTALL.md` goes live — either the installer learns to
  unpack the tarball, or the workflow also uploads the bare binary and a
  signature.
- **No signature.** The workflow does not yet produce a detached GPG (or
  minisign/cosign) signature, which `INSTALL.md` references as the real defense
  against a compromised release host.
