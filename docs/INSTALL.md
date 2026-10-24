# Installing cloakit

> Status: the prebuilt-binary install is **inactive until the repo is published**
> with release assets. The source build works today from a local checkout.

cloakit installs **user-local, on your PATH, without sudo**. The default is
`~/.local/bin` — a persistent, owner-only directory inside your home. We do
**not** install to system directories or to `/tmp`:

- `/tmp` is world-writable (`drwxrwxrwt`) and auto-wiped (files age out, and it
  often clears on reboot). A security tool's binary has no business living in a
  directory any process can overwrite.
- Hiding the binary in an obscure path is **not** anonymity. The binary is open
  source and an attacker with your machine finds it instantly; what reveals that
  you use cloakit is the vault directory, not the binary — and cloakit
  deliberately does not try to hide that encrypted data exists (see
  `SECURITY.md`). Privacy here comes from **permissions**, not obscurity.

## Option 1 — verified binary install (recommended, once released)

Download the installer, **read it**, then run it. We never tell you to pipe a
URL straight into a shell:

```sh
curl -fsSLO https://github.com/Gypsy-82/cloakit/releases/latest/download/install.sh
less install.sh          # read what you're about to run
sh install.sh
```

The script downloads the binary and its `.sha256`, verifies the checksum, and
only then places it. Customize:

```sh
CLOAKIT_INSTALL_DIR="$HOME/bin" sh install.sh   # install elsewhere
CLOAKIT_VERSION=v0.1.0          sh install.sh   # pin a version
```

### What the checksum does and does not prove

`sha256sum -c` proves the bytes you downloaded match the published digest —
protection against corruption and transit tampering. It does **not**, on its
own, defend against a compromised release host that replaces both the binary and
its checksum. For that, verify the detached **GPG signature** (the installer
checks it automatically when present and you have the maintainer key imported),
or compare the checksum against one published through a second channel.

## Option 2 — build from source (highest trust)

If you'd rather trust nothing but the source and your own compiler:

```sh
# from a local checkout
cd cloakit
cargo install --path .        # installs to ~/.cargo/bin/cloakit

# or, once the repo is published, straight from git:
cargo install --git https://github.com/Gypsy-82/cloakit
```

Requires Rust 1.97+ (edition 2024). Remove with `cargo uninstall cloakit`.

## Verify it's installed

```sh
command -v cloakit && cloakit --help
```

If the install dir isn't on your PATH yet, add it to your shell rc:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

## Uninstall

```sh
rm -f ~/.local/bin/cloakit         # binary install
cargo uninstall cloakit            # source install
```

Removing the binary does **not** touch your vault at
`~/.local/share/cloakit`. Reinstalling any version of cloakit reads the same
vault (the on-disk format is versioned).
