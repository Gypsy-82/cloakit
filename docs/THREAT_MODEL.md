# Threat model

## Assets

The confidentiality of cloaked data — not only file contents, but filenames, the
count of items, and their origin paths.

## The attacker cloakit defends against

An adversary who obtains the **vault at rest** while it is locked:

- a stolen or lost laptop,
- a compromised NAS or backup target holding the vault,
- a seized or imaged VPS.

Against this attacker, every object is an authenticated, numbered blob, and the
`vault.toml` header exposes only public KDF parameters and a wrapped key that is
useless without the passphrase. The attacker cannot read contents, recover
filenames, or even count the items.

### Guarantees and how they're proven

| Guarantee | Mechanism | Proof |
|---|---|---|
| Wrong passphrase reveals nothing | KEK unwrap fails the Poly1305 tag | `tests/wrong_password.rs` |
| Altered blob never yields garbage | AEAD tag verification, fail-closed | `tests/tamper.rs` |
| Passphrase change keeps old data readable | envelope key (master key unchanged) | `tests/manifest.rs::password_change_preserves_access` |
| Restore is byte-identical | tar round-trip, verified by hash in review | `tests/roundtrip.rs` |
| Filenames can't attack the terminal | display sanitizer | `tests/display.rs`, `src/util/display.rs` |
| Original never lost on a failed cloak | verify-before-delete ordering | `src/vault/store.rs`, `src/vault/mod.rs` |

## Out of scope

- **A live, compromised host while data is uncloaked.** If the attacker controls
  the running session, they control the keys and the plaintext.
- **Keyloggers / input capture** of the passphrase.
- **Coercion / rubber-hose.** No hidden volumes or plausible deniability.
- **Traffic/size analysis.** Blob size approximates input size (no padding in v1).
- **Recovery of plaintext from unmapped SSD NAND** written before cloaking.
  Full-disk encryption is the complementary control.
- **Availability.** cloakit is not a backup; vault loss is permanent data loss.

## Trust assumptions

- The binary and the machine are trusted at the moment of cloak/uncloak.
- The OS CSPRNG (`OsRng`) is sound.
- Argon2id parameters (64 MiB / t=3 / p=4) make offline guessing of a decent
  passphrase expensive; a weak passphrase is still a weak passphrase.
