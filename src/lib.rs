//! cloakit — terminal file/folder cloaking.
//!
//! Encrypts not just the *contents* of files but their *names* and the *entire
//! inventory*: without the passphrase you cannot tell what is cloaked, how many
//! items there are, or where they came from.
//!
//! The crate is split into a testable core (`Vault`, `crypto`, `vault`) and a
//! thin CLI layer in `main.rs`. Everything that matters for security lives in
//! the core and is exercised by the integration tests, so claims like "refuses
//! altered data" and "a new passphrase still opens old data" are proven, not
//! asserted.

pub mod crypto;
pub mod util;
pub mod vault;

pub use vault::Vault;
