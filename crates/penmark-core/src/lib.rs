//! PenMark core: hash a file, sign it with an Ed25519 key and verify it later.
//!
//! The signature covers the whole saved file (its SHA-256), the author name,
//! the public key, the time on the PC clock, an optional link to the previous
//! version and an optional note. It is stored as a small `.penmark` file next
//! to the original.
//!
//! A signature is proof, not a lock: it shows who signed a file and when, it
//! does not stop anyone from copying the content.

#![forbid(unsafe_code)]

pub mod digest;
mod error;
pub mod keys;
pub mod sidecar;
pub mod statement;
pub mod verify;

pub use digest::{FileDigest, Measured, digest_file, digest_reader};
pub use error::{Error, Result};
pub use keys::{KeyId, PublicKey, SecretKey};
pub use sidecar::{MAX_SIDECAR_BYTES, Signed, read_sidecar, sidecar_path, write_sidecar};
pub use statement::{FORMAT, Statement, now_utc_rfc3339};
pub use verify::{Verdict, verify};
