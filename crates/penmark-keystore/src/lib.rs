//! Keeps the PenMark signing key on disk, encrypted with the Windows account
//! of the person using the PC (DPAPI, current-user scope).
//!
//! - The secret seed is never written in clear and never leaves this PC.
//! - An existing key is never overwritten or deleted by this crate.
//! - Only the public key is stored in clear, so it can be shown and shared
//!   without unlocking anything.

#![cfg(windows)]

mod dpapi;
mod store;

pub use store::{KeyStore, KeyStoreError};
