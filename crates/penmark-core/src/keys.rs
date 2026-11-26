//! Ed25519 keys. This module only holds keys in memory: storing the secret
//! key on disk (protected by Windows) is done elsewhere.

use crate::error::{Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// Length of a public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of a signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

const KEY_ID_DOMAIN: &[u8] = b"PENMARK-KEY-ID-V1\0";

/// The private half of a signing key. Never printed, wiped from memory on drop.
pub struct SecretKey(SigningKey);

impl SecretKey {
    /// Creates a new key from the operating system's random generator.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| Error::Random(e.to_string()))?;
        let key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Ok(Self(key))
    }

    /// Rebuilds a key from its 32-byte seed (for example after unlocking it).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// The 32-byte seed, in a buffer that is wiped when dropped.
    /// Only for protected storage; never log or display it.
    pub fn to_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// The public half, safe to share.
    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.0.sign(message).to_bytes()
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(hidden)")
    }
}

/// The public half of a signing key: anyone can use it to check a signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// Parses 32 raw bytes; rejects bytes that are not a valid curve point.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Result<Self> {
        VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| Error::Format("public key is not a valid Ed25519 key".into()))
    }

    /// Parses 64 hex characters.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|_| Error::Format("public key is not hex".into()))?;
        let arr: [u8; PUBLIC_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| Error::Format("public key must be 32 bytes".into()))?;
        Self::from_bytes(&arr)
    }

    /// Raw 32 bytes.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Lowercase hex, 64 characters.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Short identifier people can compare by eye.
    pub fn id(&self) -> KeyId {
        let mut h = Sha256::new();
        h.update(KEY_ID_DOMAIN);
        h.update(self.to_bytes());
        let full: [u8; 32] = h.finalize().into();
        let mut id = [0u8; 8];
        id.copy_from_slice(&full[..8]);
        KeyId(id)
    }

    /// Strict Ed25519 verification (rejects malleable and weak-key signatures).
    pub(crate) fn verify(&self, message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> bool {
        let sig = Signature::from_bytes(signature);
        self.0.verify_strict(message, &sig).is_ok()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.id())
    }
}

/// 8-byte key identifier shown as four groups, e.g. `7F3A 91C2 5E08 D4B1`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId(pub [u8; 8]);

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let h = hex::encode_upper(self.0);
        write!(f, "{} {} {} {}", &h[0..4], &h[4..8], &h[8..12], &h[12..16])
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_differ() {
        let a = SecretKey::generate().unwrap();
        let b = SecretKey::generate().unwrap();
        assert_ne!(a.public(), b.public());
    }

    #[test]
    fn seed_roundtrip_keeps_public_key() {
        let a = SecretKey::generate().unwrap();
        let b = SecretKey::from_seed(&a.to_seed());
        assert_eq!(a.public(), b.public());
    }

    #[test]
    fn debug_never_shows_secret() {
        let k = SecretKey::from_seed(&[0x42; 32]);
        let shown = format!("{k:?}");
        assert_eq!(shown, "SecretKey(hidden)");
        assert!(!shown.contains("42"));
    }

    #[test]
    fn sign_and_verify() {
        let k = SecretKey::from_seed(&[1; 32]);
        let sig = k.sign(b"hello");
        assert!(k.public().verify(b"hello", &sig));
        assert!(!k.public().verify(b"hellp", &sig));
        let other = SecretKey::from_seed(&[2; 32]);
        assert!(!other.public().verify(b"hello", &sig));
    }

    #[test]
    fn public_key_hex_roundtrip() {
        let p = SecretKey::from_seed(&[9; 32]).public();
        assert_eq!(PublicKey::from_hex(&p.to_hex()).unwrap(), p);
        assert!(PublicKey::from_hex("00").is_err());
        assert!(PublicKey::from_hex("not hex").is_err());
    }

    #[test]
    fn key_id_format() {
        let id = SecretKey::from_seed(&[3; 32]).public().id().to_string();
        assert_eq!(id.len(), 19);
        assert_eq!(id.split(' ').count(), 4);
        assert!(id.chars().all(|c| c == ' ' || c.is_ascii_hexdigit()));
    }
}
