//! Where the key lives and how it is created and opened.

use crate::dpapi;
use penmark_core::{PublicKey, SecretKey};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

const SECRET_FILE: &str = "signing-key.dpapi";
const PUBLIC_FILE: &str = "signing-key.pub";
const MAGIC: &[u8] = b"PENMARK-KEY-V1\n";
const MAX_KEY_FILE: u64 = 16 * 1024;

/// What can go wrong while handling the stored key.
#[derive(Debug, Error)]
pub enum KeyStoreError {
    /// A key is already there. PenMark never replaces it.
    #[error("a signing key already exists in {0}")]
    AlreadyExists(PathBuf),
    /// No key has been created yet.
    #[error("no signing key found in {0}")]
    NotFound(PathBuf),
    /// The key files are damaged or do not belong together.
    #[error("the stored key is damaged: {0}")]
    Corrupt(String),
    /// Windows refused to unlock the key (other user, other PC, or damaged).
    #[error("Windows could not unlock the key: {0}")]
    Locked(io::Error),
    /// `%LOCALAPPDATA%` is not set.
    #[error("cannot find the local application data folder")]
    NoLocation,
    /// File system error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Error from the signing core.
    #[error(transparent)]
    Core(#[from] penmark_core::Error),
}

type Result<T> = std::result::Result<T, KeyStoreError>;

/// A folder holding one signing key.
#[derive(Clone, Debug)]
pub struct KeyStore {
    dir: PathBuf,
}

impl KeyStore {
    /// A key store in a specific folder.
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The usual place: `%LOCALAPPDATA%\PenMark\keys`.
    pub fn default_location() -> Result<Self> {
        let base = std::env::var_os("LOCALAPPDATA").ok_or(KeyStoreError::NoLocation)?;
        Ok(Self::at(PathBuf::from(base).join("PenMark").join("keys")))
    }

    /// The folder used by this store.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn secret_path(&self) -> PathBuf {
        self.dir.join(SECRET_FILE)
    }

    fn public_path(&self) -> PathBuf {
        self.dir.join(PUBLIC_FILE)
    }

    /// True if a key (or part of one) is already stored here.
    pub fn exists(&self) -> bool {
        self.secret_path().exists() || self.public_path().exists()
    }

    /// Creates a new key, encrypts it for this Windows user and writes it.
    /// Refuses if any key file already exists.
    pub fn create(&self) -> Result<PublicKey> {
        if self.exists() {
            return Err(KeyStoreError::AlreadyExists(self.dir.clone()));
        }
        fs::create_dir_all(&self.dir)?;
        let key = SecretKey::generate()?;
        let sealed = dpapi::protect(&key.to_seed()[..]).map_err(KeyStoreError::Locked)?;
        let mut content = Vec::with_capacity(MAGIC.len() + sealed.len());
        content.extend_from_slice(MAGIC);
        content.extend_from_slice(&sealed);
        write_new(&self.secret_path(), &content)?;
        write_new(
            &self.public_path(),
            format!("{}\n", key.public().to_hex()).as_bytes(),
        )?;
        let reopened = self.load()?;
        if reopened.public() != key.public() {
            return Err(KeyStoreError::Corrupt(
                "the key read back differs from the one written".into(),
            ));
        }
        Ok(key.public())
    }

    /// Unlocks the secret key. Works only for the Windows user who created it.
    pub fn load(&self) -> Result<SecretKey> {
        let path = self.secret_path();
        if !path.exists() {
            return Err(KeyStoreError::NotFound(self.dir.clone()));
        }
        let content = read_limited(&path)?;
        let sealed = content
            .strip_prefix(MAGIC)
            .ok_or_else(|| KeyStoreError::Corrupt("not a PenMark key file".into()))?;
        let seed = dpapi::unprotect(sealed).map_err(KeyStoreError::Locked)?;
        let seed: &[u8; 32] = seed[..]
            .try_into()
            .map_err(|_| KeyStoreError::Corrupt("unexpected key length".into()))?;
        let key = SecretKey::from_seed(seed);
        if self.public_path().exists() && self.public()? != key.public() {
            return Err(KeyStoreError::Corrupt(
                "public key file does not match the secret key".into(),
            ));
        }
        Ok(key)
    }

    /// The public key, read without unlocking anything.
    pub fn public(&self) -> Result<PublicKey> {
        let path = self.public_path();
        if !path.exists() {
            return Err(KeyStoreError::NotFound(self.dir.clone()));
        }
        let text = String::from_utf8(read_limited(&path)?)
            .map_err(|_| KeyStoreError::Corrupt("public key file is not text".into()))?;
        Ok(PublicKey::from_hex(text.trim())?)
    }
}

fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

fn read_limited(path: &Path) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    File::open(path)?
        .take(MAX_KEY_FILE + 1)
        .read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_KEY_FILE {
        return Err(KeyStoreError::Corrupt("key file is too large".into()));
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, KeyStore) {
        let dir = tempfile::tempdir().unwrap();
        let ks = KeyStore::at(dir.path().join("keys"));
        (dir, ks)
    }

    #[test]
    fn create_then_load() {
        let (_d, ks) = store();
        assert!(!ks.exists());
        let public = ks.create().unwrap();
        assert!(ks.exists());
        assert_eq!(ks.load().unwrap().public(), public);
        assert_eq!(ks.public().unwrap(), public);
    }

    #[test]
    fn never_overwrites_an_existing_key() {
        let (_d, ks) = store();
        ks.create().unwrap();
        let before = fs::read(ks.secret_path()).unwrap();
        assert!(matches!(ks.create(), Err(KeyStoreError::AlreadyExists(_))));
        assert_eq!(fs::read(ks.secret_path()).unwrap(), before);
    }

    #[test]
    fn seed_is_not_on_disk_in_clear() {
        let (_d, ks) = store();
        ks.create().unwrap();
        let seed = ks.load().unwrap().to_seed();
        let on_disk = fs::read(ks.secret_path()).unwrap();
        assert!(on_disk.windows(32).all(|w| w != &seed[..]));
        let hex_seed = to_hex(&seed[..]);
        let pub_text = fs::read_to_string(ks.public_path()).unwrap();
        assert!(!pub_text.contains(&hex_seed));
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn missing_key_is_reported() {
        let (_d, ks) = store();
        assert!(matches!(ks.load(), Err(KeyStoreError::NotFound(_))));
        assert!(matches!(ks.public(), Err(KeyStoreError::NotFound(_))));
    }

    #[test]
    fn damaged_files_are_reported() {
        let (_d, ks) = store();
        ks.create().unwrap();
        let mut content = fs::read(ks.secret_path()).unwrap();
        content[0] = b'X';
        fs::write(ks.secret_path(), &content).unwrap();
        assert!(matches!(ks.load(), Err(KeyStoreError::Corrupt(_))));
    }

    #[test]
    fn mismatched_public_file_is_reported() {
        let (_d, ks) = store();
        ks.create().unwrap();
        let other = SecretKey::generate().unwrap().public();
        fs::write(ks.public_path(), format!("{}\n", other.to_hex())).unwrap();
        assert!(matches!(ks.load(), Err(KeyStoreError::Corrupt(_))));
    }

    #[test]
    fn signs_with_the_stored_key() {
        let (d, ks) = store();
        ks.create().unwrap();
        let key = ks.load().unwrap();
        let file = d.path().join("lily-poster.png");
        fs::write(&file, b"png bytes").unwrap();
        let signed = penmark_core::Signed::sign_file(
            &file,
            "Alexander Puglisi",
            &key,
            "2026-11-26T15:40:00Z".into(),
            None,
            "",
        )
        .unwrap();
        let m = penmark_core::digest_file(&file).unwrap();
        assert_eq!(
            penmark_core::verify(&signed, &m, &[ks.public().unwrap()]),
            penmark_core::Verdict::Valid
        );
    }
}
