//! The `.penmark` file: a signed statement written as readable JSON.

use crate::digest::{FileDigest, digest_file};
use crate::error::{Error, Result};
use crate::keys::{PublicKey, SIGNATURE_LEN, SecretKey};
use crate::statement::{FORMAT, Statement};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

/// A `.penmark` file is tiny; anything bigger is refused before parsing.
pub const MAX_SIDECAR_BYTES: u64 = 64 * 1024;

/// Extension appended to the full file name: `cubo.blend` → `cubo.blend.penmark`.
pub const EXTENSION: &str = "penmark";

/// A statement together with its signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    /// What is vouched for.
    pub statement: Statement,
    signature: [u8; SIGNATURE_LEN],
}

impl Signed {
    /// Signs a statement. The statement must name the same key that signs it.
    pub fn sign(statement: Statement, key: &SecretKey) -> Result<Self> {
        statement.validate()?;
        if statement.public_key != key.public() {
            return Err(Error::Input(
                "statement public key does not match the signing key".into(),
            ));
        }
        let signature = key.sign(&statement.signing_bytes());
        Ok(Self {
            statement,
            signature,
        })
    }

    /// True when the signature matches the statement and its key.
    /// It says nothing about the file itself or who owns the key.
    pub fn signature_is_valid(&self) -> bool {
        self.statement
            .public_key
            .verify(&self.statement.signing_bytes(), &self.signature)
    }

    /// The raw 64-byte signature.
    pub fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }

    /// Readable JSON for the `.penmark` file.
    pub fn to_json(&self) -> Result<String> {
        let s = &self.statement;
        let wire = Wire {
            format: FORMAT.to_string(),
            file: WireFile {
                name: s.file_name.clone(),
                size: s.file_size,
                sha256: s.file_sha256.to_hex(),
            },
            author: s.author.clone(),
            key: WireKey {
                algorithm: ALGORITHM.to_string(),
                public: s.public_key.to_hex(),
                id: s.public_key.id().to_string(),
            },
            signed_at: s.signed_at.clone(),
            previous_sha256: s.previous_sha256.map(|d| d.to_hex()),
            note: s.note.clone(),
            signature: hex::encode(self.signature),
        };
        let mut out =
            serde_json::to_string_pretty(&wire).map_err(|e| Error::Format(e.to_string()))?;
        out.push('\n');
        Ok(out)
    }

    /// Parses a `.penmark` file. Structure is checked strictly; the signature
    /// itself is checked later by [`crate::verify`].
    pub fn from_json(text: &str) -> Result<Self> {
        if text.len() as u64 > MAX_SIDECAR_BYTES {
            return Err(Error::Format("file is too large".into()));
        }
        let wire: Wire = serde_json::from_str(text).map_err(|e| Error::Format(e.to_string()))?;
        if wire.format != FORMAT {
            return Err(Error::Format(format!(
                "unsupported format {:?}",
                wire.format
            )));
        }
        if wire.key.algorithm != ALGORITHM {
            return Err(Error::Format(format!(
                "unsupported algorithm {:?}",
                wire.key.algorithm
            )));
        }
        let public_key = PublicKey::from_hex(&wire.key.public)?;
        if public_key.id().to_string() != wire.key.id {
            return Err(Error::Format("key id does not match the public key".into()));
        }
        let file_sha256 = FileDigest::from_hex(&wire.file.sha256)
            .ok_or_else(|| Error::Format("file sha256 must be 64 hex characters".into()))?;
        let previous_sha256 = match wire.previous_sha256 {
            Some(h) => Some(FileDigest::from_hex(&h).ok_or_else(|| {
                Error::Format("previous sha256 must be 64 hex characters".into())
            })?),
            None => None,
        };
        let sig_bytes = hex::decode(&wire.signature)
            .map_err(|_| Error::Format("signature is not hex".into()))?;
        let signature: [u8; SIGNATURE_LEN] = sig_bytes
            .try_into()
            .map_err(|_| Error::Format("signature must be 64 bytes".into()))?;
        let statement = Statement {
            file_name: wire.file.name,
            file_size: wire.file.size,
            file_sha256,
            author: wire.author,
            public_key,
            signed_at: wire.signed_at,
            previous_sha256,
            note: wire.note,
        };
        statement
            .validate()
            .map_err(|e| Error::Format(e.to_string()))?;
        Ok(Self {
            statement,
            signature,
        })
    }

    /// Hashes `path` and signs it. The file name stored is the last path part.
    pub fn sign_file(
        path: &Path,
        author: &str,
        key: &SecretKey,
        signed_at: String,
        previous_sha256: Option<FileDigest>,
        note: &str,
    ) -> Result<Self> {
        let measured = digest_file(path)?;
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| Error::Input("file name is not valid Unicode".into()))?
            .to_string();
        let statement = Statement {
            file_name,
            file_size: measured.size,
            file_sha256: measured.digest,
            author: author.to_string(),
            public_key: key.public(),
            signed_at,
            previous_sha256,
            note: note.to_string(),
        };
        Self::sign(statement, key)
    }
}

/// Where the `.penmark` for `file` lives: same folder, extension appended.
pub fn sidecar_path(file: &Path) -> PathBuf {
    let mut name: OsString = file.as_os_str().to_owned();
    name.push(".");
    name.push(EXTENSION);
    PathBuf::from(name)
}

/// Reads and parses a `.penmark` file, refusing oversized input.
pub fn read_sidecar(path: &Path) -> Result<Signed> {
    let file = File::open(path)?;
    let mut text = String::new();
    file.take(MAX_SIDECAR_BYTES + 1).read_to_string(&mut text)?;
    Signed::from_json(&text)
}

const ALGORITHM: &str = "ed25519";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    format: String,
    file: WireFile,
    author: String,
    key: WireKey,
    signed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    note: String,
    signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireFile {
    name: String,
    size: u64,
    sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireKey {
    algorithm: String,
    public: String,
    id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::statement::tests::sample;

    fn signed() -> (SecretKey, Signed) {
        let k = SecretKey::from_seed(&[1; 32]);
        let s = Signed::sign(sample(&k), &k).unwrap();
        (k, s)
    }

    #[test]
    fn json_roundtrip() {
        let (_, s) = signed();
        let json = s.to_json().unwrap();
        let back = Signed::from_json(&json).unwrap();
        assert_eq!(back, s);
        assert!(back.signature_is_valid());
    }

    #[test]
    fn json_is_readable() {
        let (_, s) = signed();
        let json = s.to_json().unwrap();
        assert!(json.contains("\"format\": \"penmark/1\""));
        assert!(json.contains("\"author\": \"Alexander Puglisi\""));
        assert!(json.contains("\"name\": \"cubo-officina.blend\""));
        assert!(!json.contains("previous_sha256"));
        assert!(!json.contains("\"note\""));
    }

    #[test]
    fn refuses_to_sign_with_other_key() {
        let k = SecretKey::from_seed(&[1; 32]);
        let other = SecretKey::from_seed(&[2; 32]);
        assert!(Signed::sign(sample(&k), &other).is_err());
    }

    #[test]
    fn edited_author_breaks_signature() {
        let (_, s) = signed();
        let json = s
            .to_json()
            .unwrap()
            .replace("Alexander Puglisi", "Someone Else");
        let back = Signed::from_json(&json).unwrap();
        assert!(!back.signature_is_valid());
    }

    #[test]
    fn edited_date_breaks_signature() {
        let (_, s) = signed();
        let json = s
            .to_json()
            .unwrap()
            .replace("2026-11-26T14:32:00Z", "2020-01-01T00:00:00Z");
        let back = Signed::from_json(&json).unwrap();
        assert!(!back.signature_is_valid());
    }

    #[test]
    fn rejects_unknown_fields() {
        let (_, s) = signed();
        let json = s
            .to_json()
            .unwrap()
            .replacen("{", "{\n  \"verified\": true,", 1);
        assert!(Signed::from_json(&json).is_err());
    }

    #[test]
    fn rejects_wrong_format_and_algorithm() {
        let (_, s) = signed();
        let json = s.to_json().unwrap();
        assert!(Signed::from_json(&json.replace("penmark/1", "penmark/9")).is_err());
        assert!(Signed::from_json(&json.replace("\"ed25519\"", "\"rsa\"")).is_err());
    }

    #[test]
    fn rejects_mismatched_key_id() {
        let (k, s) = signed();
        let id = k.public().id().to_string();
        let json = s.to_json().unwrap().replace(&id, "0000 0000 0000 0000");
        assert!(Signed::from_json(&json).is_err());
    }

    #[test]
    fn rejects_garbage_and_oversize() {
        assert!(Signed::from_json("").is_err());
        assert!(Signed::from_json("not json").is_err());
        assert!(Signed::from_json(&" ".repeat(MAX_SIDECAR_BYTES as usize + 1)).is_err());
    }

    #[test]
    fn sidecar_path_appends_extension() {
        let p = sidecar_path(Path::new("C:\\Opere\\cubo.blend"));
        assert_eq!(p, PathBuf::from("C:\\Opere\\cubo.blend.penmark"));
        let p = sidecar_path(Path::new("senza-estensione"));
        assert_eq!(p, PathBuf::from("senza-estensione.penmark"));
    }
}
