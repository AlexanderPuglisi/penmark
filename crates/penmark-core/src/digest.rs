//! SHA-256 of a whole file, read in chunks so large videos do not fill memory.

use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Length of a SHA-256 digest in bytes.
pub const DIGEST_LEN: usize = 32;

const CHUNK: usize = 64 * 1024;

/// The SHA-256 fingerprint of a file's exact bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileDigest(pub [u8; DIGEST_LEN]);

impl FileDigest {
    /// Lowercase hex, 64 characters.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses 64 hex characters; anything else is rejected.
    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != DIGEST_LEN * 2 {
            return None;
        }
        let bytes = hex::decode(s).ok()?;
        Some(Self(bytes.try_into().ok()?))
    }

    /// Short form for people: first and last 4 hex characters.
    pub fn short(&self) -> String {
        let h = self.to_hex();
        format!("{}…{}", &h[..4], &h[h.len() - 4..])
    }
}

impl fmt::Debug for FileDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileDigest({})", self.to_hex())
    }
}

impl fmt::Display for FileDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Digest and size of a file, measured in one pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Measured {
    /// SHA-256 of every byte.
    pub digest: FileDigest,
    /// Number of bytes read.
    pub size: u64,
}

/// Hashes everything the reader yields.
pub fn digest_reader<R: Read>(mut reader: R) -> io::Result<Measured> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut size: u64 = 0;
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    let out: [u8; DIGEST_LEN] = hasher.finalize().into();
    Ok(Measured {
        digest: FileDigest(out),
        size,
    })
}

/// Hashes the file at `path`, whole.
pub fn digest_file(path: &Path) -> io::Result<Measured> {
    digest_reader(File::open(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector_abc() {
        let m = digest_reader(&b"abc"[..]).unwrap();
        assert_eq!(
            m.digest.to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(m.size, 3);
    }

    #[test]
    fn empty_input() {
        let m = digest_reader(&b""[..]).unwrap();
        assert_eq!(
            m.digest.to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(m.size, 0);
    }

    #[test]
    fn larger_than_one_chunk() {
        let data = vec![7u8; CHUNK * 3 + 11];
        let m = digest_reader(&data[..]).unwrap();
        let direct: [u8; DIGEST_LEN] = Sha256::digest(&data).into();
        assert_eq!(m.digest.0, direct);
        assert_eq!(m.size, data.len() as u64);
    }

    #[test]
    fn hex_roundtrip_and_rejects() {
        let d = digest_reader(&b"penmark"[..]).unwrap().digest;
        assert_eq!(FileDigest::from_hex(&d.to_hex()), Some(d));
        assert_eq!(FileDigest::from_hex("abcd"), None);
        assert_eq!(FileDigest::from_hex(&"zz".repeat(32)), None);
        assert_eq!(d.short().chars().count(), 9);
    }
}
