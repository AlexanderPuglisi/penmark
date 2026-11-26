//! What exactly gets signed, and its byte encoding.
//!
//! The signature is computed over a fixed binary encoding, not over JSON, so
//! the result never depends on spacing, key order or escaping. Every field is
//! length-prefixed, which keeps `"ab" + "c"` distinct from `"a" + "bc"`.

use crate::digest::FileDigest;
use crate::error::{Error, Result};
use crate::keys::PublicKey;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Format tag written in every `.penmark` file.
pub const FORMAT: &str = "penmark/1";

const DOMAIN: &[u8] = b"PENMARK-SIGNATURE-V1\0";

/// Longest accepted file name, in bytes.
pub const MAX_FILE_NAME: usize = 1024;
/// Longest accepted author name, in bytes.
pub const MAX_AUTHOR: usize = 256;
/// Longest accepted note, in bytes.
pub const MAX_NOTE: usize = 4096;

/// The facts a signature vouches for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    /// File name at signing time (informative: renaming keeps the proof).
    pub file_name: String,
    /// Exact size in bytes.
    pub file_size: u64,
    /// SHA-256 of the whole file.
    pub file_sha256: FileDigest,
    /// Name the signer chose. Anyone can type any name: the key is what counts.
    pub author: String,
    /// Key that made the signature.
    pub public_key: PublicKey,
    /// Time from the PC clock, RFC 3339 in UTC. It can be set wrong on purpose.
    pub signed_at: String,
    /// SHA-256 of the previous version, if this file continues a chain.
    pub previous_sha256: Option<FileDigest>,
    /// Optional note, e.g. what changed in this version.
    pub note: String,
}

impl Statement {
    /// Checks lengths, characters and the time format.
    pub fn validate(&self) -> Result<()> {
        check_text("file name", &self.file_name, MAX_FILE_NAME, false)?;
        check_text("author", &self.author, MAX_AUTHOR, false)?;
        check_text("note", &self.note, MAX_NOTE, true)?;
        if self.author.trim().is_empty() {
            return Err(Error::Input("author must not be empty".into()));
        }
        if self.file_name.contains(['/', '\\']) {
            return Err(Error::Input("file name must not contain a path".into()));
        }
        let t = OffsetDateTime::parse(&self.signed_at, &Rfc3339)
            .map_err(|_| Error::Input("signed_at must be RFC 3339".into()))?;
        if t.offset() != time::UtcOffset::UTC {
            return Err(Error::Input("signed_at must be in UTC".into()));
        }
        Ok(())
    }

    /// The exact bytes the Ed25519 signature covers.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.note.len());
        out.extend_from_slice(DOMAIN);
        put(&mut out, self.file_name.as_bytes());
        put(&mut out, &self.file_size.to_be_bytes());
        put(&mut out, &self.file_sha256.0);
        put(&mut out, self.author.as_bytes());
        put(&mut out, &self.public_key.to_bytes());
        put(&mut out, self.signed_at.as_bytes());
        match &self.previous_sha256 {
            Some(d) => {
                out.push(1);
                put(&mut out, &d.0);
            }
            None => out.push(0),
        }
        put(&mut out, self.note.as_bytes());
        out
    }
}

fn put(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u64).to_be_bytes());
    out.extend_from_slice(field);
}

fn check_text(what: &str, s: &str, max: usize, allow_newlines: bool) -> Result<()> {
    if s.len() > max {
        return Err(Error::Input(format!("{what} is longer than {max} bytes")));
    }
    let bad = s
        .chars()
        .any(|c| c.is_control() && !(allow_newlines && (c == '\n' || c == '\t')));
    if bad {
        return Err(Error::Input(format!("{what} contains control characters")));
    }
    Ok(())
}

/// Current PC time in UTC, whole seconds, RFC 3339 (e.g. `2026-11-26T14:32:00Z`).
pub fn now_utc_rfc3339() -> Result<String> {
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .map_err(|e| Error::Input(e.to_string()))?;
    now.format(&Rfc3339)
        .map_err(|e| Error::Input(e.to_string()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::digest::digest_reader;
    use crate::keys::SecretKey;

    pub(crate) fn sample(key: &SecretKey) -> Statement {
        Statement {
            file_name: "cubo-officina.blend".into(),
            file_size: 3,
            file_sha256: digest_reader(&b"abc"[..]).unwrap().digest,
            author: "Alexander Puglisi".into(),
            public_key: key.public(),
            signed_at: "2026-11-26T14:32:00Z".into(),
            previous_sha256: None,
            note: String::new(),
        }
    }

    #[test]
    fn sample_is_valid() {
        let k = SecretKey::from_seed(&[1; 32]);
        sample(&k).validate().unwrap();
    }

    #[test]
    fn every_field_changes_the_bytes() {
        let k = SecretKey::from_seed(&[1; 32]);
        let base = sample(&k);
        let b0 = base.signing_bytes();
        let mut variants = Vec::new();
        let mut s = base.clone();
        s.file_name = "cubo-officina2.blend".into();
        variants.push(s);
        let mut s = base.clone();
        s.file_size = 4;
        variants.push(s);
        let mut s = base.clone();
        s.file_sha256 = digest_reader(&b"abd"[..]).unwrap().digest;
        variants.push(s);
        let mut s = base.clone();
        s.author = "Someone Else".into();
        variants.push(s);
        let mut s = base.clone();
        s.public_key = SecretKey::from_seed(&[2; 32]).public();
        variants.push(s);
        let mut s = base.clone();
        s.signed_at = "2026-11-26T14:32:01Z".into();
        variants.push(s);
        let mut s = base.clone();
        s.previous_sha256 = Some(base.file_sha256);
        variants.push(s);
        let mut s = base.clone();
        s.note = "v2".into();
        variants.push(s);
        for v in variants {
            assert_ne!(v.signing_bytes(), b0);
        }
    }

    #[test]
    fn length_prefix_prevents_shifting() {
        let k = SecretKey::from_seed(&[1; 32]);
        let mut a = sample(&k);
        let mut b = sample(&k);
        a.author = "Alexander".into();
        a.note = " Puglisi".into();
        b.author = "Alexander Puglisi".into();
        b.note = String::new();
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn rejects_bad_input() {
        let k = SecretKey::from_seed(&[1; 32]);
        let mut s = sample(&k);
        s.author = "  ".into();
        assert!(s.validate().is_err());
        let mut s = sample(&k);
        s.author = "a\u{0007}b".into();
        assert!(s.validate().is_err());
        let mut s = sample(&k);
        s.file_name = "dir\\file.png".into();
        assert!(s.validate().is_err());
        let mut s = sample(&k);
        s.signed_at = "26/11/2026".into();
        assert!(s.validate().is_err());
        let mut s = sample(&k);
        s.signed_at = "2026-11-26T15:32:00+01:00".into();
        assert!(s.validate().is_err());
        let mut s = sample(&k);
        s.note = "x".repeat(MAX_NOTE + 1);
        assert!(s.validate().is_err());
        let mut s = sample(&k);
        s.note = "line one\nline two".into();
        assert!(s.validate().is_ok());
    }

    #[test]
    fn now_is_valid_rfc3339_utc() {
        let k = SecretKey::from_seed(&[1; 32]);
        let mut s = sample(&k);
        s.signed_at = now_utc_rfc3339().unwrap();
        assert!(s.signed_at.ends_with('Z'));
        s.validate().unwrap();
    }
}
