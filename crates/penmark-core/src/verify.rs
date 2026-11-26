//! Checking a file against its signature.

use crate::digest::{FileDigest, Measured};
use crate::keys::PublicKey;
use crate::sidecar::Signed;

/// The outcome of a check, in the order it is decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The `.penmark` was altered or the signature is forged.
    BadSignature,
    /// The signature is genuine, but the file is not the one that was signed.
    FileChanged {
        /// Digest recorded at signing time.
        expected: FileDigest,
        /// Digest of the file being checked.
        found: FileDigest,
    },
    /// Genuine signature, unchanged file, but the key is not one you trust.
    /// The author name inside could be anything: only the key proves identity.
    UnknownKey,
    /// Genuine signature, unchanged file, key among the trusted ones.
    Valid,
}

/// Checks `signed` against the measured file and the keys you trust.
pub fn verify(signed: &Signed, file: &Measured, trusted: &[PublicKey]) -> Verdict {
    if !signed.signature_is_valid() {
        return Verdict::BadSignature;
    }
    let st = &signed.statement;
    if st.file_sha256 != file.digest || st.file_size != file.size {
        return Verdict::FileChanged {
            expected: st.file_sha256,
            found: file.digest,
        };
    }
    if trusted.contains(&st.public_key) {
        Verdict::Valid
    } else {
        Verdict::UnknownKey
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::digest_reader;
    use crate::keys::SecretKey;
    use crate::statement::tests::sample;

    fn setup() -> (SecretKey, Signed, Measured) {
        let k = SecretKey::from_seed(&[1; 32]);
        let s = Signed::sign(sample(&k), &k).unwrap();
        let m = digest_reader(&b"abc"[..]).unwrap();
        (k, s, m)
    }

    #[test]
    fn valid_with_trusted_key() {
        let (k, s, m) = setup();
        assert_eq!(verify(&s, &m, &[k.public()]), Verdict::Valid);
    }

    #[test]
    fn unknown_key_when_not_trusted() {
        let (_, s, m) = setup();
        let other = SecretKey::from_seed(&[2; 32]).public();
        assert_eq!(verify(&s, &m, &[other]), Verdict::UnknownKey);
        assert_eq!(verify(&s, &m, &[]), Verdict::UnknownKey);
    }

    #[test]
    fn changed_file_detected() {
        let (k, s, _) = setup();
        let m = digest_reader(&b"abd"[..]).unwrap();
        assert!(matches!(
            verify(&s, &m, &[k.public()]),
            Verdict::FileChanged { .. }
        ));
    }

    #[test]
    fn impostor_resigning_with_same_name_is_unknown_key() {
        let (alex, _, m) = setup();
        let impostor = SecretKey::from_seed(&[66; 32]);
        let fake = Signed::sign(sample(&impostor), &impostor).unwrap();
        assert_eq!(fake.statement.author, "Alexander Puglisi");
        assert_eq!(verify(&fake, &m, &[alex.public()]), Verdict::UnknownKey);
    }

    #[test]
    fn forged_signature_wins_over_everything() {
        let (k, s, m) = setup();
        let json = s.to_json().unwrap();
        let sig = hex::encode(s.signature());
        let mut flipped = sig.clone().into_bytes();
        flipped[0] = if flipped[0] == b'0' { b'1' } else { b'0' };
        let json = json.replace(&sig, std::str::from_utf8(&flipped).unwrap());
        let forged = Signed::from_json(&json).unwrap();
        assert_eq!(verify(&forged, &m, &[k.public()]), Verdict::BadSignature);
    }
}
