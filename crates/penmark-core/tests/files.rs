//! End-to-end checks on real files in a temporary folder.

use penmark_core::{SecretKey, Signed, Verdict, digest_file, read_sidecar, sidecar_path, verify};
use std::fs;

#[test]
fn sign_write_read_verify_then_detect_change() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("cubo-officina.blend");
    fs::write(&file, b"BLENDER-v405 pretend scene data").unwrap();

    let key = SecretKey::generate().unwrap();
    let signed = Signed::sign_file(
        &file,
        "Alexander Puglisi",
        &key,
        "2026-11-26T14:32:00Z".into(),
        None,
        "",
    )
    .unwrap();
    let side = sidecar_path(&file);
    fs::write(&side, signed.to_json().unwrap()).unwrap();

    let back = read_sidecar(&side).unwrap();
    let m = digest_file(&file).unwrap();
    assert_eq!(verify(&back, &m, &[key.public()]), Verdict::Valid);

    // Renaming keeps the proof: only the bytes matter.
    let renamed = dir.path().join("cubo-finale.blend");
    fs::rename(&file, &renamed).unwrap();
    let m = digest_file(&renamed).unwrap();
    assert_eq!(verify(&back, &m, &[key.public()]), Verdict::Valid);

    // One extra byte and it is no longer the signed file.
    let mut bytes = fs::read(&renamed).unwrap();
    bytes.push(b'!');
    fs::write(&renamed, bytes).unwrap();
    let m = digest_file(&renamed).unwrap();
    assert!(matches!(
        verify(&back, &m, &[key.public()]),
        Verdict::FileChanged { .. }
    ));
}

#[test]
fn version_chain_links_to_previous() {
    let dir = tempfile::tempdir().unwrap();
    let key = SecretKey::generate().unwrap();
    let v1 = dir.path().join("scena.png");
    fs::write(&v1, b"first version").unwrap();
    let s1 = Signed::sign_file(
        &v1,
        "Alexander Puglisi",
        &key,
        "2026-11-22T10:15:00Z".into(),
        None,
        "Prima versione",
    )
    .unwrap();

    fs::write(&v1, b"second version").unwrap();
    let s2 = Signed::sign_file(
        &v1,
        "Alexander Puglisi",
        &key,
        "2026-11-24T16:02:00Z".into(),
        Some(s1.statement.file_sha256),
        "Nuova inquadratura",
    )
    .unwrap();
    assert_eq!(s2.statement.previous_sha256, Some(s1.statement.file_sha256));
    assert!(s2.signature_is_valid());
    let back = Signed::from_json(&s2.to_json().unwrap()).unwrap();
    assert_eq!(back, s2);
}

#[test]
fn oversized_sidecar_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let side = dir.path().join("big.penmark");
    fs::write(&side, vec![b' '; 70 * 1024]).unwrap();
    assert!(read_sidecar(&side).is_err());
}

/// Fixed key and statement: if this ever changes, old `.penmark` files would
/// stop verifying. Bump the format instead of editing the expected value.
#[test]
fn golden_signature_is_stable() {
    let key = SecretKey::from_seed(&[1; 32]);
    let st = penmark_core::Statement {
        file_name: "cubo-officina.blend".into(),
        file_size: 3,
        file_sha256: penmark_core::digest_reader(&b"abc"[..]).unwrap().digest,
        author: "Alexander Puglisi".into(),
        public_key: key.public(),
        signed_at: "2026-11-26T14:32:00Z".into(),
        previous_sha256: None,
        note: String::new(),
    };
    let s = Signed::sign(st, &key).unwrap();
    assert_eq!(
        hex::encode(s.signature()),
        "247128d51cb0f13beb1b4ca32281a90abda1be3e6f844514cc23f0903f21e12e69560509ce91166988eb781a0bb4afceeeb242de1f7162b9e8c1a4f972814100"
    );
}
