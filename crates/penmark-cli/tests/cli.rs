//! Runs the real `penmark` binary against temporary folders.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn penmark(keys: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_penmark"))
        .arg("--keys")
        .arg(keys)
        .args(args)
        .output()
        .unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn public_hex(keys: &Path) -> String {
    let o = penmark(keys, &["key", "show"]);
    out(&o)
        .lines()
        .find_map(|l| l.strip_prefix("Chiave pubblica: "))
        .unwrap()
        .trim()
        .to_string()
}

#[test]
fn full_flow() {
    let d = tempfile::tempdir().unwrap();
    let keys = d.path().join("keys");
    let file = d.path().join("cubo-officina.blend");
    fs::write(&file, b"scene").unwrap();
    let f = file.to_str().unwrap();

    let o = penmark(&keys, &["key", "create"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(out(&o).contains("Codice chiave:"));

    // A second create must fail and leave the key alone.
    let before = fs::read(keys.join("signing-key.dpapi")).unwrap();
    let o = penmark(&keys, &["key", "create"]);
    assert_eq!(o.status.code(), Some(4));
    assert_eq!(fs::read(keys.join("signing-key.dpapi")).unwrap(), before);

    let o = penmark(&keys, &["sign", f, "--author", "Alexander Puglisi"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let side = d.path().join("cubo-officina.blend.penmark");
    assert!(side.exists());

    let o = penmark(&keys, &["verify", f]);
    assert_eq!(o.status.code(), Some(0));
    assert!(out(&o).contains("FIRMA VALIDA"));

    // Signing again must not overwrite the existing .penmark.
    let side_before = fs::read(&side).unwrap();
    let o = penmark(&keys, &["sign", f, "--author", "Alexander Puglisi"]);
    assert_eq!(o.status.code(), Some(4));
    assert_eq!(fs::read(&side).unwrap(), side_before);

    // Someone else's PC, no trust: unknown key.
    let stranger = d.path().join("stranger-keys");
    let o = penmark(&stranger, &["verify", f]);
    assert_eq!(o.status.code(), Some(1));
    // ...until they trust Alex's published public key.
    let alex = public_hex(&keys);
    let o = penmark(&stranger, &["verify", f, "--trust", &alex]);
    assert_eq!(o.status.code(), Some(0));

    // Edited author: forged.
    let edited = String::from_utf8(side_before.clone())
        .unwrap()
        .replace("Alexander Puglisi", "Mallory");
    fs::write(&side, edited).unwrap();
    let o = penmark(&keys, &["verify", f]);
    assert_eq!(o.status.code(), Some(3));
    fs::write(&side, &side_before).unwrap();

    // Changed file.
    fs::write(&file, b"scene, edited").unwrap();
    let o = penmark(&keys, &["verify", f]);
    assert_eq!(o.status.code(), Some(2));
    assert!(out(&o).contains("FILE CAMBIATO"));

    // New version linked to the old one.
    let v1 = d.path().join("cubo-officina.blend.v1.penmark");
    fs::rename(&side, &v1).unwrap();
    let o = penmark(
        &keys,
        &[
            "sign",
            f,
            "--author",
            "Alexander Puglisi",
            "--note",
            "seconda versione",
            "--previous",
            v1.to_str().unwrap(),
        ],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let o = penmark(&keys, &["verify", f]);
    assert_eq!(o.status.code(), Some(0));
    assert!(out(&o).contains("Versione precedente:"));
}

#[test]
fn verify_without_sidecar_is_an_error() {
    let d = tempfile::tempdir().unwrap();
    let file = d.path().join("solo.png");
    fs::write(&file, b"x").unwrap();
    let o = penmark(&d.path().join("k"), &["verify", file.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(4));
}
