//! What the app does, without any window: easy to test.

use penmark_core::{
    PublicKey, Signed, Verdict, digest_file, now_utc_rfc3339, read_sidecar, sidecar_path, verify,
    write_sidecar,
};
use penmark_keystore::KeyStore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

const MAX_SETTINGS_BYTES: u64 = 16 * 1024;

/// The key as the "La mia chiave" page shows it.
#[derive(Debug, Serialize)]
pub struct KeyInfo {
    pub exists: bool,
    pub id: Option<String>,
    pub public_hex: Option<String>,
    pub folder: String,
}

/// Settings kept in `%LOCALAPPDATA%\PenMark\settings.json`.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    #[serde(default)]
    pub author: String,
}

/// Result of signing a file, for the "Appena firmato" card.
#[derive(Debug, Serialize)]
pub struct SignOutcome {
    pub file_name: String,
    pub size: u64,
    pub sha256: String,
    pub sha256_short: String,
    pub signed_at: String,
    pub author: String,
    pub key_id: String,
    pub sidecar: String,
}

/// Result of a check, for the "Verifica" page.
#[derive(Debug, Serialize)]
pub struct VerifyOutcome {
    /// `valid`, `unknown_key`, `changed` or `bad_signature`.
    pub verdict: &'static str,
    pub file: String,
    pub file_name: String,
    pub size: u64,
    pub author: String,
    pub key_id: String,
    pub signed_at: String,
    pub note: String,
    pub previous_short: Option<String>,
    pub expected_short: Option<String>,
    pub found_short: Option<String>,
}

pub fn key_info(ks: &KeyStore) -> KeyInfo {
    let public = ks.public().ok();
    KeyInfo {
        exists: ks.exists(),
        id: public.map(|p| p.id().to_string()),
        public_hex: public.map(|p| p.to_hex()),
        folder: ks.dir().display().to_string(),
    }
}

pub fn key_create(ks: &KeyStore) -> Result<KeyInfo, String> {
    ks.create().map_err(|e| it_keystore(&e))?;
    Ok(key_info(ks))
}

pub fn load_settings(path: &Path) -> Settings {
    let Ok(meta) = fs::metadata(path) else {
        return Settings::default();
    };
    if meta.len() > MAX_SETTINGS_BYTES {
        return Settings::default();
    }
    fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

pub fn save_author(path: &Path, author: &str) -> Result<Settings, String> {
    let author = author.trim();
    if author.is_empty() {
        return Err("Scrivi il nome con cui vuoi firmare.".into());
    }
    if author.len() > penmark_core::statement::MAX_AUTHOR || author.chars().any(char::is_control) {
        return Err("Il nome è troppo lungo o contiene caratteri non validi.".into());
    }
    let settings = Settings {
        author: author.to_string(),
    };
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("Non riesco a salvare: {e}"))?;
    }
    let json = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    fs::write(path, json).map_err(|e| format!("Non riesco a salvare: {e}"))?;
    Ok(settings)
}

pub fn sign(ks: &KeyStore, file: &Path, author: &str, note: &str) -> Result<SignOutcome, String> {
    if author.trim().is_empty() {
        return Err("Prima scrivi il tuo nome nella pagina «La mia chiave».".into());
    }
    if is_sidecar(file) {
        return Err("Questo è già un file di firma .penmark: scegli il file originale.".into());
    }
    let key = ks.load().map_err(|e| it_keystore(&e))?;
    let signed_at = now_utc_rfc3339().map_err(|e| e.to_string())?;
    let signed = Signed::sign_file(file, author.trim(), &key, signed_at, None, note.trim())
        .map_err(|e| format!("Non riesco a firmare il file: {e}"))?;
    let out = write_sidecar(file, &signed).map_err(|e| match e {
        penmark_core::Error::Io(io) if io.kind() == ErrorKind::AlreadyExists => format!(
            "Esiste già {}. PenMark non lo sovrascrive mai: spostalo o rinominalo, poi firma di nuovo.",
            sidecar_path(file).display()
        ),
        other => format!("Non riesco a scrivere la firma: {other}"),
    })?;
    let st = &signed.statement;
    Ok(SignOutcome {
        file_name: st.file_name.clone(),
        size: st.file_size,
        sha256: st.file_sha256.to_hex(),
        sha256_short: st.file_sha256.short(),
        signed_at: st.signed_at.clone(),
        author: st.author.clone(),
        key_id: st.public_key.id().to_string(),
        sidecar: out.display().to_string(),
    })
}

pub fn check(ks: &KeyStore, path: &Path, trust: &[String]) -> Result<VerifyOutcome, String> {
    // Accept either the file or its .penmark.
    let (file, side) = if is_sidecar(path) {
        (strip_sidecar(path), path.to_path_buf())
    } else {
        (path.to_path_buf(), sidecar_path(path))
    };
    if !side.exists() {
        return Err(format!(
            "Accanto a questo file non c'è {}: senza firma non c'è niente da controllare.",
            file_label(&side)
        ));
    }
    if !file.exists() {
        return Err(format!(
            "Manca il file firmato {}: mettilo nella stessa cartella del .penmark.",
            file_label(&file)
        ));
    }
    let signed = read_sidecar(&side).map_err(|e| format!("Il file .penmark non è valido: {e}"))?;
    let measured = digest_file(&file).map_err(|e| format!("Non riesco a leggere il file: {e}"))?;
    let mut trusted: Vec<PublicKey> = trust
        .iter()
        .filter(|t| !t.trim().is_empty())
        .map(|t| PublicKey::from_hex(t.trim()))
        .collect::<Result<_, _>>()
        .map_err(|_| "La chiave pubblica incollata non è valida.".to_string())?;
    if let Ok(own) = ks.public() {
        trusted.push(own);
    }
    let verdict = verify(&signed, &measured, &trusted);
    let st = &signed.statement;
    let (name, expected, found) = match verdict {
        Verdict::Valid => ("valid", None, None),
        Verdict::UnknownKey => ("unknown_key", None, None),
        Verdict::FileChanged { expected, found } => {
            ("changed", Some(expected.short()), Some(found.short()))
        }
        Verdict::BadSignature => ("bad_signature", None, None),
    };
    Ok(VerifyOutcome {
        verdict: name,
        file: file.display().to_string(),
        file_name: file_label(&file),
        size: st.file_size,
        author: st.author.clone(),
        key_id: st.public_key.id().to_string(),
        signed_at: st.signed_at.clone(),
        note: st.note.clone(),
        previous_short: st.previous_sha256.map(|d| d.short()),
        expected_short: expected,
        found_short: found,
    })
}

fn is_sidecar(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("penmark"))
}

fn strip_sidecar(path: &Path) -> PathBuf {
    path.with_extension("")
}

fn file_label(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn it_keystore(e: &penmark_keystore::KeyStoreError) -> String {
    use penmark_keystore::KeyStoreError as K;
    match e {
        K::AlreadyExists(_) => "Hai già una chiave: PenMark non la sostituisce mai.".into(),
        K::NotFound(_) => "Non hai ancora una chiave: creala nella pagina «La mia chiave».".into(),
        K::Locked(_) => {
            "Windows non sblocca la chiave: funziona solo con l'account che l'ha creata.".into()
        }
        K::Corrupt(why) => format!("La chiave salvata è danneggiata ({why}). Non l'ho toccata."),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, KeyStore, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let ks = KeyStore::at(d.path().join("keys"));
        let file = d.path().join("officina-scena-03.png");
        fs::write(&file, b"png bytes").unwrap();
        (d, ks, file)
    }

    #[test]
    fn sign_needs_key_and_author() {
        let (_d, ks, file) = setup();
        assert!(sign(&ks, &file, "", "").is_err());
        assert!(sign(&ks, &file, "Alexander Puglisi", "").is_err());
        key_create(&ks).unwrap();
        let out = sign(&ks, &file, "Alexander Puglisi", "").unwrap();
        assert!(out.sidecar.ends_with("officina-scena-03.png.penmark"));
        assert_eq!(out.author, "Alexander Puglisi");
    }

    #[test]
    fn never_overwrites_a_signature() {
        let (_d, ks, file) = setup();
        key_create(&ks).unwrap();
        sign(&ks, &file, "Alexander Puglisi", "").unwrap();
        let side = sidecar_path(&file);
        let before = fs::read(&side).unwrap();
        let err = sign(&ks, &file, "Alexander Puglisi", "").unwrap_err();
        assert!(err.contains("non lo sovrascrive"));
        assert_eq!(fs::read(&side).unwrap(), before);
    }

    #[test]
    fn check_from_file_or_sidecar() {
        let (_d, ks, file) = setup();
        key_create(&ks).unwrap();
        sign(&ks, &file, "Alexander Puglisi", "prima").unwrap();
        assert_eq!(check(&ks, &file, &[]).unwrap().verdict, "valid");
        let side = sidecar_path(&file);
        let r = check(&ks, &side, &[]).unwrap();
        assert_eq!(r.verdict, "valid");
        assert_eq!(r.note, "prima");
    }

    #[test]
    fn check_reports_each_case() {
        let (d, ks, file) = setup();
        key_create(&ks).unwrap();
        sign(&ks, &file, "Alexander Puglisi", "").unwrap();

        let stranger = KeyStore::at(d.path().join("other"));
        assert_eq!(check(&stranger, &file, &[]).unwrap().verdict, "unknown_key");
        let alex = key_info(&ks).public_hex.unwrap();
        assert_eq!(check(&stranger, &file, &[alex]).unwrap().verdict, "valid");
        assert!(check(&stranger, &file, &["zz".into()]).is_err());

        fs::write(&file, b"png bytes, edited").unwrap();
        let r = check(&ks, &file, &[]).unwrap();
        assert_eq!(r.verdict, "changed");
        assert!(r.expected_short.is_some() && r.found_short.is_some());

        let side = sidecar_path(&file);
        let text = fs::read_to_string(&side)
            .unwrap()
            .replace("Alexander", "Mallory");
        fs::write(&side, text).unwrap();
        assert_eq!(check(&ks, &file, &[]).unwrap().verdict, "bad_signature");
    }

    #[test]
    fn check_without_signature_or_file() {
        let (_d, ks, file) = setup();
        assert!(check(&ks, &file, &[]).unwrap_err().contains("senza firma"));
        let lonely = file.with_file_name("assente.png.penmark");
        fs::write(&lonely, "{}").unwrap();
        assert!(
            check(&ks, &lonely, &[])
                .unwrap_err()
                .contains("Manca il file")
        );
    }

    #[test]
    fn refuses_to_sign_a_penmark_file() {
        let (_d, ks, file) = setup();
        key_create(&ks).unwrap();
        sign(&ks, &file, "Alexander Puglisi", "").unwrap();
        let side = sidecar_path(&file);
        assert!(sign(&ks, &side, "Alexander Puglisi", "").is_err());
    }

    #[test]
    fn settings_roundtrip_and_validation() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("PenMark").join("settings.json");
        assert_eq!(load_settings(&p), Settings::default());
        assert!(save_author(&p, "   ").is_err());
        assert!(save_author(&p, "a\u{7}b").is_err());
        save_author(&p, " Alexander Puglisi ").unwrap();
        assert_eq!(load_settings(&p).author, "Alexander Puglisi");
        fs::write(&p, "not json").unwrap();
        assert_eq!(load_settings(&p), Settings::default());
    }

    #[test]
    fn key_create_twice_is_refused() {
        let (_d, ks, _) = setup();
        let info = key_create(&ks).unwrap();
        assert!(info.exists && info.id.is_some());
        assert!(key_create(&ks).unwrap_err().contains("già una chiave"));
    }
}
