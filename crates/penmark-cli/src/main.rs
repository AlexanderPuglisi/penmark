//! `penmark`: create your key, sign files and verify them from the terminal.
//!
//! Exit codes of `penmark verify`:
//! 0 valid · 1 unknown key · 2 file changed · 3 forged signature · 4 error.

use clap::{Parser, Subcommand};
use penmark_core::{
    PublicKey, Signed, Verdict, digest_file, now_utc_rfc3339, read_sidecar, sidecar_path, verify,
};
use penmark_keystore::KeyStore;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// PenMark — firma quello che crei e dimostra che è tuo. by Alexander Puglisi
#[derive(Parser)]
#[command(name = "penmark", version, about)]
struct Cli {
    /// Cartella della chiave (di solito %LOCALAPPDATA%\PenMark\keys).
    #[arg(long, global = true, value_name = "CARTELLA")]
    keys: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Gestisce la tua chiave per firmare.
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Firma un file e scrive accanto <file>.penmark.
    Sign {
        /// Il file da firmare.
        file: PathBuf,
        /// Il nome con cui firmi.
        #[arg(long)]
        author: String,
        /// Una nota facoltativa, per esempio cosa è cambiato.
        #[arg(long, default_value = "")]
        note: String,
        /// Il .penmark della versione precedente, per collegare le versioni.
        #[arg(long, value_name = "FILE.penmark")]
        previous: Option<PathBuf>,
    },
    /// Controlla un file e la sua firma.
    Verify {
        /// Il file ricevuto.
        file: PathBuf,
        /// Il .penmark da usare (di solito <file>.penmark).
        #[arg(long, value_name = "FILE.penmark")]
        sidecar: Option<PathBuf>,
        /// Chiave pubblica di cui ti fidi, in esadecimale. Ripetibile.
        #[arg(long, value_name = "CHIAVE")]
        trust: Vec<String>,
    },
}

#[derive(Subcommand)]
enum KeyAction {
    /// Crea la tua chiave (una volta sola; non sovrascrive mai).
    Create,
    /// Mostra la tua chiave pubblica, da condividere.
    Show,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("Errore: {msg}");
            ExitCode::from(4)
        }
    }
}

fn store(cli_keys: &Option<PathBuf>) -> Result<KeyStore, String> {
    match cli_keys {
        Some(dir) => Ok(KeyStore::at(dir)),
        None => KeyStore::default_location().map_err(|e| e.to_string()),
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    let ks = store(&cli.keys)?;
    match cli.command {
        Command::Key { action } => match action {
            KeyAction::Create => {
                let public = ks.create().map_err(|e| e.to_string())?;
                println!("Chiave creata e protetta da Windows.");
                print_public(&ks, &public);
                println!();
                println!("Fai una copia di sicurezza della cartella e pubblica la chiave pubblica");
                println!(
                    "dove ti trovano (sito, GitHub): chi riceve i tuoi file la confronta con questa."
                );
            }
            KeyAction::Show => {
                let public = ks.public().map_err(|e| e.to_string())?;
                print_public(&ks, &public);
            }
        },
        Command::Sign {
            file,
            author,
            note,
            previous,
        } => sign(&ks, &file, &author, &note, previous.as_deref())?,
        Command::Verify {
            file,
            sidecar,
            trust,
        } => return verify_cmd(&ks, &file, sidecar, &trust),
    }
    Ok(ExitCode::SUCCESS)
}

fn print_public(ks: &KeyStore, public: &PublicKey) {
    println!("Codice chiave:   {}", public.id());
    println!("Chiave pubblica: {}", public.to_hex());
    println!("Cartella:        {}", ks.dir().display());
}

fn sign(
    ks: &KeyStore,
    file: &Path,
    author: &str,
    note: &str,
    previous: Option<&Path>,
) -> Result<(), String> {
    let key = ks.load().map_err(|e| e.to_string())?;
    let previous_sha256 = match previous {
        None => None,
        Some(p) => {
            let prev = read_sidecar(p).map_err(|e| format!("{}: {e}", p.display()))?;
            if !prev.signature_is_valid() {
                return Err(format!("{}: la firma precedente non è valida", p.display()));
            }
            if prev.statement.public_key != key.public() {
                return Err(format!(
                    "{}: la versione precedente è firmata con un'altra chiave",
                    p.display()
                ));
            }
            Some(prev.statement.file_sha256)
        }
    };
    let signed_at = now_utc_rfc3339().map_err(|e| e.to_string())?;
    let signed = Signed::sign_file(file, author, &key, signed_at, previous_sha256, note)
        .map_err(|e| format!("{}: {e}", file.display()))?;
    let out = sidecar_path(file);
    let json = signed.to_json().map_err(|e| e.to_string())?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&out)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                format!(
                    "{} esiste già e non lo sovrascrivo. Spostalo o rinominalo; \
                     per una nuova versione passa il vecchio con --previous.",
                    out.display()
                )
            } else {
                format!("{}: {e}", out.display())
            }
        })?;
    f.write_all(json.as_bytes())
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("{}: {e}", out.display()))?;
    let st = &signed.statement;
    println!("Firmato: {}", st.file_name);
    println!("Autore:   {}", st.author);
    println!("Impronta: {}", st.file_sha256);
    println!("Data:     {} (ora del PC)", st.signed_at);
    println!("Chiave:   {}", st.public_key.id());
    if let Some(p) = st.previous_sha256 {
        println!("Versione precedente: {}", p.short());
    }
    println!("Firma scritta in {}", out.display());
    println!("Manda insieme il file e il suo .penmark.");
    Ok(())
}

fn verify_cmd(
    ks: &KeyStore,
    file: &Path,
    sidecar: Option<PathBuf>,
    trust: &[String],
) -> Result<ExitCode, String> {
    let side = sidecar.unwrap_or_else(|| sidecar_path(file));
    let signed = read_sidecar(&side).map_err(|e| format!("{}: {e}", side.display()))?;
    let measured = digest_file(file).map_err(|e| format!("{}: {e}", file.display()))?;
    let mut trusted = Vec::new();
    for t in trust {
        trusted.push(PublicKey::from_hex(t.trim()).map_err(|e| format!("--trust: {e}"))?);
    }
    // Your own key, if this PC has one, is always trusted.
    if let Ok(own) = ks.public() {
        trusted.push(own);
    }
    let st = &signed.statement;
    let verdict = verify(&signed, &measured, &trusted);
    let code = match verdict {
        Verdict::Valid => {
            println!("FIRMA VALIDA");
            println!("Il file è identico a quello firmato e la chiave è una di cui ti fidi.");
            0
        }
        Verdict::UnknownKey => {
            println!("FIRMA DI UNA CHIAVE SCONOSCIUTA");
            println!("Il file è integro, ma la chiave non è tra quelle di cui ti fidi.");
            println!("Il nome scritto nella firma lo può mettere chiunque: confronta il codice");
            println!("chiave qui sotto con quello pubblicato dall'autore.");
            1
        }
        Verdict::FileChanged { expected, found } => {
            println!("FILE CAMBIATO");
            println!("La firma è vera, ma il file non è più quello firmato.");
            println!("Impronta attesa:  {expected}");
            println!("Impronta trovata: {found}");
            2
        }
        Verdict::BadSignature => {
            println!("FIRMA NON VALIDA");
            println!("Il file .penmark è stato alterato o la firma è falsa: non fidarti.");
            return Ok(ExitCode::from(3));
        }
    };
    println!();
    println!("Autore dichiarato: {}", st.author);
    println!("Codice chiave:     {}", st.public_key.id());
    println!(
        "Firmato il:        {} (ora del PC di chi firma)",
        st.signed_at
    );
    println!(
        "File firmato:      {} ({} byte)",
        st.file_name, st.file_size
    );
    if let Some(p) = st.previous_sha256 {
        println!("Versione precedente: {}", p.short());
    }
    if !st.note.is_empty() {
        println!("Nota: {}", st.note);
    }
    Ok(ExitCode::from(code))
}
