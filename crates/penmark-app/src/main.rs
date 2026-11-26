//! PenMark desktop app. by Alexander Puglisi
//!
//! The window only talks to the commands below; there is no shell access,
//! no file system plugin and no network code.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(missing_docs)]

mod logic;

use logic::{KeyInfo, Settings, SignOutcome, VerifyOutcome};
use penmark_keystore::KeyStore;
use std::path::{Path, PathBuf};

/// `%LOCALAPPDATA%\PenMark`. Debug builds only: `PENMARK_HOME` points the app
/// at a throwaway folder, so trying it never touches the real key.
fn data_dir() -> Result<PathBuf, String> {
    #[cfg(debug_assertions)]
    if let Some(dir) = std::env::var_os("PENMARK_HOME") {
        return Ok(PathBuf::from(dir));
    }
    let base = std::env::var_os("LOCALAPPDATA")
        .ok_or_else(|| "Non trovo la cartella dei dati locali di Windows.".to_string())?;
    Ok(PathBuf::from(base).join("PenMark"))
}

fn store() -> Result<KeyStore, String> {
    Ok(KeyStore::at(data_dir()?.join("keys")))
}

fn settings_path() -> Result<PathBuf, String> {
    Ok(data_dir()?.join("settings.json"))
}

#[tauri::command]
fn key_info() -> Result<KeyInfo, String> {
    Ok(logic::key_info(&store()?))
}

#[tauri::command]
fn key_create() -> Result<KeyInfo, String> {
    logic::key_create(&store()?)
}

#[tauri::command]
fn get_settings() -> Result<Settings, String> {
    Ok(logic::load_settings(&settings_path()?))
}

#[tauri::command]
fn set_author(author: String) -> Result<Settings, String> {
    logic::save_author(&settings_path()?, &author)
}

#[tauri::command]
async fn sign_file(path: String, note: String) -> Result<SignOutcome, String> {
    let author = logic::load_settings(&settings_path()?).author;
    let ks = store()?;
    tauri::async_runtime::spawn_blocking(move || logic::sign(&ks, Path::new(&path), &author, &note))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn verify_file(path: String, trust: Vec<String>) -> Result<VerifyOutcome, String> {
    let ks = store()?;
    tauri::async_runtime::spawn_blocking(move || logic::check(&ks, Path::new(&path), &trust))
        .await
        .map_err(|e| e.to_string())?
}

fn main() {
    let result = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            key_info,
            key_create,
            get_settings,
            set_author,
            sign_file,
            verify_file
        ])
        .run(tauri::generate_context!());
    if let Err(e) = result {
        eprintln!("PenMark non è partito: {e}");
        std::process::exit(1);
    }
}
