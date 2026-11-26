// PenMark — interfaccia. Parla solo con i comandi dell'app, niente rete.
"use strict";

const T = window.__TAURI__;
const invoke = T.core.invoke;
const $ = (id) => document.getElementById(id);

const state = { view: "sign", signPath: null, author: "", hasKey: false, recent: [] };

// ---------- utilità ----------
function show(id, on) { $(id).hidden = !on; }

function toast(msg, isError) {
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast" + (isError ? " error" : "");
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, isError ? 7000 : 3500);
}

function niceDate(rfc) {
  const d = new Date(rfc);
  if (isNaN(d)) return rfc;
  return d.toLocaleString("it-IT", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

function baseName(p) { return p.split(/[\\/]/).pop(); }

function setView(view) {
  state.view = view;
  for (const b of document.querySelectorAll(".nav-item")) {
    if (b.dataset.view === view) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  }
  show("view-sign", view === "sign");
  show("view-verify", view === "verify");
  show("view-key", view === "key");
}

// ---------- chiave e nome ----------
async function refreshKey() {
  const k = await invoke("key_info");
  state.hasKey = k.exists && !!k.id;
  $("key-id").textContent = k.id || "—";
  show("key-none", !state.hasKey);
  show("key-pub-wrap", state.hasKey);
  show("key-create", !k.exists);
  $("key-hex").textContent = k.public_hex || "";
  $("key-folder").textContent = "Cartella: " + k.folder;
  $("side-status").textContent = state.hasKey ? "Offline · chiave protetta" : "Offline · nessuna chiave";
}

async function refreshSettings() {
  const s = await invoke("get_settings");
  state.author = s.author || "";
  $("author-input").value = state.author;
  $("sign-author").textContent = state.author || "— scrivi il tuo nome in «La mia chiave»";
}

// ---------- firma ----------
function chooseForSign(path) {
  if (!path) return;
  state.signPath = path;
  $("sign-name").textContent = baseName(path);
  $("sign-path").textContent = path;
  $("sign-note").value = "";
  show("sign-empty", false);
  show("sign-chosen", true);
}

function resetSign() {
  state.signPath = null;
  show("sign-chosen", false);
  show("sign-empty", true);
}

async function doSign() {
  if (!state.signPath) return;
  if (!state.hasKey) { toast("Prima crea la tua chiave nella pagina «La mia chiave».", true); setView("key"); return; }
  if (!state.author) { toast("Prima scrivi il nome con cui firmi.", true); setView("key"); return; }
  const btn = $("sign-go");
  btn.disabled = true;
  btn.textContent = "Firmo…";
  try {
    const r = await invoke("sign_file", { path: state.signPath, note: $("sign-note").value });
    $("last-name").textContent = r.file_name;
    $("last-author").textContent = r.author;
    $("last-date").textContent = niceDate(r.signed_at);
    $("last-hash").textContent = r.sha256_short;
    $("last-hash").title = r.sha256;
    show("last-empty", false);
    show("last-body", true);
    show("last-pill", true);
    state.recent.unshift(r.file_name);
    renderRecent();
    toast("Firmato. Manda insieme il file e il suo .penmark.");
    resetSign();
  } catch (e) {
    toast(String(e), true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Firma il file";
  }
}

function renderRecent() {
  const ul = $("recent");
  ul.replaceChildren();
  const items = state.recent.slice(0, 6);
  if (items.length === 0) {
    const li = document.createElement("li");
    li.className = "recent-empty";
    li.textContent = "Ancora niente in questa sessione.";
    ul.append(li);
    return;
  }
  for (const name of items) {
    const li = document.createElement("li");
    const a = document.createElement("span"); a.textContent = name;
    const b = document.createElement("span"); b.textContent = "+ .penmark";
    li.append(a, b);
    ul.append(li);
  }
}

// ---------- verifica ----------
const ICONS = {
  valid: '<svg width="84" height="84" viewBox="0 0 96 96"><circle cx="48" cy="48" r="44" fill="rgba(143,240,198,0.10)" stroke="#8ff0c6" stroke-width="1.6"/><path d="M30 49l12 12 24-26" fill="none" stroke="#8ff0c6" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  changed: '<svg width="84" height="84" viewBox="0 0 96 96"><circle cx="48" cy="48" r="44" fill="rgba(255,92,170,0.10)" stroke="#ff9fcd" stroke-width="1.6"/><path d="M48 26v28" stroke="#ff9fcd" stroke-width="5" stroke-linecap="round"/><circle cx="48" cy="68" r="3.6" fill="#ff9fcd"/></svg>',
  unknown_key: '<svg width="84" height="84" viewBox="0 0 96 96"><circle cx="48" cy="48" r="44" fill="rgba(255,210,120,0.10)" stroke="#ffd98a" stroke-width="1.6"/><circle cx="48" cy="40" r="11" fill="none" stroke="#ffd98a" stroke-width="3"/><path d="M28 72c5-10 12-13 20-13s15 3 20 13" fill="none" stroke="#ffd98a" stroke-width="3" stroke-linecap="round"/></svg>',
  bad_signature: '<svg width="84" height="84" viewBox="0 0 96 96"><circle cx="48" cy="48" r="44" fill="rgba(255,90,110,0.10)" stroke="#ff8a9a" stroke-width="1.6"/><path d="M34 34l28 28M62 34L34 62" stroke="#ff8a9a" stroke-width="4.5" stroke-linecap="round"/></svg>',
};

async function doVerify(path) {
  if (!path) return;
  const trust = $("trust-key").value.trim();
  try {
    const r = await invoke("verify_file", { path, trust: trust ? [trust] : [] });
    renderResult(r);
  } catch (e) {
    show("result", false);
    toast(String(e), true);
  }
}

function renderResult(r) {
  const res = $("result");
  res.className = "result " + r.verdict;
  $("result-icon").innerHTML = ICONS[r.verdict] || "";
  const when = niceDate(r.signed_at);
  let title = "", sub = "";
  switch (r.verdict) {
    case "valid":
      title = "Firmato da " + r.author;
      sub = r.file_name + " · firmato il " + when + " · non è stato modificato";
      break;
    case "unknown_key":
      title = "Firma di una chiave che non conosci";
      sub = "Il file è integro, ma la chiave non è tra quelle di cui ti fidi. Il nome dichiarato è «" + r.author + "»: confronta il codice chiave con quello pubblicato dall'autore.";
      break;
    case "changed":
      title = "Firmato da " + r.author + ", ma modificato dopo";
      sub = r.file_name + " non è più il file firmato il " + when + ".";
      break;
    default:
      title = "Firma non valida";
      sub = "Il file .penmark è stato alterato o la firma è falsa: non fidarti di questo file.";
  }
  $("result-title").textContent = title;
  $("result-sub").textContent = sub;
  const meta = ["chiave " + r.key_id];
  if (r.verdict === "changed") meta.push("impronta attesa " + r.expected_short + " · trovata " + r.found_short);
  if (r.previous_short) meta.push("versione precedente " + r.previous_short);
  if (r.note) meta.push("nota: " + r.note);
  $("result-meta").textContent = r.verdict === "bad_signature" ? "" : meta.join("\n");
  show("result", true);
}

// ---------- eventi ----------
async function pick() {
  const p = await T.dialog.open({ multiple: false, directory: false, title: "Scegli un file" });
  return typeof p === "string" ? p : null;
}

function wire() {
  for (const b of document.querySelectorAll(".nav-item")) b.addEventListener("click", () => setView(b.dataset.view));
  $("sign-pick").addEventListener("click", async () => chooseForSign(await pick()));
  $("sign-change").addEventListener("click", async () => { const p = await pick(); if (p) chooseForSign(p); });
  $("sign-go").addEventListener("click", doSign);
  $("verify-pick").addEventListener("click", async () => doVerify(await pick()));
  $("key-create").addEventListener("click", async () => {
    try { await invoke("key_create"); await refreshKey(); toast("Chiave creata e protetta da Windows."); }
    catch (e) { toast(String(e), true); }
  });
  $("key-copy").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText($("key-hex").textContent); toast("Chiave pubblica copiata."); }
    catch { toast("Non riesco a copiare: seleziona il testo e usa Ctrl+C.", true); }
  });
  $("author-save").addEventListener("click", async () => {
    try { await invoke("set_author", { author: $("author-input").value }); await refreshSettings(); toast("Nome salvato."); }
    catch (e) { toast(String(e), true); }
  });

  // Trascina e rilascia: la finestra riceve i percorsi veri dei file.
  T.webview.getCurrentWebview().onDragDropEvent((ev) => {
    const p = ev.payload;
    const target = state.view === "verify" ? $("verify-drop") : $("sign-drop");
    if (p.type === "over" || p.type === "enter") target.classList.add("over");
    else target.classList.remove("over");
    if (p.type === "drop" && p.paths && p.paths.length) {
      if (state.view === "verify") doVerify(p.paths[0]);
      else { setView("sign"); chooseForSign(p.paths[0]); }
    }
  });
}

window.addEventListener("DOMContentLoaded", async () => {
  wire();
  try {
    await refreshKey();
    if (!state.hasKey) setView("key");
    await refreshSettings();
  } catch (e) {
    toast(String(e), true);
  }
});
