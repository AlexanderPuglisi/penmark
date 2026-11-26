# Privacy

**Short version: PenMark collects no data about anyone.** It runs on your PC, it has no account, no analytics and no telemetry, and the developer receives nothing.

## What stays on your PC

- **Your signing key.** The private part is encrypted with your Windows account (DPAPI) and never leaves the PC. PenMark never uploads it.
- **Your archive.** The list of files you signed and their versions is kept in a local folder. Deleting that folder removes it.

## What goes to the people you send files to

A signature (inside the file, or in the `.penmark` file next to it) contains:

- the file name, size and SHA-256 fingerprint;
- the author name **you** type;
- your public key and its short id;
- the date and time from your PC;
- the fingerprint of the previous version and your note, if you add them.

You decide who receives a signed file. Do not put anything in the author name or the note that you would not want the recipient to read.

## Network

PenMark works fully offline and opens no network ports. A planned, optional feature will ask an RFC 3161 timestamp service to confirm the date of a signature. It will be off unless you turn it on, it will send only a fingerprint (never the file, never your key), and the service you choose has its own privacy policy.

## GDPR

PenMark does not process personal data on any server, so there is no data to access, correct or delete on the developer's side. Everything PenMark knows is in files on your own PC, under your control.

## Questions

Open an issue on [GitHub](https://github.com/AlexanderPuglisi/penmark/issues).

---

## In italiano

**In breve: PenMark non raccoglie dati di nessuno.** Funziona sul tuo PC, senza account, senza statistiche e senza invii automatici; lo sviluppatore non riceve niente.

- **Resta sul PC:** la tua chiave segreta, cifrata con il tuo account Windows (DPAPI), e l'archivio delle firme in una cartella locale.
- **Va a chi riceve il file:** nome, dimensione e impronta del file, il nome d'autore che scrivi tu, la tua chiave pubblica, la data del PC, ed eventualmente l'impronta della versione precedente e la tua nota. Non scrivere nel nome o nella nota cose che non vuoi far leggere.
- **Rete:** PenMark funziona senza internet e non apre porte. Una funzione futura, facoltativa e spenta di base, chiederà a un servizio di marca temporale (RFC 3161) di confermare la data: invierà solo un'impronta, mai il file o la chiave.
- **GDPR:** nessun dato personale viene trattato su server; tutto ciò che PenMark sa sta in file sul tuo PC, sotto il tuo controllo.
