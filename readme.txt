              ________                       
_______  _____\______ \_______  ____ ______  
\_  __ \/  ___/|    |  \_  __ \/  _ \\____ \ 
 |  | \/\___ \ |    `   \  | \(  <_> )  |_> >
 |__|  /____  >_______  /__|   \____/|   __/ 
            \/        \/             |__|      


rsDrop is a tiny, end‑to‑end encrypted, pastebin‑style sharing app.
It aims to be lightweight, fast and ephemeral by keeping data only in memory.

What it is
- End‑to‑end encrypted: content is encrypted client‑side before upload.
- Pastebin‑style sharing: create a snippet and share a single link.
- In‑memory storage: the server holds ciphertext in RAM only (no disk).
- Ephemeral by design: data expires by default and disappears on restart.
- Lightweight footprint: minimal surface area, quick to run and reset.

How it works (high level)
1) You create a note/snippet in the browser.
2) The browser encrypts it and sends only ciphertext to the server.
3) The server stores that ciphertext in memory for a short time.
4) Anyone with the share link fetches and decrypts it locally in the browser.

Good for
- Quick hand‑offs, temporary notes, throwaway snippets.
- Sharing commands, logs, or small text securely and quickly.

Limitations & notes
- RAM‑only: capacity is limited by memory; nothing is persisted to disk.
- Ephemeral: data is lost on restart; treat it as temporary by default.
- Trust model: the server never needs the decryption key; keep links private.
- Not for large files or long‑term storage.

Status
- Early, lightweight, and focused on simple, secure sharing.

**How To Compile**
- Prerequisites: install Rust via `rustup` and ensure a recent stable toolchain (Edition `2024`).
- Build debug: `cargo build`
- Build release (recommended): `cargo build --release`
- Binaries:
  - Linux/macOS: `target/release/rsDrop`
  - Windows: `target\release\rsDrop.exe`

**How To Run**
- Quick start (HTTP on default `0.0.0.0:8080`):
  - `cargo run --release`
- Choose address/port:
  - `cargo run --release -- --addr 127.0.0.1:8080`
- Run with existing TLS cert/key (PEM):
  - `cargo run --release -- --addr 0.0.0.0:8443 --cert cert.pem --key key.pem`
  - Then open `https://localhost:8443`
- Without TLS (default):
  - Open `http://localhost:8080`

Notes
- Static pages are served from `web/index.html` (create) and `web/retrieve.html` (view).
- TLS is optional; without `--cert/--key`, the server runs over HTTP.
