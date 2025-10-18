              ________                       
_______  _____\______ \_______  ____ ______  
\_  __ \/  ___/|    |  \_  __ \/  _ \\____ \ 
 |  | \/\___ \ |    `   \  | \(  <_> )  |_> >
 |__|  /____  >_______  /__|   \____/|   __/ 
            \/        \/             |__|      


rsDrop is a tiny, end‑to‑end encrypted, pastebin‑style sharing app.
It aims to be lightweight, fast and ephemeral by keeping data only in memory.

Why
Most selfhosted paste platforms require excessive server resources and setup times to run. rsDrop is designed to implent secure ephemeral selfhosted secret sharing on compact easy to audit code. With that said this is a work in progress please submit pull requests to any vulnerablites identifed. 

How it Works
rsDrop uses true end-to-end encryption (e2ee) with front end or client side AES encryption in your browser, so the server stores only ciphertext and a nonce. The decryption secret lives in the URL fragment after '#', for example https://host/p/abcd123#BASE64_KEY; browsers never send this fragment to servers, so the key is never logged or transmitted. Upon sending your url over a reasonably secure messaging platform such as discord or slack the decrypting user can use this url to fetch the ciphertext and nounce from the server, then this is decrypted in the browser using the key stored in the URL fragment which is never sent to the server. 

What it is
- End‑to‑end encrypted: content is encrypted client‑side before upload.
- Pastebin‑style sharing: create a snippet and share a single link.
- In‑memory storage: the server holds ciphertext in RAM only (no disk).
- Ephemeral by design: data expires by default and disappears on restart.
- Lightweight footprint: minimal surface area, quick to run and reset.

What it's good for
- Quick hand‑offs, temporary notes, throwaway snippets and password sharing
- Sharing commands, logs, or small text securely and quickly.

Limitations & notes
- RAM‑only: capacity is limited by memory; nothing is persisted to disk.
- Ephemeral: data is lost on restart; treat it as temporary by default.
- Trust model: the server never needs the decryption key; keep links private.
- Not for large files or long‑term storage.

**How To Compile**
- Prerequisites: install Rust via `rustup` and ensure a recent stable toolchain (Edition `2024`).
- Build debug: `cargo build`
- Build release (recommended): `cargo build --release`
- Binaries:
  - Linux/macOS: `target/release/rsDrop`
  - Windows: `target\release\rsDrop.exe`

**How To Run**
After complilation copy rsDrop from the release directory to the main directory with the web/ subfolder.
Then run it 
  - `rsDrop --addr 127.0.0.1:8080`
to run with existing TLS cert/key (PEM):
  - `rsDrop  --addr 0.0.0.0:8443 --cert cert.pem --key key.pem`

Notes
- Static pages are served from `web/index.html` (create) and `web/retrieve.html` (view).
- TLS is optional; without `--cert/--key`, the server runs over HTTP.

