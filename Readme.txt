              ________                       
_______  _____\______ \_______  ____ ______  
\_  __ \/  ___/|    |  \_  __ \/  _ \\____ \ 
 |  | \/\___ \ |    `   \  | \(  <_> )  |_> >
 |__|  /____  >_______  /__|   \____/|   __/ 
            \/        \/             |__|      

rsDrop is a tiny, end-to-end encrypted, pastebin-style sharing app.
It aims to be lightweight, fast, and ephemeral by keeping data only in memory.

Why  
Most self-hosted paste platforms require excessive server resources and can be complicated to configure.  
rsDrop is designed to implement secure, ephemeral, self-hosted secret sharing with compact, easy-to-audit code.  
That said, this is a work in progress—please submit pull requests for any vulnerabilities identified.

How it Works  
rsDrop uses true end-to-end encryption (E2EE) with front-end (client-side) AES encryption in your browser, so the server stores only ciphertext and a nonce.  
The decryption secret lives in the URL fragment after '#', for example:  
`https://host/p/abcd123#BASE64_KEY`  
Browsers do not include this fragment in HTTP requests. With the unmodified application, the key stays in the browser and is not uploaded to the server.  

When you send your URL over a reasonably secure messaging platform such as Discord or Slack, the recipient can use the link to fetch the ciphertext and nonce from the server.  
Decryption then occurs entirely in their browser using the key stored in the URL fragment, which is never sent to the server.

What it is  
- End-to-end encrypted: content is encrypted client-side before upload.  
- Pastebin-style sharing: create a snippet and share a single link.  
- In-memory storage: the application stores ciphertext in RAM, without writing shares to files.  
- Ephemeral by design: shares expire after 60 minutes; restarting the server loses all shares.  
- Lightweight footprint: minimal surface area, quick to run and reset.

What it’s good for  
- Quick hand-offs, temporary notes, throwaway snippets, and password sharing.  
- Sharing commands, logs, or small text securely and quickly.

Limitations & Notes  
- In-memory storage is not guaranteed disk avoidance: host swap, hibernation, or core dumps may retain process memory.  
- Ephemeral: data is lost on restart; treat it as temporary by default.  
- Trust model: the server never needs the decryption key; keep links private.  
- Not for large files or long-term storage.  
- Limits: 640 KB per share, 100 shares on the server at once, 60 minute lifetime.

**Security Notes**  
- Run it over HTTPS only (`--cert/--key`, or behind a TLS-terminating reverse proxy). Browsers refuse to run the encryption code on plain HTTP, and plain HTTP would let a network attacker replace it.  
- With the unmodified application, encryption/decryption happens in the browser and the server receives only ciphertext and a nonce. The server also delivers the JavaScript: a compromised host or delivery path can replace it with code that steals plaintext and keys. HTTPS is necessary but does not protect against a compromised server; trust the host and the code it serves.  
- Anyone who obtains the full link within 60 minutes can read the secret. The link is as sensitive as the secret itself.  
- A link can be opened more than once until it expires; there is no burn-after-read.  
- Use `--create-token` on any instance reachable by people you do not trust; without it anyone can fill the server.  
- After viewing, the key is removed from the address bar and that history entry, so reloading the page needs the original link again.  
- Expiration means the API stops serving a share after its 60-minute lifetime. Cleanup removes expired shares on a roughly one-minute sweep. Before releasing stored ciphertext and nonce buffers, it attempts a random overwrite and then zeroizes them. This does not erase all memory copies or revoke data already downloaded by recipients.
- This project has not had an independent security audit.

**Memory retention and deployment policy**
- Intended threat model: temporary sharing on a trusted host, not protection against host administrators, memory forensics, or compromised browsers/server-delivered JavaScript.
- Stored share buffers receive a best-effort random overwrite followed by optimization-resistant zeroization when dropped. Plaintext and decryption keys normally live only in browsers. This does not erase response/allocator copies, browser memory, swap, or dumps. Abrupt termination (SIGKILL, crashes, or power loss) can bypass cleanup. Guaranteed secure erasure is not provided.
- For sensitive deployments, disable process core dumps (`ulimit -c 0` or systemd `LimitCORE=0`) and review host crash collectors, which may have separate policies. Disable swap/hibernation or use appropriately managed encrypted swap; restrict access to host memory and dumps. These are operator settings, not enforced by the application.
- The Docker example disables container swap by setting --memory-swap equal to --memory (requires host support). Add --ulimit core=0:0 to disable container process core dumps. Verify the host's effective settings; no host policy has been verified by this project.

**How To Compile**  
- Prerequisites: install Rust via `rustup` and ensure a recent stable toolchain (Edition `2024`).  
- Build (recommended): `make`  
  This produces `./dist` containing the `rsDrop` binary and the `web/` folder, ready to run or copy to a server.  
- Without make: `cargo build --release` (binary at `target/release/rsDrop`, or `target\release\rsDrop.exe` on Windows)  
- Clean up: `make clean`

**How To Run**  
Run from inside `dist` (the binary looks for `web/` in the current directory):  
  - `cd dist && ./rsDrop --addr 127.0.0.1:8080`  
If you built with plain cargo instead, copy the binary next to the `web/` folder first.  

To run with an existing TLS certificate/key (PEM):  
  - `rsDrop --addr 0.0.0.0:8443 --cert cert.pem --key key.pem`

To require a create token for creating pastes:  
  - `rsDrop --addr 127.0.0.1:8080 --create-token` (or `-ct`)  
A random token is generated at startup and printed in the log. Hand it out as a link,  
`https://host/#CREATE_TOKEN`, and the create page sends it in the `X-Create-Token` request header. API clients must also use this header; the former JSON `create_token` field is no longer accepted for authentication. Invalid tokens are rejected before the upload body is read.  
Viewing a paste never needs the token. The token changes on every restart.  
With the token enabled, the root page shows only "Create token required" unless it is opened with the token link.

**Docker**  
- Build the image: `make docker` (optional tag: `make docker IMAGE=rsdrop:1.0`)  
- Run it capped at 100 MB of memory:  
  `docker run --rm -p 8080:8080 --memory=100m --memory-swap=100m --read-only --cap-drop=ALL rsdrop:latest --create-token`  
The image is built from `scratch` and holds only the static binary and the `web/` folder.
For native TLS, mount certificates and private keys read-only at runtime and pass their container paths with `--cert` and `--key`. Do not bake private keys into the image.

Notes  
- Static pages are served from `web/index.html` (create) and `web/retrieve.html` (view).  
- Their scripts and the shared stylesheet live in `web/*.js` and `web/style.css`, served under `/static/`, so a strict Content-Security-Policy can forbid inline code.  
- TLS is optional; without `--cert/--key`, the server runs over HTTP.
