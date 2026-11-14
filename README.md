```text
              ________
_______  _____\______ \_______  ____ ______
\_  __ \/  ___/|    |  \_  __ \/  _ \\____ \
 |  | \/\___ \ |    `   \  | \(  <_> )  |_> >
 |__|  /____  >_______  /__|   \____/|   __/
            \/        \/             |__|
```

# rsDrop

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Version 0.1.0](https://img.shields.io/badge/version-0.1.0-informational.svg)
![Rust edition 2024](https://img.shields.io/badge/rust-edition%202024-orange.svg)

rsDrop is a tiny, end-to-end encrypted, pastebin-style secrets sharing app.
It aims to be lightweight, fast, and ephemeral by keeping data only in memory.

> **Status:** work in progress. This project has not had an independent security audit.
> Please submit pull requests for any vulnerabilities you identify.

## Contents

- [Why](#why)
- [How it works](#how-it-works)
- [Features](#features)
- [Limitations](#limitations)
- [Quick start](#quick-start)
- [Building](#building)
- [Running](#running)
- [Docker](#docker)
- [Security notes](#security-notes)
- [Memory retention and deployment policy](#memory-retention-and-deployment-policy)
- [Project layout](#project-layout)
- [License](#license)

## Why

Most self-hosted paste platforms require excessive server resources and can be complicated to configure.

rsDrop is designed to implement secure, ephemeral, self-hosted secret sharing with compact, easy-to-audit code. The whole project aims to stay under 2000 lines of code.

## How it works

rsDrop uses end-to-end encryption (E2EE): content is encrypted with AES-GCM in your browser, so the server stores only ciphertext and a nonce.

The decryption secret lives in the URL fragment after `#`, for example:

```text
https://host/s/abcd123#BASE64_KEY
```

Browsers do not include this fragment in HTTP requests. With the unmodified application, the key stays in the browser and is not uploaded to the server.

When you send the URL over a reasonably secure messaging platform such as Discord or Slack, the recipient uses the link to fetch the ciphertext and nonce from the server. Decryption then happens entirely in their browser, using the key from the URL fragment.

## Features

- **End-to-end encrypted:** content is encrypted client-side before upload.
- **Pastebin-style sharing:** create a snippet and share a single link.
- **In-memory storage:** ciphertext is held in RAM; shares are never written to files.
- **Ephemeral by design:** shares expire after 60 minutes, and restarting the server loses all shares.
- **Lightweight footprint:** minimal surface area, quick to run and reset.

Good for quick hand-offs, temporary notes, throwaway snippets, password sharing, and sending commands, logs, or small text securely.

## Limitations

| Limit | Value |
| --- | --- |
| Size per share | 640 KB |
| Shares held at once | 100 |
| Share lifetime | 60 minutes |

- Not for large files or long-term storage.
- Data is lost on restart; treat everything as temporary.
- In-memory storage does not guarantee the data never reaches disk: host swap, hibernation, or core dumps may retain process memory.
- The server never needs the decryption key, but anyone with the full link can read the secret. Keep links private.

## Quick start

Build, generate a self-signed certificate, and run over HTTPS:

```sh
make
cd dist
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout key.pem -out cert.pem -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
./rsDrop --addr 127.0.0.1:8443 --cert cert.pem --key key.pem
```

Or the same thing, but requiring a token to create secrets (the token link is printed in the log at startup):

```sh
make
cd dist
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout key.pem -out cert.pem -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
./rsDrop --addr 127.0.0.1:8443 --cert cert.pem --key key.pem --create-token
```

Then open <https://localhost:8443>. Your browser will warn about the self-signed certificate; that is expected for local testing. For a real deployment, use a certificate from a trusted CA instead (see [Security notes](#security-notes)).

## Building

Prerequisites: Rust installed via [`rustup`](https://rustup.rs), with a recent stable toolchain (edition 2024).

| Command | Result |
| --- | --- |
| `make` | Builds `./dist` containing the `rsDrop` binary and the `web/` folder, ready to run or copy to a server (recommended) |
| `cargo build --release` | Binary at `target/release/rsDrop` (`target\release\rsDrop.exe` on Windows) |
| `make clean` | Removes `./dist` and the cargo build output |

## Running

The binary looks for `web/` in the current directory, so run it from inside `dist`:

```sh
cd dist && ./rsDrop --addr 127.0.0.1:8080
```

If you built with plain `cargo`, copy the binary next to the `web/` folder first.

### Options

| Flag | Description |
| --- | --- |
| `--addr <ip:port>` | Address to listen on (default `0.0.0.0:8080`) |
| `--cert <file>` / `--key <file>` | PEM certificate and private key; enables native TLS |
| `--create-token`, `-ct` | Require a token to create shares |

### TLS

Run with an existing TLS certificate and key (PEM):

```sh
rsDrop --addr 0.0.0.0:8443 --cert cert.pem --key key.pem
```

TLS is optional: without `--cert`/`--key` the server speaks plain HTTP, which is only suitable behind a TLS-terminating reverse proxy or for local testing.

### Create token

```sh
rsDrop --addr 127.0.0.1:8080 --create-token
```

- A random token is generated at startup and printed in the log. It changes on every restart.
- Hand it out as a link, `https://host/#CREATE_TOKEN`. The create page sends it in the `X-Create-Token` request header.
- API clients must use the same header; the former JSON `create_token` field is no longer accepted. Invalid tokens are rejected before the upload body is read.
- Viewing a share never needs the token.
- With the token enabled, the root page shows only "Create token required" unless it is opened with the token link.

## Docker

Build the image (optionally with a custom tag):

```sh
make docker
make docker IMAGE=rsdrop:1.0
```

Run it capped at 100 MB of memory:

```sh
docker run --rm -p 8080:8080 \
  --memory=100m --memory-swap=100m \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  rsdrop:latest --create-token
```

The image is built from `scratch` and holds only the static binary and the `web/` folder.

For native TLS, mount certificates and private keys read-only at runtime and pass their container paths with `--cert` and `--key`. Do not bake private keys into the image.

## Security notes

- **Run it over HTTPS only** (`--cert`/`--key`, or behind a TLS-terminating reverse proxy). Browsers refuse to run the encryption code on plain HTTP, and plain HTTP would let a network attacker replace it.
- **You must trust the host.** Encryption and decryption happen in the browser and the server receives only ciphertext and a nonce, but the server also delivers the JavaScript. A compromised host or delivery path can replace it with code that steals plaintext and keys. HTTPS is necessary but does not protect against a compromised server.
- **The link is as sensitive as the secret.** Anyone who obtains the full link within 60 minutes can read it.
- **No burn-after-read.** A link can be opened more than once until it expires.
- **Use `--create-token`** on any instance reachable by people you do not trust; without it anyone can fill the server.
- After viewing, the key is removed from the address bar and that history entry, so reloading the page needs the original link again.
- Expiration means the API stops serving a share after its 60-minute lifetime. A sweep removes expired shares roughly once a minute. Before releasing stored ciphertext and nonce buffers, it attempts a random overwrite and then zeroizes them. This does not erase all memory copies or revoke data already downloaded by recipients.

## Memory retention and deployment policy

**Intended threat model:** temporary sharing on a trusted host. rsDrop does not protect against host administrators, memory forensics, or compromised browsers or server-delivered JavaScript.

- Stored share buffers receive a best-effort random overwrite followed by optimization-resistant zeroization when dropped. Plaintext and decryption keys normally live only in browsers.
- This does not erase response or allocator copies, browser memory, swap, or dumps. Abrupt termination (`SIGKILL`, crashes, or power loss) can bypass cleanup. Guaranteed secure erasure is not provided.
- For sensitive deployments, disable process core dumps (`ulimit -c 0` or systemd `LimitCORE=0`) and review host crash collectors, which may have separate policies. Disable swap and hibernation or use appropriately managed encrypted swap, and restrict access to host memory and dumps. These are operator settings, not enforced by the application.
- The Docker example disables container swap by setting `--memory-swap` equal to `--memory` (requires host support). Add `--ulimit core=0:0` to disable container process core dumps. Verify the host's effective settings; no host policy has been verified by this project.

## Project layout

| Path | Purpose |
| --- | --- |
| `src/main.rs` | Server: routing, in-memory store, expiry, TLS |
| `src/tests.rs` | Unit tests (`cargo test`) |
| `web/index.html`, `web/create.js` | Create page |
| `web/retrieve.html`, `web/retrieve.js` | View page |
| `web/style.css` | Shared stylesheet |

Scripts and the stylesheet are served under `/static/`, so a strict Content-Security-Policy can forbid inline code.

## License

Released under the [MIT License](LICENSE).
