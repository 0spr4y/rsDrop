use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Json, Path, Request, State},
    http::{HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use axum_server::{
    Handle,
    accept::Accept,
    tls_rustls::{RustlsAcceptor, RustlsConfig},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as base64_engine, URL_SAFE_NO_PAD},
};
use clap::Parser;
use rand::{Rng, RngCore, distributions::Alphanumeric};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    future::Future,
    io,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::{
    net::TcpStream,
    sync::{RwLock, Semaphore},
};
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use zeroize::Zeroize;

#[cfg(test)]
mod tests;

// --- Configuration Constants ---
const MAX_ENCRYPTED_SIZE: usize = 640 * 1024; // 640 KiB limit (encrypted data + nonce)
const MAX_REQUEST_BODY_SIZE: usize = 1024 * 1024; // 1 MiB: fits a max-size share once base64/JSON encoded
// Uploads buffered at once; each holds up to ~2 MiB while it is read and decoded, so this bounds peak memory.
const MAX_CONCURRENT_CREATES: usize = 8;
const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(10); // How long a new HTTPS-port connection may stay silent
const CREATE_TIMEOUT: Duration = Duration::from_secs(30); // A stalled upload cannot hold a slot for longer
const MAX_SHARE_COUNT: usize = 100; // Maximum number of shares held on the server at once
const CREATE_TOKEN_BYTE_LENGTH: usize = 32; // Random bytes behind the create token
const SHARE_ID_LENGTH: usize = 22; // Length of the random URL-safe ID
const NONCE_LENGTH: usize = 12; // Standard AES-GCM nonce length
const EXPIRY_DURATION: Duration = Duration::from_secs(60 * 60); // Shares live for 60 minutes
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60); // Sweep every minute; dropped share buffers are overwritten before release
// Replaced in index.html with "true"/"false" so the page knows whether to show only "Create token required".
const TOKEN_REQUIRED_PLACEHOLDER: &str = "{{TOKEN_REQUIRED}}";
const WEB_DIR: &str = "./web";
// Sent with every response, including errors and 404s.
const SECURITY_HEADERS: &[(&str, &str)] = &[
    // Everything is same-origin: no inline script/style, no framing, no third-party loads.
    (
        "content-security-policy",
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    ),
    ("x-frame-options", "DENY"),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    ("cache-control", "no-store"),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
];
// Static assets served under /static/: (file name in WEB_DIR, content type).
const STATIC_ASSETS: &[(&str, &str)] = &[
    ("create.js", "text/javascript; charset=utf-8"),
    ("retrieve.js", "text/javascript; charset=utf-8"),
    ("style.css", "text/css; charset=utf-8"),
];

// --- Command Line Arguments ---
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    cert: Option<PathBuf>,
    #[arg(long)]
    key: Option<PathBuf>,
    #[arg(long, default_value = "0.0.0.0:8080")]
    addr: SocketAddr,
    /// Require a create token to create shares (also accepted as -ct).
    /// A random token is generated and printed in the log at startup.
    #[arg(long = "create-token")]
    create_token: bool,
}

// --- Data Structures ---
struct EncryptedShare {
    /// Nonce followed by ciphertext, exactly as served. Responses share this one
    /// buffer instead of copying it, so downloads cannot multiply memory use.
    data: Bytes,
    timestamp: Instant,
}

/// Owns a share's bytes; dropped once the store and every in-flight response have released them.
struct WipeOnDrop(Vec<u8>);

impl AsRef<[u8]> for WipeOnDrop {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for WipeOnDrop {
    fn drop(&mut self) {
        // Best-effort random pass, followed by optimization-resistant zeroization.
        // Do not panic during cleanup if the random source fails.
        let _ = rand::thread_rng().try_fill_bytes(&mut self.0);
        self.0.zeroize();
    }
}

#[derive(Deserialize)]
struct CreateRequest {
    encrypted_data_b64: String,
    nonce_b64: String,
}

#[derive(Serialize)]
struct CreateResponse {
    share_id: String,
}

struct AppData {
    shares: RwLock<HashMap<String, EncryptedShare>>,
    create_slots: Semaphore,
    /// When set, POST /create must supply this token.
    create_token: Option<String>,
    /// True when this process terminates TLS itself (--cert/--key).
    tls_enabled: bool,
}

type SharedState = Arc<AppData>;
type ApiError = (StatusCode, &'static str);

fn fatal(message: String) -> ! {
    error!("{}", message);
    std::process::exit(1)
}

// --- Main Function ---
#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::filter::LevelFilter::INFO)
        .init();

    // Clap short flags are single characters, so map the `-ct` alias by hand.
    let args = Args::parse_from(std::env::args().map(|arg| match arg.as_str() {
        "-ct" => "--create-token".to_string(),
        _ => arg,
    }));

    // rustls needs its crypto provider chosen once per process, before any TLS config is built.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        fatal("Failed to install the TLS crypto provider.".into());
    }

    let tls_config = match (&args.cert, &args.key) {
        (Some(cert), Some(key)) => {
            info!("TLS enabled. Loading cert: {:?}, key: {:?}", cert, key);
            match RustlsConfig::from_pem_file(cert, key).await {
                Ok(config) => Some(config),
                Err(e) => fatal(format!("Failed to load TLS certificate/key: {e}")),
            }
        }
        (None, None) => {
            warn!(
                "TLS not configured: running in HTTP mode. Traffic is unencrypted and potentially tamperable. Provide --cert and --key to enable HTTPS."
            );
            None
        }
        _ => fatal("Both --cert and --key must be provided for TLS, or neither for HTTP.".into()),
    };
    let protocol = if tls_config.is_some() {
        "https"
    } else {
        "http"
    };

    let create_token = args.create_token.then(generate_create_token);
    match &create_token {
        Some(token) => {
            info!("Create token enabled. Shares can only be created with this token.");
            info!("Create token: {}", token);
            info!(
                "Share it as a link: {}://{}/#{}",
                protocol, args.addr, token
            );
        }
        None => warn!(
            "Create token disabled: anyone who can reach the server can create shares. With no rate limiting, {} small requests fill every slot and block all new shares for up to {} minutes (denial of service). Use --create-token (-ct) to restrict who can create shares.",
            MAX_SHARE_COUNT,
            EXPIRY_DURATION.as_secs() / 60
        ),
    }

    let shared_state: SharedState = Arc::new(AppData {
        shares: RwLock::new(HashMap::new()),
        create_slots: Semaphore::new(MAX_CONCURRENT_CREATES),
        create_token,
        tls_enabled: tls_config.is_some(),
    });
    tokio::spawn(delete_expired_shares(shared_state.clone()));

    let app = Router::new()
        .route("/", get(handle_index))
        .route(
            "/create",
            post(handle_create_encrypted).layer(middleware::from_fn_with_state(
                shared_state.clone(),
                limit_concurrent_creates,
            )),
        )
        .route("/s/*path", get(handle_retrieve_page))
        .route("/api/share/:share_id", get(handle_get_encrypted_share))
        .route("/static/:file", get(handle_static_asset))
        .layer(middleware::from_fn_with_state(
            shared_state.clone(),
            add_security_headers,
        ))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_SIZE))
        .with_state(shared_state);

    info!("Listening on {}", args.addr);
    let result = if let Some(tls_config) = tls_config {
        let handle = Handle::new();
        let shutdown_handle = handle.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            shutdown_handle.shutdown();
        });
        axum_server::bind(args.addr)
            .acceptor(RustlsAcceptor::new(tls_config).acceptor(RedirectPlainHttp))
            .handle(handle)
            .serve(app.into_make_service())
            .await
    } else {
        match tokio::net::TcpListener::bind(args.addr).await {
            Ok(listener) => {
                axum::serve(listener, app)
                    .with_graceful_shutdown(shutdown_signal())
                    .await
            }
            Err(e) => Err(e),
        }
    };
    if let Err(e) = result {
        fatal(format!("Server failed: {e}"));
    }
    info!("Server shutting down.");
}

/// Runs before the TLS handshake: a client that speaks plain HTTP to the HTTPS port
/// is redirected to HTTPS instead of getting a connection error.
#[derive(Clone)]
struct RedirectPlainHttp;

impl<S: Send + 'static> Accept<TcpStream, S> for RedirectPlainHttp {
    type Stream = TcpStream;
    type Service = S;
    type Future = Pin<Box<dyn Future<Output = io::Result<(TcpStream, S)>> + Send>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        Box::pin(async move {
            let mut head = [0u8; 2048];
            let length = tokio::time::timeout(FIRST_BYTE_TIMEOUT, stream.peek(&mut head)).await??;
            // Every TLS connection opens with a handshake record, whose first byte is 0x16.
            if head[..length].first() == Some(&0x16) {
                return Ok((stream, service));
            }
            let response = match https_location(&head[..length]) {
                Some(location) => format!(
                    "HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                ),
                None => {
                    "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .into()
                }
            };
            // Consume the request first: closing with unread data would reset the connection before the reply arrives.
            let _ = stream.try_read(&mut head);
            let _ = stream.try_write(response.as_bytes());
            Err(io::Error::other("plain HTTP on the HTTPS port"))
        })
    }
}

/// The HTTPS URL for a plain-HTTP request head. Only a well-formed Host is echoed back, and any
/// path that is not plainly safe (the request is attacker-controlled) is replaced with `/`.
fn https_location(head: &[u8]) -> Option<String> {
    let mut lines = std::str::from_utf8(head).ok()?.split("\r\n");
    let path = lines.next()?.split(' ').nth(1)?;
    let host = lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("host").then(|| value.trim())
    })?;
    let safe = |text: &str, punctuation: &str| {
        !text.is_empty()
            && text
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || punctuation.contains(c))
    };
    let path = if path.starts_with('/') && safe(path, "/-_.") {
        path
    } else {
        "/"
    };
    safe(host, ".-:[]").then(|| format!("https://{host}{path}"))
}

// --- Utility Functions ---
fn generate_share_id() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(SHARE_ID_LENGTH)
        .map(char::from)
        .collect()
}

fn generate_create_token() -> String {
    let bytes: [u8; CREATE_TOKEN_BYTE_LENGTH] = rand::thread_rng().r#gen();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A share ID is valid only if it has the exact shape `generate_share_id` produces.
fn is_valid_share_id(share_id: &str) -> bool {
    share_id.len() == SHARE_ID_LENGTH && share_id.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn is_expired(share: &EncryptedShare, now: Instant) -> bool {
    now.duration_since(share.timestamp) >= EXPIRY_DURATION
}

async fn delete_expired_shares(state: SharedState) {
    let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
    loop {
        interval.tick().await;
        let now = Instant::now();
        state.shares.write().await.retain(|id, share| {
            let expired = is_expired(share, now);
            if expired {
                info!("Deleting expired share with id: {}", id);
            }
            !expired
        });
    }
}

/// Resolves on SIGTERM (what `docker stop` sends) or on the second Ctrl+C.
async fn shutdown_signal() {
    let terminate = async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            match signal(SignalKind::terminate()) {
                Ok(mut sigterm) => return sigterm.recv().await.unwrap_or(()),
                Err(e) => error!("Failed to listen for SIGTERM: {}", e),
            }
        }
        std::future::pending::<()>().await
    };
    let ctrl_c_twice = async {
        if tokio::signal::ctrl_c().await.is_ok() {
            warn!("Received Ctrl+C. Press Ctrl+C again to exit.");
            let _ = tokio::signal::ctrl_c().await;
        }
    };
    tokio::select! {
        _ = ctrl_c_twice => {}
        _ = terminate => {}
    }
    info!("Shutdown signal received.");
}

async fn add_security_headers(
    State(state): State<SharedState>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for &(name, value) in SECURITY_HEADERS {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    if state.tls_enabled {
        // Pin browsers to HTTPS so the pages (and their crypto code) are never fetched in clear text.
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    response
}

/// Caps how many uploads are buffered at once and how long each may take, to bound memory use.
async fn limit_concurrent_creates(
    State(state): State<SharedState>,
    request: Request,
    next: Next,
) -> Response {
    // Reject unauthenticated uploads before acquiring a slot or reading the body.
    if let Some(expected) = &state.create_token {
        let supplied = request
            .headers()
            .get("x-create-token")
            .map(|value| value.as_bytes())
            .unwrap_or_default();
        if !bool::from(supplied.ct_eq(expected.as_bytes())) {
            return (StatusCode::UNAUTHORIZED, "Missing or invalid create token.").into_response();
        }
    }
    let Ok(_slot) = state.create_slots.try_acquire() else {
        warn!("Rejected create request: too many uploads in progress");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Server is busy: too many uploads in progress. Try again in a moment.",
        )
            .into_response();
    };
    tokio::time::timeout(CREATE_TIMEOUT, next.run(request))
        .await
        .unwrap_or_else(|_| {
            warn!("Create request timed out");
            (StatusCode::REQUEST_TIMEOUT, "Upload took too long.").into_response()
        })
}

async fn read_web_file(filename: &str) -> Result<String, ApiError> {
    let path = PathBuf::from(WEB_DIR).join(filename);
    tokio::fs::read_to_string(&path).await.map_err(|e| {
        error!("Failed to read web file {:?}: {}", path, e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error: Could not load page template.",
        )
    })
}

/// Logs why a create request was refused and builds its error response.
fn reject<T>(status: StatusCode, message: &'static str) -> Result<T, ApiError> {
    warn!("Rejected create request: {}", message);
    Err((status, message))
}

// --- Route Handlers ---
async fn handle_index(State(state): State<SharedState>) -> Result<Html<String>, ApiError> {
    let token_required = state.create_token.is_some().to_string();
    let page = read_web_file("index.html").await?;
    Ok(Html(
        page.replace(TOKEN_REQUIRED_PLACEHOLDER, &token_required),
    ))
}

async fn handle_create_encrypted(
    State(state): State<SharedState>,
    Json(payload): Json<CreateRequest>,
) -> Result<Json<CreateResponse>, ApiError> {
    let Ok(mut data) = base64_engine.decode(&payload.nonce_b64) else {
        return reject(StatusCode::BAD_REQUEST, "Invalid nonce encoding");
    };
    let Ok(mut encrypted_data) = base64_engine.decode(&payload.encrypted_data_b64) else {
        return reject(StatusCode::BAD_REQUEST, "Invalid encrypted_data encoding");
    };

    if data.len() != NONCE_LENGTH {
        return reject(StatusCode::BAD_REQUEST, "Invalid nonce length. Expected 12");
    }
    if encrypted_data.is_empty() || encrypted_data.len() + data.len() > MAX_ENCRYPTED_SIZE {
        return reject(
            StatusCode::BAD_REQUEST,
            "Encrypted content exceeds maximum size limit or is empty",
        );
    }

    let share_id = generate_share_id();
    data.reserve_exact(encrypted_data.len()); // Stored for up to an hour: do not keep spare capacity
    data.extend_from_slice(&encrypted_data);
    encrypted_data.zeroize(); // The stored copy is the only one that should outlive this request
    let share = EncryptedShare {
        data: Bytes::from_owner(WipeOnDrop(data)),
        timestamp: Instant::now(),
    };

    let mut shares = state.shares.write().await;
    if shares.len() >= MAX_SHARE_COUNT {
        // Reclaim any expired slots before refusing.
        let now = Instant::now();
        shares.retain(|_, share| !is_expired(share, now));
    }
    if shares.len() >= MAX_SHARE_COUNT {
        return reject(
            StatusCode::SERVICE_UNAVAILABLE,
            "Server is full: maximum number of shares reached. Try again later.",
        );
    }
    if shares.contains_key(&share_id) {
        error!("Share ID collision detected for ID: {}", share_id);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not save share, please try again.",
        ));
    }
    shares.insert(share_id.clone(), share);

    info!("Stored encrypted share with id: {}", share_id);
    Ok(Json(CreateResponse { share_id }))
}

async fn handle_retrieve_page() -> Result<Html<String>, ApiError> {
    read_web_file("retrieve.html").await.map(Html)
}

async fn handle_static_asset(Path(file): Path<String>) -> Response {
    // Only the fixed allow-list is served; the requested name never touches the filesystem.
    let Some((name, content_type)) = STATIC_ASSETS.iter().find(|(name, _)| *name == file) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match read_web_file(name).await {
        Ok(body) => ([(header::CONTENT_TYPE, *content_type)], body).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn handle_get_encrypted_share(
    State(state): State<SharedState>,
    Path(share_id): Path<String>,
) -> Result<Bytes, StatusCode> {
    // Validate before logging: the ID is attacker-controlled and must never reach the log raw.
    if !is_valid_share_id(&share_id) {
        warn!("Received get request with invalid share_id format.");
        return Err(StatusCode::BAD_REQUEST);
    }

    let shares = state.shares.read().await;
    // Never serve a share past its lifetime, even if the sweep has not removed it yet.
    let live = |share: &&EncryptedShare| !is_expired(share, Instant::now());
    let Some(share) = shares.get(&share_id).filter(live) else {
        warn!("Share not found for id: {}", share_id);
        return Err(StatusCode::NOT_FOUND);
    };
    info!("Returning encrypted data for id: {}", share_id);
    Ok(share.data.clone())
}
