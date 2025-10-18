use axum::{
    extract::{Json, Path, State},
    http::{Method, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine as _};
use clap::Parser;
use rand::{distributions::Alphanumeric, Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// --- Configuration Constants ---
const MAX_ENCRYPTED_SIZE: usize = 10 * 1024 * 1024; // 10 MiB limit (encrypted data + nonce)
const PASTE_ID_LENGTH: usize = 22; // Length of the random URL-safe ID
const NONCE_LENGTH: usize = 12; // Standard AES-GCM nonce length
const EXPIRY_DURATION: Duration = Duration::from_secs(24 * 60 * 60);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60 * 60);
const WEB_DIR: &str = "./web";

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
}

// --- Data Structures ---
#[derive(Clone)]
struct EncryptedPaste {
    encrypted_data: Vec<u8>,
    nonce: Vec<u8>,
    timestamp: Instant,
}

#[derive(Deserialize)]
struct CreateEncryptedPasteRequest {
    encrypted_data_b64: String,
    nonce_b64: String,
}

#[derive(Serialize)]
struct CreateEncryptedPasteResponse {
    paste_id: String,
}

#[derive(Serialize)]
struct GetEncryptedPasteResponse {
    encrypted_data_b64: String,
    nonce_b64: String,
}

#[derive(Clone)]
struct AppConfig {}

struct AppData {
    pastes: RwLock<HashMap<String, EncryptedPaste>>,
    config: AppConfig,
}

type SharedState = Arc<AppData>;

// --- Main Function ---
#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();

    let (_protocol, tls_config) = match (&args.cert, &args.key) {
        (Some(cert_path), Some(key_path)) => {
            info!("TLS enabled. Loading cert: {:?}, key: {:?}", cert_path, key_path);
            let config = match RustlsConfig::from_pem_file(cert_path, key_path).await {
                Ok(config) => config,
                Err(e) => {
                    error!("Failed to load TLS certificate/key: {}", e);
                    panic!("TLS configuration failed: {}", e);
                }
            };
            ("https://", Some(config))
        }
        (None, None) => {
            warn!(
                "TLS not configured: running in HTTP mode. Traffic is unencrypted and potentially tamperable. Provide --cert and --key to enable HTTPS."
            );
            ("http://", None)
        }
        _ => {
            error!("Both --cert and --key must be provided for TLS, or neither for HTTP.");
            std::process::exit(1);
        }
    };

    let app_config = AppConfig {};
    let app_data = AppData {
        pastes: RwLock::new(HashMap::new()),
        config: app_config,
    };
    let shared_state: SharedState = Arc::new(app_data);

    // Spawn background cleanup task to delete expired pastes.
    let cleanup_state = shared_state.clone();
    tokio::spawn(async move {
        delete_expired_pastes(cleanup_state).await;
    });

    // Setup CORS enable if required
    /*
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE])
        .allow_origin("TODO");*/

    // Define routes.
    let app = Router::new()
        .route("/", get(handle_index))
        .route("/create", post(handle_create_encrypted))
        .route("/p/*path", get(handle_retrieve_page))
        .route("/api/paste/:paste_id", get(handle_get_encrypted_paste))
        .with_state(shared_state)
        //.layer(cors);

    info!("Listening on {}", args.addr);

    if let Some(tls_config) = tls_config {
        axum_server::bind_rustls(args.addr, tls_config)
            .serve(app.into_make_service())
            .await
            .unwrap_or_else(|e| error!("HTTPS Server failed: {}", e));
    } else {
        let listener = tokio::net::TcpListener::bind(args.addr).await.unwrap();
        axum::serve(listener, app)
            .await
            .unwrap_or_else(|e| error!("HTTP Server failed: {}", e));
    }
    info!("Server shutting down.");
}

// --- Utility Functions ---
fn generate_paste_id() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(PASTE_ID_LENGTH)
        .map(char::from)
        .collect()
}

async fn delete_expired_pastes(state: SharedState) {
    let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
    loop {
        interval.tick().await;
        info!("Running cleanup task for expired pastes...");
        let mut pastes = state.pastes.write().await;
        let now = Instant::now();
        pastes.retain(|id, paste| {
            let expired = now.duration_since(paste.timestamp) > EXPIRY_DURATION;
            if expired {
                info!("Deleting expired paste with id: {}", id);
            }
            !expired
        });
        info!("Cleanup finished. Current paste count: {}", pastes.len());
    }
}

async fn read_html_file(filename: &str) -> Result<String, (StatusCode, String)> {
    let path = PathBuf::from(WEB_DIR).join(filename);
    tokio::fs::read_to_string(&path)
        .await
        .map_err(|e| {
            error!("Failed to read HTML file {:?}: {}", path, e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error: Could not load page template.".to_string())
        })
}

// --- Route Handlers ---
async fn handle_index() -> Result<Html<String>, (StatusCode, String)> {
    read_html_file("index.html").await.map(Html)
}

async fn handle_create_encrypted(
    State(state): State<SharedState>,
    Json(payload): Json<CreateEncryptedPasteRequest>,
) -> Result<Json<CreateEncryptedPasteResponse>, (StatusCode, String)> {
    // Decode Base64 nonce and encrypted data.
    let nonce = match base64_engine.decode(&payload.nonce_b64) {
        Ok(n) => n,
        Err(e) => {
            warn!("Failed to decode nonce base64: {}", e);
            return Err((StatusCode::BAD_REQUEST, "Invalid nonce encoding".to_string()));
        }
    };
    let encrypted_data = match base64_engine.decode(&payload.encrypted_data_b64) {
        Ok(d) => d,
        Err(e) => {
            warn!("Failed to decode encrypted data base64: {}", e);
            return Err((StatusCode::BAD_REQUEST, "Invalid encrypted_data encoding".to_string()));
        }
    };

    if nonce.len() != NONCE_LENGTH {
        warn!("Received invalid nonce length: {}. Expected: {}", nonce.len(), NONCE_LENGTH);
        return Err((StatusCode::BAD_REQUEST, format!("Invalid nonce length. Expected {}", NONCE_LENGTH)));
    }
    if encrypted_data.is_empty() || encrypted_data.len() + nonce.len() > MAX_ENCRYPTED_SIZE {
        warn!("Received paste exceeding max size or empty encrypted data");
        return Err((StatusCode::BAD_REQUEST, "Encrypted content exceeds maximum size limit or is empty".to_string()));
    }

    let paste_id = generate_paste_id();
    let paste = EncryptedPaste {
        encrypted_data,
        nonce,
        timestamp: Instant::now(),
    };

    {
        let mut pastes = state.pastes.write().await;
        if pastes.contains_key(&paste_id) {
            error!("Paste ID collision detected for ID: {}", paste_id);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "Could not save paste, please try again.".to_string()));
        }
        pastes.insert(paste_id.clone(), paste);
    }

    info!("Stored encrypted paste with id: {}", paste_id);
    Ok(Json(CreateEncryptedPasteResponse { paste_id }))
}

async fn handle_retrieve_page() -> Result<Html<String>, (StatusCode, String)> {
    read_html_file("retrieve.html").await.map(Html)
}

async fn handle_get_encrypted_paste(
    State(state): State<SharedState>,
    Path(paste_id): Path<String>,
) -> Result<Json<GetEncryptedPasteResponse>, StatusCode> {
    if paste_id.is_empty() || paste_id.len() > 50 {
        warn!("Received get request with invalid paste_id format.");
        return Err(StatusCode::BAD_REQUEST);
    }

    info!("Attempting retrieval for paste id: {}", paste_id);
    let pastes = state.pastes.read().await;
    match pastes.get(&paste_id) {
        Some(paste) => {
            let response = GetEncryptedPasteResponse {
                encrypted_data_b64: base64_engine.encode(&paste.encrypted_data),
                nonce_b64: base64_engine.encode(&paste.nonce),
            };
            info!("Returning encrypted data for id: {}", paste_id);
            Ok(Json(response))
        }
        None => {
            warn!("Paste not found for id: {}", paste_id);
            Err(StatusCode::NOT_FOUND)
        }
    }
}
