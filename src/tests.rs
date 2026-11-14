use super::*;

fn state() -> SharedState {
    Arc::new(AppData {
        shares: RwLock::new(HashMap::new()),
        create_slots: Semaphore::new(0),
        create_token: Some("secret".into()),
        tls_enabled: false,
    })
}

async fn create_status(token: Option<&str>) -> StatusCode {
    let app = Router::new()
        .route("/create", post(|| async { StatusCode::OK }))
        .layer(middleware::from_fn_with_state(
            state(),
            limit_concurrent_creates,
        ));
    let mut request = Request::builder().method("POST").uri("/create");
    if let Some(token) = token {
        request = request.header("x-create-token", token);
    }
    // Deliberately invalid JSON: authentication must happen before parsing.
    let request = request.body(axum::body::Body::from("not json")).unwrap();
    use tower::ServiceExt;
    app.oneshot(request).await.unwrap().status()
}

#[tokio::test]
async fn authentication_precedes_upload_slots() {
    assert_eq!(create_status(None).await, StatusCode::UNAUTHORIZED);
    assert_eq!(create_status(Some("wrong")).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        create_status(Some("secret")).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[test]
fn expiration_boundary() {
    let share = EncryptedShare {
        data: Bytes::from_owner(WipeOnDrop(vec![0; NONCE_LENGTH + 1])),
        timestamp: Instant::now(),
    };
    assert!(!is_expired(
        &share,
        share.timestamp + EXPIRY_DURATION - Duration::from_nanos(1)
    ));
    assert!(is_expired(&share, share.timestamp + EXPIRY_DURATION));
}

#[test]
fn share_ids_have_strict_shape() {
    assert!(is_valid_share_id(&generate_share_id()));
    assert!(!is_valid_share_id("short"));
    assert!(!is_valid_share_id(&"/".repeat(SHARE_ID_LENGTH)));
}

#[test]
fn plain_http_is_redirected_to_https() {
    let location = |head: &str| https_location(head.as_bytes());
    assert_eq!(
        location("GET /s/abc123 HTTP/1.1\r\nHost: example.com:8443\r\n\r\n").as_deref(),
        Some("https://example.com:8443/s/abc123")
    );
    // An unsafe path falls back to the root; a missing or malformed Host is refused.
    assert_eq!(
        location("GET /?next=//evil HTTP/1.1\r\nhost: [::1]:8443\r\n\r\n").as_deref(),
        Some("https://[::1]:8443/")
    );
    assert_eq!(location("GET / HTTP/1.1\r\n\r\n"), None);
    assert_eq!(
        location("GET / HTTP/1.1\r\nHost: evil.com/\\@x\r\n\r\n"),
        None
    );
}
