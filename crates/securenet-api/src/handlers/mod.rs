//! Axum route handlers for the SecureNet control-plane API.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppState;

// ---------------------------------------------------------------------------
// JWT
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — device UUID.
    pub sub: String,
    /// Issued-at (Unix timestamp).
    pub iat: i64,
    /// Expiry (Unix timestamp).
    pub exp: i64,
    /// Role: "client" | "admin".
    pub role: String,
}

// ---------------------------------------------------------------------------
// Auth handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AuthRequest {
    pub device_id: Uuid,
    pub public_key: String,
    /// HMAC-SHA256(device_id || timestamp, device_secret) — anti-replay.
    pub signature: String,
    pub timestamp: i64,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub expires_at: i64,
    /// Assigned inner tunnel IP.
    pub tunnel_ip: String,
    /// Server's WireGuard public key.
    pub server_public_key: String,
    /// Server WireGuard endpoint.
    pub server_endpoint: String,
}

/// `POST /v1/auth/device`
///
/// Authenticate a device using its UUID + public key.  Returns a short-lived
/// JWT that the client uses to call all other endpoints.
pub async fn auth_device(
    State(state): State<AppState>,
    Json(req): Json<AuthRequest>,
) -> impl IntoResponse {
    // --- Validate timestamp (±30 s) to prevent replay ---
    let now = Utc::now().timestamp();
    if (now - req.timestamp).abs() > 30 {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "timestamp out of window"})),
        );
    }

    // --- Look up device in DB and verify public key ---
    // (Database interaction omitted for brevity; shown structurally.)
    // let device = db::find_device(&state.db, req.device_id).await?;
    // if device.public_key != req.public_key { return 401 }

    // --- Issue JWT ---
    let exp = Utc::now() + Duration::seconds(state.config.api.token_ttl_secs as i64);
    let claims = Claims {
        sub: req.device_id.to_string(),
        iat: now,
        exp: exp.timestamp(),
        role: "client".to_string(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.api.jwt_secret.as_bytes()),
    );

    match token {
        Ok(t) => (
            StatusCode::OK,
            Json(serde_json::json!(AuthResponse {
                token: t,
                expires_at: exp.timestamp(),
                tunnel_ip: "10.0.0.X/32".to_string(), // allocate from pool
                server_public_key: state.server_pub_key.clone(),
                server_endpoint: state.config.interface.listen_addr.to_string(),
            })),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "token generation failed"})),
        ),
    }
}

// ---------------------------------------------------------------------------
// Server-list handler
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct ServerEntry {
    pub id: Uuid,
    pub name: String,
    pub country: String,
    pub city: String,
    pub endpoint: String,
    pub public_key: String,
    pub load_percent: u8,
    pub latency_ms: Option<u32>,
    pub features: Vec<String>,
    pub plan: String, // "free" or "premium"
}

/// `GET /v1/servers`
///
/// Return the list of available VPN servers with load information.
pub async fn list_servers(State(state): State<AppState>) -> impl IntoResponse {
    // In production: query a servers table from the database.
    let servers: Vec<ServerEntry> = vec![
        ServerEntry {
            id: Uuid::new_v4(),
            name: "US-East-01".to_string(),
            country: "US".to_string(),
            city: "New York".to_string(),
            endpoint: "198.51.100.1:51820".to_string(),
            public_key: state.server_pub_key.clone(),
            load_percent: 42,
            latency_ms: Some(15),
            features: vec!["wireguard".to_string(), "multi-hop".to_string()],
            plan: "free".to_string(),
        },
        ServerEntry {
            id: Uuid::new_v4(),
            name: "UK-London-01".to_string(),
            country: "UK".to_string(),
            city: "London".to_string(),
            endpoint: "203.0.113.1:51820".to_string(),
            public_key: "UK_SERVER_PUB_KEY".to_string(),
            load_percent: 15,
            latency_ms: Some(85),
            features: vec!["wireguard".to_string(), "netflix-unblock".to_string()],
            plan: "premium".to_string(),
        },
        ServerEntry {
            id: Uuid::new_v4(),
            name: "DE-Frankfurt-01".to_string(),
            country: "DE".to_string(),
            city: "Frankfurt".to_string(),
            endpoint: "1.2.3.4:51820".to_string(),
            public_key: "DE_SERVER_PUB_KEY".to_string(),
            load_percent: 10,
            latency_ms: Some(25),
            features: vec!["wireguard".to_string()],
            plan: "free".to_string(),
        },
        ServerEntry {
            id: Uuid::new_v4(),
            name: "SG-Singapore-01".to_string(),
            country: "SG".to_string(),
            city: "Singapore".to_string(),
            endpoint: "5.6.7.8:51820".to_string(),
            public_key: "SG_SERVER_PUB_KEY".to_string(),
            load_percent: 5,
            latency_ms: Some(120),
            features: vec!["wireguard".to_string(), "gaming-opt".to_string()],
            plan: "premium".to_string(),
        },
    ];
    (StatusCode::OK, Json(servers))
}

// ---------------------------------------------------------------------------
// Peer management (admin)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AddPeerRequest {
    pub name: String,
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub pre_shared_key: Option<String>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Serialize)]
pub struct AddPeerResponse {
    pub peer_id: Uuid,
    pub tunnel_ip: String,
}

/// `POST /v1/admin/peers`  (admin-only)
pub async fn add_peer(
    State(_state): State<AppState>,
    Json(req): Json<AddPeerRequest>,
) -> impl IntoResponse {
    // Validate public key format
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let decoded_key: std::result::Result<Vec<u8>, _> = B64.decode(&req.public_key);
    match decoded_key {
        Ok(b) if b.len() == 32 => {}
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid public key"})),
            )
        }
    }

    // Persist to DB and hot-reload the tunnel at runtime
    // state.tunnel.add_peer(peer_cfg).await?;

    (
        StatusCode::CREATED,
        Json(serde_json::json!(AddPeerResponse {
            peer_id: Uuid::new_v4(),
            tunnel_ip: req.allowed_ips.first().cloned().unwrap_or_default(),
        })),
    )
}

/// `DELETE /v1/admin/peers/:public_key`  (admin-only)
pub async fn remove_peer(
    State(_state): State<AppState>,
    Path(public_key): Path<String>,
) -> impl IntoResponse {
    // state.tunnel.remove_peer(&public_key).await?;
    (StatusCode::NO_CONTENT, Json(serde_json::json!({})))
}

// ---------------------------------------------------------------------------
// Health / readiness
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub uptime_secs: u64,
}

/// `GET /healthz`
pub async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    let uptime = state.started_at.elapsed().as_secs();
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ok",
            version: env!("CARGO_PKG_VERSION"),
            uptime_secs: uptime,
        }),
    )
}
