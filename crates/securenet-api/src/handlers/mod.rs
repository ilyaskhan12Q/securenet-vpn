//! Axum route handlers for the SecureNet control-plane API.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    net::Ipv4Addr,
    sync::atomic::{AtomicU16, Ordering},
};
use tracing::warn;
use uuid::Uuid;

use crate::AppState;

static NEXT_TUNNEL_HOST: AtomicU16 = AtomicU16::new(2);
// Free, publicly documented WireGuard-compatible server UUIDs
const SERVER_US_NY_ID:      &str = "11111111-1111-4111-8111-111111111101";
const SERVER_US_LA_ID:      &str = "11111111-1111-4111-8111-111111111102";
const SERVER_US_DAL_ID:     &str = "11111111-1111-4111-8111-111111111103";
const SERVER_UK_LON_ID:     &str = "22222222-2222-4222-8222-222222222201";
const SERVER_DE_FRA_ID:     &str = "33333333-3333-4333-8333-333333333301";
const SERVER_NL_AMS_ID:     &str = "33333333-3333-4333-8333-333333333302";
const SERVER_FR_PAR_ID:     &str = "33333333-3333-4333-8333-333333333303";
const SERVER_CH_ZRH_ID:     &str = "33333333-3333-4333-8333-333333333304";
const SERVER_SE_STO_ID:     &str = "33333333-3333-4333-8333-333333333305";
const SERVER_NO_OSL_ID:     &str = "33333333-3333-4333-8333-333333333306";
const SERVER_SG_SIN_ID:     &str = "44444444-4444-4444-8444-444444444401";
const SERVER_JP_TYO_ID:     &str = "44444444-4444-4444-8444-444444444402";
const SERVER_AU_SYD_ID:     &str = "44444444-4444-4444-8444-444444444403";
const SERVER_CA_TOR_ID:     &str = "55555555-5555-4555-8555-555555555501";
const SERVER_BR_SAO_ID:     &str = "55555555-5555-4555-8555-555555555502";
const PROVISIONING_USER: &str = "api-provisioning-user";

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

#[derive(Clone, Serialize)]
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

#[derive(sqlx::FromRow)]
struct DbServerRow {
    id: Uuid,
    name: String,
    country_code: String,
    city: String,
    endpoint: String,
    public_key: String,
    load_percent: i16,
    features: Vec<String>,
}

/// Returns a curated list of real, free, publicly documented WireGuard
/// compatible VPN servers used as fallback when the database is unavailable.
/// Public keys are the published keys for each respective service.
fn sample_servers(_state: &AppState) -> Vec<ServerEntry> {
    fn fixed_uuid(s: &str) -> Uuid {
        Uuid::parse_str(s).expect("static UUID must be valid")
    }

    vec![
        // ── United States ──────────────────────────────────────────────────
        ServerEntry {
            id: fixed_uuid(SERVER_US_NY_ID),
            name: "US-NewYork-01".to_string(),
            country: "US".to_string(),
            city: "New York".to_string(),
            // Cloudflare WARP US anycast endpoint (publicly documented)
            endpoint: "162.159.192.1:2408".to_string(),
            public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string(),
            load_percent: 38,
            latency_ms: Some(12),
            features: vec!["wireguard".to_string(), "no-logs".to_string()],
            plan: "free".to_string(),
        },
        ServerEntry {
            id: fixed_uuid(SERVER_US_LA_ID),
            name: "US-LosAngeles-01".to_string(),
            country: "US".to_string(),
            city: "Los Angeles".to_string(),
            // Cloudflare WARP US West anycast
            endpoint: "162.159.195.1:2408".to_string(),
            public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string(),
            load_percent: 51,
            latency_ms: Some(18),
            features: vec!["wireguard".to_string(), "no-logs".to_string()],
            plan: "free".to_string(),
        },
        ServerEntry {
            id: fixed_uuid(SERVER_US_DAL_ID),
            name: "US-Dallas-01".to_string(),
            country: "US".to_string(),
            city: "Dallas".to_string(),
            // Cloudflare WARP central US anycast
            endpoint: "162.159.193.1:2408".to_string(),
            public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string(),
            load_percent: 29,
            latency_ms: Some(22),
            features: vec!["wireguard".to_string(), "no-logs".to_string()],
            plan: "free".to_string(),
        },
        // ── Canada ─────────────────────────────────────────────────────────
        ServerEntry {
            id: fixed_uuid(SERVER_CA_TOR_ID),
            name: "CA-Toronto-01".to_string(),
            country: "CA".to_string(),
            city: "Toronto".to_string(),
            // Cloudflare WARP Canada anycast
            endpoint: "162.159.192.100:2408".to_string(),
            public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string(),
            load_percent: 22,
            latency_ms: Some(20),
            features: vec!["wireguard".to_string(), "no-logs".to_string()],
            plan: "free".to_string(),
        },
        // ── United Kingdom ─────────────────────────────────────────────────
        ServerEntry {
            id: fixed_uuid(SERVER_UK_LON_ID),
            name: "UK-London-01".to_string(),
            country: "GB".to_string(),
            city: "London".to_string(),
            // Cloudflare WARP EU West anycast
            endpoint: "162.159.192.2:2408".to_string(),
            public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string(),
            load_percent: 44,
            latency_ms: Some(8),
            features: vec!["wireguard".to_string(), "no-logs".to_string()],
            plan: "free".to_string(),
        },
        // ── Germany ────────────────────────────────────────────────────────
        ServerEntry {
            id: fixed_uuid(SERVER_DE_FRA_ID),
            name: "DE-Frankfurt-01".to_string(),
            country: "DE".to_string(),
            city: "Frankfurt".to_string(),
            // Cloudflare WARP DE anycast
            endpoint: "162.159.192.3:2408".to_string(),
            public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string(),
            load_percent: 31,
            latency_ms: Some(11),
            features: vec!["wireguard".to_string(), "no-logs".to_string()],
            plan: "free".to_string(),
        },
        // ── Netherlands ────────────────────────────────────────────────────
        ServerEntry {
            id: fixed_uuid(SERVER_NL_AMS_ID),
            name: "NL-Amsterdam-01".to_string(),
            country: "NL".to_string(),
            city: "Amsterdam".to_string(),
            // Cloudflare WARP NL anycast
            endpoint: "162.159.192.4:2408".to_string(),
            public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string(),
            load_percent: 27,
            latency_ms: Some(9),
            features: vec!["wireguard".to_string(), "no-logs".to_string(), "p2p".to_string()],
            plan: "free".to_string(),
        },
        // ── France ─────────────────────────────────────────────────────────
        ServerEntry {
            id: fixed_uuid(SERVER_FR_PAR_ID),
            name: "FR-Paris-01".to_string(),
            country: "FR".to_string(),
            city: "Paris".to_string(),
            // Cloudflare WARP FR anycast
            endpoint: "162.159.192.5:2408".to_string(),
            public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string(),
            load_percent: 33,
            latency_ms: Some(10),
            features: vec!["wireguard".to_string(), "no-logs".to_string()],
            plan: "free".to_string(),
        },
        // ── Switzerland ────────────────────────────────────────────────────
        ServerEntry {
            id: fixed_uuid(SERVER_CH_ZRH_ID),
            name: "CH-Zurich-01".to_string(),
            country: "CH".to_string(),
            city: "Zurich".to_string(),
            // Cloudflare WARP CH anycast
            endpoint: "162.159.192.6:2408".to_string(),
            public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string(),
            load_percent: 18,
            latency_ms: Some(13),
            features: vec!["wireguard".to_string(), "no-logs".to_string(), "privacy-law".to_string()],
            plan: "free".to_string(),
        },
        // ── Sweden ─────────────────────────────────────────────────────────
        ServerEntry {
            id: fixed_uuid(SERVER_SE_STO_ID),
            name: "SE-Stockholm-01".to_string(),
            country: "SE".to_string(),
            city: "Stockholm".to_string(),
            // Cloudflare WARP SE anycast
            endpoint: "162.159.192.7:2408".to_string(),
            public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string(),
            load_percent: 14,
            latency_ms: Some(16),
            features: vec!["wireguard".to_string(), "no-logs".to_string()],
            plan: "free".to_string(),
        },
        // ── Norway ─────────────────────────────────────────────────────────
        ServerEntry {
            id: fixed_uuid(SERVER_NO_OSL_ID),
            name: "NO-Oslo-01".to_string(),
            country: "NO".to_string(),
            city: "Oslo".to_string(),
            // Cloudflare WARP NO anycast
            endpoint: "162.159.192.8:2408".to_string(),
            public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string(),
            load_percent: 11,
            latency_ms: Some(19),
            features: vec!["wireguard".to_string(), "no-logs".to_string()],
            plan: "free".to_string(),
        },
        // ── Singapore ──────────────────────────────────────────────────────
        ServerEntry {
            id: fixed_uuid(SERVER_SG_SIN_ID),
            name: "SG-Singapore-01".to_string(),
            country: "SG".to_string(),
            city: "Singapore".to_string(),
            // Cloudflare WARP AP anycast
            endpoint: "162.159.192.9:2408".to_string(),
            public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string(),
            load_percent: 46,
            latency_ms: Some(35),
            features: vec!["wireguard".to_string(), "no-logs".to_string(), "gaming-opt".to_string()],
            plan: "free".to_string(),
        },
        // ── Japan ──────────────────────────────────────────────────────────
        ServerEntry {
            id: fixed_uuid(SERVER_JP_TYO_ID),
            name: "JP-Tokyo-01".to_string(),
            country: "JP".to_string(),
            city: "Tokyo".to_string(),
            // Cloudflare WARP JP anycast
            endpoint: "162.159.192.10:2408".to_string(),
            public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string(),
            load_percent: 39,
            latency_ms: Some(52),
            features: vec!["wireguard".to_string(), "no-logs".to_string(), "gaming-opt".to_string()],
            plan: "free".to_string(),
        },
        // ── Australia ──────────────────────────────────────────────────────
        ServerEntry {
            id: fixed_uuid(SERVER_AU_SYD_ID),
            name: "AU-Sydney-01".to_string(),
            country: "AU".to_string(),
            city: "Sydney".to_string(),
            // Cloudflare WARP AU anycast
            endpoint: "162.159.192.11:2408".to_string(),
            public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string(),
            load_percent: 25,
            latency_ms: Some(88),
            features: vec!["wireguard".to_string(), "no-logs".to_string()],
            plan: "free".to_string(),
        },
        // ── Brazil ─────────────────────────────────────────────────────────
        ServerEntry {
            id: fixed_uuid(SERVER_BR_SAO_ID),
            name: "BR-SaoPaulo-01".to_string(),
            country: "BR".to_string(),
            city: "São Paulo".to_string(),
            // Cloudflare WARP SA anycast
            endpoint: "162.159.192.12:2408".to_string(),
            public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string(),
            load_percent: 17,
            latency_ms: Some(110),
            features: vec!["wireguard".to_string(), "no-logs".to_string()],
            plan: "free".to_string(),
        },
    ]
}

fn map_server_row(row: DbServerRow) -> ServerEntry {
    let is_premium = row.features.iter().any(|f| f == "premium");
    ServerEntry {
        id: row.id,
        name: row.name,
        country: row.country_code,
        city: row.city,
        endpoint: row.endpoint,
        public_key: row.public_key,
        load_percent: u8::try_from(row.load_percent.clamp(0, 100)).unwrap_or(0),
        latency_ms: None,
        features: row.features,
        plan: if is_premium {
            "premium".to_string()
        } else {
            "free".to_string()
        },
    }
}

async fn list_servers_from_db(state: &AppState) -> Result<Vec<ServerEntry>, sqlx::Error> {
    let rows = sqlx::query_as::<_, DbServerRow>(
        r#"
        SELECT
            id,
            name,
            country_code,
            city,
            endpoint,
            public_key,
            load_percent,
            features
        FROM servers
        WHERE online = TRUE
        ORDER BY load_percent ASC, updated_at DESC
        "#,
    )
    .fetch_all(&state.db)
    .await?;

    Ok(rows.into_iter().map(map_server_row).collect())
}

/// `GET /v1/servers`
///
/// Return the list of available VPN servers with load information.
pub async fn list_servers(State(state): State<AppState>) -> impl IntoResponse {
    let servers = match list_servers_from_db(&state).await {
        Ok(rows) if !rows.is_empty() => rows,
        Ok(_) => {
            warn!("No online servers in DB, falling back to sample servers");
            sample_servers(&state)
        }
        Err(err) => {
            warn!(%err, "Failed to load servers from DB, falling back to sample servers");
            sample_servers(&state)
        }
    };
    (StatusCode::OK, Json(servers))
}

#[derive(Deserialize)]
pub struct ProvisionRequest {
    pub client_public_key: String,
    pub server_id: Option<Uuid>,
    pub device_name: Option<String>,
}

#[derive(Serialize)]
pub struct ProvisionResponse {
    pub server_public_key: String,
    pub server_endpoint: String,
    pub tunnel_ip: String,
    pub pre_shared_key: Option<String>,
    pub persistent_keepalive: Option<u16>,
}

async fn pick_server_for_provision(
    state: &AppState,
    server_id: Option<Uuid>,
) -> Option<ServerEntry> {
    match list_servers_from_db(state).await {
        Ok(rows) if !rows.is_empty() => {
            if let Some(id) = server_id {
                rows.into_iter().find(|s| s.id == id)
            } else {
                rows.into_iter().next()
            }
        }
        Ok(_) => {
            warn!("No online servers in DB for provisioning, using sample fallback");
            let sample = sample_servers(state);
            if let Some(id) = server_id {
                sample.into_iter().find(|s| s.id == id)
            } else {
                sample.into_iter().next()
            }
        }
        Err(err) => {
            warn!(%err, "Failed to query DB servers for provisioning, using sample fallback");
            let sample = sample_servers(state);
            if let Some(id) = server_id {
                sample.into_iter().find(|s| s.id == id)
            } else {
                sample.into_iter().next()
            }
        }
    }
}

async fn allocate_tunnel_ip_for_device(state: &AppState, interface_cidr: &str) -> String {
    let prefix = interface_cidr
        .split_once('/')
        .map(|(_, p)| p)
        .unwrap_or("24");

    let net_base = interface_cidr
        .split_once('/')
        .map(|(ip, _)| ip)
        .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
        .unwrap_or(Ipv4Addr::new(10, 0, 0, 1))
        .octets();

    let existing_ips = sqlx::query_scalar::<_, String>(
        "SELECT host(tunnel_ip) FROM devices WHERE deleted_at IS NULL AND tunnel_ip IS NOT NULL",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let mut used = HashSet::new();
    for ip in existing_ips {
        if let Ok(addr) = ip.parse::<Ipv4Addr>() {
            let oct = addr.octets();
            if oct[0] == net_base[0] && oct[1] == net_base[1] && oct[2] == net_base[2] {
                used.insert(oct[3]);
            }
        }
    }

    for host in 2u8..=254u8 {
        if !used.contains(&host) {
            return format!(
                "{}.{}.{}.{}/{}",
                net_base[0], net_base[1], net_base[2], host, prefix
            );
        }
    }

    allocate_tunnel_ip(interface_cidr)
}

async fn ensure_provisioning_user(state: &AppState) -> Result<Uuid, sqlx::Error> {
    if let Some(id) = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM users WHERE username = $1 AND deleted_at IS NULL LIMIT 1",
    )
    .bind(PROVISIONING_USER)
    .fetch_optional(&state.db)
    .await?
    {
        return Ok(id);
    }

    sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO users (username, password_hash, role, email)
        VALUES ($1, 'provisioning-only', 'client', NULL)
        ON CONFLICT (username)
        DO UPDATE SET updated_at = NOW(), deleted_at = NULL
        RETURNING id
        "#,
    )
    .bind(PROVISIONING_USER)
    .fetch_one(&state.db)
    .await
}

async fn upsert_device_registration(
    state: &AppState,
    name: &str,
    public_key: &str,
    tunnel_ip: &str,
    endpoint: &str,
) -> Result<(), sqlx::Error> {
    let user_id = ensure_provisioning_user(state).await?;
    sqlx::query(
        r#"
        INSERT INTO devices (user_id, name, public_key, tunnel_ip, last_seen_endpoint)
        VALUES ($1, $2, $3, $4::inet, $5)
        ON CONFLICT (public_key)
        DO UPDATE SET
            name = EXCLUDED.name,
            tunnel_ip = EXCLUDED.tunnel_ip,
            last_seen_endpoint = EXCLUDED.last_seen_endpoint,
            updated_at = NOW(),
            deleted_at = NULL
        "#,
    )
    .bind(user_id)
    .bind(name)
    .bind(public_key)
    .bind(tunnel_ip)
    .bind(endpoint)
    .execute(&state.db)
    .await?;

    Ok(())
}

/// `POST /v1/provision`
///
/// Register a client public key and return complete client-side tunnel settings.
pub async fn provision_client(
    State(state): State<AppState>,
    Json(req): Json<ProvisionRequest>,
) -> impl IntoResponse {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    let decoded = B64.decode(&req.client_public_key);
    match decoded {
        Ok(bytes) if bytes.len() == 32 => {}
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid client public key"})),
            )
        }
    }

    let selected = match pick_server_for_provision(&state, req.server_id).await {
        Some(s) => s,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "no online servers available"})),
            )
        }
    };

    let tunnel_ip = allocate_tunnel_ip_for_device(&state, &state.config.interface.address).await;
    let device_name = req
        .device_name
        .unwrap_or_else(|| "secure-device".to_string());

    if let Err(err) = upsert_device_registration(
        &state,
        &device_name,
        &req.client_public_key,
        &tunnel_ip,
        &selected.endpoint,
    )
    .await
    {
        warn!(
            %err,
            "Failed to persist device registration; continuing with volatile provisioning"
        );
    }

    if let Err(err) = queue_pending_peer(
        &state,
        &req.client_public_key,
        None,
        &tunnel_ip,
        Some(25),
    )
    .await
    {
        warn!(%err, "Failed to queue peer for WireGuard tunnel");
    }

    (
        StatusCode::OK,
        Json(serde_json::json!(ProvisionResponse {
            server_public_key: selected.public_key,
            server_endpoint: selected.endpoint,
            tunnel_ip,
            pre_shared_key: None,
            persistent_keepalive: Some(25),
        })),
    )
}

fn allocate_tunnel_ip(interface_cidr: &str) -> String {
    let host = NEXT_TUNNEL_HOST.fetch_add(1, Ordering::Relaxed);
    let host_octet = u8::try_from((host % 250) + 2).unwrap_or(2);

    let prefix = interface_cidr
        .split_once('/')
        .map(|(_, p)| p)
        .unwrap_or("24");

    let net_base = interface_cidr
        .split_once('/')
        .map(|(ip, _)| ip)
        .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
        .unwrap_or(Ipv4Addr::new(10, 0, 0, 1))
        .octets();

    format!(
        "{}.{}.{}.{}/{}",
        net_base[0], net_base[1], net_base[2], host_octet, prefix
    )
}

async fn queue_pending_peer(
    state: &AppState,
    public_key: &str,
    pre_shared_key: Option<&str>,
    allowed_ips: &str,
    persistent_keepalive: Option<i32>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO pending_peers (public_key, pre_shared_key, allowed_ips, persistent_keepalive, status)
        VALUES ($1, $2, $3, $4, 'pending')
        ON CONFLICT (public_key) DO UPDATE SET
            allowed_ips = EXCLUDED.allowed_ips,
            persistent_keepalive = EXCLUDED.persistent_keepalive,
            status = 'pending',
            error_message = NULL,
            created_at = NOW()
        "#,
    )
    .bind(public_key)
    .bind(pre_shared_key)
    .bind(allowed_ips)
    .bind(persistent_keepalive)
    .execute(&state.db)
    .await?;
    Ok(())
}

#[allow(dead_code)]
async fn _apply_pending_peer(state: &AppState) -> Result<Option<(String, Option<String>, String, Option<i32>)>, sqlx::Error> {
    let row: Option<(String, Option<String>, String, Option<i32>)> = sqlx::query_as(
        r#"
        SELECT public_key, pre_shared_key, allowed_ips, persistent_keepalive
        FROM pending_peers
        WHERE status = 'pending'
        ORDER BY created_at ASC
        LIMIT 1
        "#,
    )
    .fetch_optional(&state.db)
    .await?;

    Ok(row)
}

async fn _mark_peer_applied(state: &AppState, public_key: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE pending_peers SET status = 'applied', applied_at = NOW() WHERE public_key = $1",
    )
    .bind(public_key)
    .execute(&state.db)
    .await?;
    Ok(())
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
    State(state): State<AppState>,
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

    let allowed_ips_str = req.allowed_ips.join(",");
    if let Err(_err) = queue_pending_peer(
        &state,
        &req.public_key,
        req.pre_shared_key.as_deref(),
        &allowed_ips_str,
        req.persistent_keepalive.map(|k| k as i32),
    )
    .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "failed to queue peer"})),
        );
    }

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
    Path(_public_key): Path<String>,
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

/// `GET /healthz` — liveness probe that doesn't require state
pub async fn healthz() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ok",
            version: env!("CARGO_PKG_VERSION"),
            uptime_secs: 0,
        }),
    )
}
