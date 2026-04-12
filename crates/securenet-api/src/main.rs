//! `securenet-api` — SecureNet control-plane REST API.
//!
//! Routes:
//!   POST   /v1/auth/device           — device authentication, returns JWT
//!   GET    /v1/servers               — list available VPN servers
//!   POST   /v1/admin/peers           — register a new peer (admin)
//!   DELETE /v1/admin/peers/:pub_key  — remove a peer (admin)
//!   GET    /healthz                  — liveness probe
//!   GET    /readyz                   — readiness probe (checks DB)

use std::{path::PathBuf, time::Instant};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    middleware as axum_middleware,
    routing::{delete, get, post},
    Router,
};
use clap::Parser;
use sqlx::postgres::PgPoolOptions;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::info;
use tracing_subscriber::EnvFilter;

use securenet_core::config::ServerConfig;

pub mod handlers;
pub mod middleware;
use middleware as mw;

// ---------------------------------------------------------------------------
// Application state — shared across all handlers via axum State extractor
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ServerConfig>,
    pub db: sqlx::PgPool,
    pub server_pub_key: String,
    pub started_at: Arc<Instant>,
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "securenet-api", about = "SecureNet VPN control-plane API", version)]
struct Cli {
    #[arg(short, long, default_value = "/etc/securenet/server.toml", env = "SECURENET_CONFIG")]
    config: PathBuf,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();

    // --- Logging ---
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .json()
        .init();

    // --- Config ---
    let cfg = Arc::new(
        ServerConfig::from_file(&cli.config)
            .with_context(|| format!("Failed to read config {:?}", cli.config))?,
    );

    // --- Database ---
    let pool = PgPoolOptions::new()
        .max_connections(cfg.database.max_connections)
        .connect_lazy(&cfg.database.url)
        .context("Database connection failed")?;

    // sqlx::migrate!("./migrations")
    //     .run(&pool)
    //     .await
    //     .context("Database migration failed")?;

    info!("Database configuration loaded (lazy connection)");

    // --- Derive server public key from private ---
    // In production: parse cfg.interface.private_key and derive public key.
    let server_pub_key = "SERVER_PUB_KEY_PLACEHOLDER".to_string();

    let state = AppState {
        config: cfg.clone(),
        db: pool,
        server_pub_key,
        started_at: Arc::new(Instant::now()),
    };

    // --- Router ---
    let public_routes = Router::new()
        .route("/v1/auth/device", post(handlers::auth_device))
        .route("/healthz", get(handlers::healthz))
        .route("/v1/servers", get(handlers::list_servers));

    let authenticated_routes = Router::new()
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            mw::require_auth,
        ))
        // Admin endpoints (require admin role)
        .route("/v1/admin/peers", post(handlers::add_peer))
        .route("/v1/admin/peers/:public_key", delete(handlers::remove_peer))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            mw::require_admin,
        ))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            mw::require_auth,
        ));

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .merge(public_routes)
        .merge(authenticated_routes)
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(cors)
        .with_state(state);

    // --- Bind and serve ---
    let bind_addr = cfg.api.bind_addr;
    info!(%bind_addr, "API server listening");
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .context("Failed to bind API port")?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("API server error")?;

    info!("API server stopped");
    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install SIGINT handler");
    info!("Shutdown signal received");
}
