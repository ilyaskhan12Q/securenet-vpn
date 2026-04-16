//! `securenet-server` — the SecureNet VPN server daemon.
//!
//! ## Responsibilities
//!   - Reads a TOML configuration file (or falls back to env vars).
//!   - Initialises the userspace WireGuard tunnel.
//!   - Applies iptables NAT / routing rules via shell post-up hooks.
//!   - Exposes Prometheus metrics on a separate port.
//!   - Handles SIGINT / SIGTERM gracefully (post-down hooks, flush peers).

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use clap::Parser;
use prometheus::{
    register_counter_vec, register_histogram_vec, CounterVec, Encoder, HistogramVec, TextEncoder,
};
use sqlx::postgres::PgPoolOptions;
use tokio::{signal, sync::watch, time};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use securenet_core::{
    config::{PeerConfig, ServerConfig}, crypto::KeyPair, tun_device::TunDevice, tunnel::Tunnel,
};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "securenet-server",
    about = "SecureNet VPN Server Daemon",
    version
)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(
        short,
        long,
        default_value = "/etc/securenet/server.toml",
        env = "SECURENET_CONFIG"
    )]
    config: PathBuf,

    /// Override log level (e.g. debug, info, warn).
    #[arg(long, env = "SECURENET_LOG")]
    log_level: Option<String>,

    /// Print a blank configuration template to stdout and exit.
    #[arg(long)]
    print_config: bool,
}

// ---------------------------------------------------------------------------
// Prometheus metrics
// ---------------------------------------------------------------------------

struct Metrics {
    #[allow(dead_code)]
    packets_tx: CounterVec,
    #[allow(dead_code)]
    packets_rx: CounterVec,
    #[allow(dead_code)]
    bytes_tx: CounterVec,
    #[allow(dead_code)]
    bytes_rx: CounterVec,
    #[allow(dead_code)]
    handshake_latency: HistogramVec,
}

impl Metrics {
    fn new() -> Result<Self> {
        Ok(Self {
            #[allow(dead_code)]
            packets_tx: register_counter_vec!(
                "securenet_packets_transmitted_total",
                "Total WireGuard packets sent",
                &["peer"]
            )?,
            #[allow(dead_code)]
            packets_rx: register_counter_vec!(
                "securenet_packets_received_total",
                "Total WireGuard packets received",
                &["peer"]
            )?,
            #[allow(dead_code)]
            bytes_tx: register_counter_vec!(
                "securenet_bytes_transmitted_total",
                "Total bytes sent through the tunnel",
                &["peer"]
            )?,
            #[allow(dead_code)]
            bytes_rx: register_counter_vec!(
                "securenet_bytes_received_total",
                "Total bytes received through the tunnel",
                &["peer"]
            )?,
            #[allow(dead_code)]
            handshake_latency: register_histogram_vec!(
                "securenet_handshake_duration_seconds",
                "WireGuard handshake round-trip latency",
                &["peer"],
                vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
            )?,
        })
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();

    if cli.print_config {
        print_config_template();
        return Ok(());
    }

    // --- Logging ---
    let log_level = cli
        .log_level
        .as_deref()
        .unwrap_or("info,securenet_core=debug");

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(log_level))
        .json()
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "SecureNet server starting"
    );

    // --- Config ---
    let cfg = ServerConfig::from_file(&cli.config)
        .with_context(|| format!("Failed to load config from {:?}", cli.config))?;

    // --- Key pair ---
    let key_pair = KeyPair::from_private_key_base64(&cfg.interface.private_key)
        .context("Invalid interface private_key")?;
    info!(
        pub_key = %key_pair.public.to_base64(),
        listen = %cfg.interface.listen_addr,
        "Interface initialised"
    );

    // --- TUN device ---
    let tun = TunDevice::create(
        &cfg.interface.tun_name,
        &cfg.interface.address,
        cfg.interface.mtu,
    )
    .context("Failed to create TUN device")?;
    info!(tun = %tun.name(), "TUN device created");

    // --- Tunnel ---
    let tunnel = Tunnel::start(key_pair, cfg.interface.listen_addr, cfg.peers.clone())
        .await
        .context("Failed to start WireGuard tunnel")?;

    // --- Database for pending peer queue ---
    let db_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_lazy(&cfg.database.url)
        .context("Failed to connect to database")?;
    info!("Connected to peer queue database");

    // --- Peer queue poller ---
    let tunnel_clone = tunnel.clone();
    let db_pool_clone = db_pool.clone();
    tokio::spawn(async move {
        peer_queue_poller(tunnel_clone, db_pool_clone).await;
    });

    // --- Run post-up hooks ---
    run_hooks(&cfg.interface.post_up, "post-up").await;

    // --- Metrics server ---
    let metrics = Arc::new(Metrics::new().context("Prometheus registry error")?);
    if cfg.metrics.enabled {
        let bind: std::net::SocketAddr = cfg
            .metrics
            .bind_addr
            .parse()
            .context("Invalid metrics bind address")?;
        tokio::spawn(run_metrics_server(bind));
        info!(%bind, "Prometheus metrics endpoint started");
    }

    // --- Graceful shutdown ---
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    let _shutdown_handle = tokio::spawn(async move {
        match signal::ctrl_c().await {
            Ok(()) => info!("SIGINT received, shutting down"),
            Err(e) => error!(err = %e, "Failed to listen for SIGINT"),
        }
        let _ = shutdown_tx.send(true);
    });

    // --- Main data-plane loops ---
    let tun_rx = tun.clone();
    let tunnel_tx = tunnel.clone();
    let tun_to_net = tokio::spawn(async move {
        let mut buf = vec![0u8; securenet_core::crypto::MAX_PACKET];
        loop {
            match tun_rx.recv(&mut buf).await {
                Ok(n) => {
                    if n == 0 {
                        continue;
                    }
                    if let Err(e) = tunnel_tx.send_packet(&buf[..n]).await {
                        warn!(err = %e, "Failed to send packet to peer");
                    }
                }
                Err(e) => {
                    warn!(err = %e, "TUN recv error");
                    time::sleep(Duration::from_millis(250)).await;
                }
            }
        }
    });

    let tun_tx = tun.clone();
    let tunnel_rx = tunnel.clone();
    let metrics_clone = metrics.clone();
    let net_to_tun = tokio::spawn(async move {
        loop {
            match tunnel_rx.recv_packet().await {
                Ok((pkt, peer_key)) => {
                    let peer_hex = hex::encode(&peer_key[..4]);
                    metrics_clone
                        .packets_rx
                        .with_label_values(&[&peer_hex])
                        .inc();
                    metrics_clone
                        .bytes_rx
                        .with_label_values(&[&peer_hex])
                        .inc_by(pkt.len() as f64);
                    if let Err(e) = tun_tx.send(&pkt).await {
                        warn!(err = %e, "Failed to write packet to TUN");
                    }
                    trace_packet(&pkt);
                }
                Err(e) => {
                    warn!(err = %e, "Packet receive error");
                }
            }
        }
    });

    // Wait for shutdown signal
    shutdown_rx.changed().await.ok();

    // Cancel data plane
    tun_to_net.abort();
    net_to_tun.abort();

    // Run post-down hooks
    run_hooks(&cfg.interface.post_down, "post-down").await;

    info!("SecureNet server stopped cleanly");
    Ok(())
}

// ---------------------------------------------------------------------------
// Metrics HTTP server
// ---------------------------------------------------------------------------

async fn run_metrics_server(addr: std::net::SocketAddr) {
    use axum::{routing::get, Router};

    let app = Router::new().route("/metrics", get(metrics_handler));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Cannot bind metrics port");
    axum::serve(listener, app).await.unwrap();
}

async fn metrics_handler() -> String {
    let encoder = TextEncoder::new();
    let families = prometheus::gather();
    let mut buf = Vec::new();
    encoder.encode(&families, &mut buf).unwrap_or_default();
    String::from_utf8(buf).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Shell hook runner
// ---------------------------------------------------------------------------

async fn run_hooks(commands: &[String], stage: &str) {
    for cmd in commands {
        info!(%stage, %cmd, "Running hook");
        let status = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .status()
            .await;
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => warn!(%stage, %cmd, code = ?s.code(), "Hook exited non-zero"),
            Err(e) => error!(%stage, %cmd, err = %e, "Hook execution failed"),
        }
    }
}

// ---------------------------------------------------------------------------
// Peer queue poller
// ---------------------------------------------------------------------------

async fn peer_queue_poller(tunnel: Tunnel, pool: sqlx::PgPool) {
    let mut interval = time::interval(Duration::from_secs(2));

    loop {
        interval.tick().await;

        let result: Result<Option<(String, Option<String>, String, Option<i32>)>, sqlx::Error> = sqlx::query_as(
            r#"
            SELECT public_key, pre_shared_key, allowed_ips, persistent_keepalive
            FROM pending_peers
            WHERE status = 'pending'
            ORDER BY created_at ASC
            LIMIT 1
            "#,
        )
        .fetch_optional(&pool)
        .await;

        let Ok(Some((pub_key, psk, allowed_ips, keepalive))) = result else {
            continue;
        };

        let psk_opt: Option<&str> = psk.as_deref();

        let peer_cfg = PeerConfig {
            name: "dynamic-peer".to_string(),
            public_key: pub_key.clone(),
            pre_shared_key: psk_opt.map(String::from),
            endpoint: None,
            allowed_ips: allowed_ips.split(',').map(String::from).collect(),
            persistent_keepalive: keepalive.map(|k| k as u16),
        };

        match tunnel.add_peer(peer_cfg).await {
            Ok(()) => {
                info!(peer = %pub_key, "Added peer from pending queue");
                let _ = sqlx::query(
                    "UPDATE pending_peers SET status = 'applied', applied_at = NOW() WHERE public_key = $1"
                )
                .bind(&pub_key)
                .execute(&pool)
                .await;
            }
            Err(e) => {
                warn!(err = %e, peer = %pub_key, "Failed to add peer");
                let _ = sqlx::query(
                    "UPDATE pending_peers SET status = 'failed', error_message = $1 WHERE public_key = $2"
                )
                .bind(e.to_string())
                .bind(&pub_key)
                .execute(&pool)
                .await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Debug helper
// ---------------------------------------------------------------------------

fn trace_packet(pkt: &[u8]) {
    if pkt.len() < 20 {
        return;
    }
    let version = pkt[0] >> 4;
    tracing::trace!(version, len = pkt.len(), "Inner IP packet");
}

// ---------------------------------------------------------------------------
// Config template printer
// ---------------------------------------------------------------------------

fn print_config_template() {
    println!(
        r#"# SecureNet Server Configuration
# Generated by: securenet-server --print-config

[interface]
private_key  = "BASE64_PRIVATE_KEY"      # wg genkey | base64
listen_addr  = "0.0.0.0:51820"
address      = "10.0.0.1/24"
tun_name     = "wg0"
mtu          = 1420
dns          = ["1.1.1.1", "8.8.8.8"]
post_up      = [
    "iptables -A FORWARD -i wg0 -j ACCEPT",
    "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
]
post_down    = [
    "iptables -D FORWARD -i wg0 -j ACCEPT",
    "iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE",
]

[[peers]]
name                 = "client-001"
public_key           = "BASE64_CLIENT_PUBLIC_KEY"
pre_shared_key       = "BASE64_PSK"           # optional
allowed_ips          = ["10.0.0.2/32"]
persistent_keepalive = 25

[api]
bind_addr      = "127.0.0.1:8080"
jwt_secret     = "CHANGE_ME_LONG_RANDOM_STRING"
token_ttl_secs = 3600
tls_enabled    = false

[database]
url             = "postgres://securenet:secret@localhost:5432/securenet"
max_connections = 20

[logging]
level  = "info"
format = "json"

[metrics]
enabled   = true
bind_addr = "127.0.0.1:9090"
"#
    );
}
