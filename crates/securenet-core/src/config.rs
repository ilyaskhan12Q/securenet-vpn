//! Configuration types for SecureNet.
//!
//! Supports loading from a TOML file, environment variables, or a builder.
//! All secret fields are marked `#[serde(skip_serializing)]` so they are
//! never accidentally serialised to a log or API response.

use std::{net::SocketAddr, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};

// ---------------------------------------------------------------------------
// Top-level server configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub interface: InterfaceConfig,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    pub api: ApiConfig,
    pub database: DatabaseConfig,
    pub logging: LoggingConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
}

impl ServerConfig {
    /// Load configuration from a TOML file at `path`.
    pub fn from_file(path: &PathBuf) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| CoreError::ConfigParse(e.to_string()))?;
        toml::from_str(&raw).map_err(|e| CoreError::ConfigParse(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// WireGuard interface
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InterfaceConfig {
    /// Base64-encoded private key for this interface.
    #[serde(skip_serializing)]
    pub private_key: String,

    /// UDP listen address (e.g. "0.0.0.0:51820").
    pub listen_addr: SocketAddr,

    /// Inner tunnel IP address + prefix length (e.g. "10.0.0.1/24").
    pub address: String,

    /// TUN device name (e.g. "wg0", "utun5").
    #[serde(default = "default_tun_name")]
    pub tun_name: String,

    /// Interface MTU.
    #[serde(default = "default_mtu")]
    pub mtu: u16,

    /// DNS servers to push to clients.
    #[serde(default)]
    pub dns: Vec<String>,

    /// iptables / nftables post-up commands (shell).
    #[serde(default)]
    pub post_up: Vec<String>,

    /// iptables / nftables post-down commands (shell).
    #[serde(default)]
    pub post_down: Vec<String>,
}

fn default_tun_name() -> String {
    "wg0".to_string()
}

fn default_mtu() -> u16 {
    1420
}

// ---------------------------------------------------------------------------
// Peer configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PeerConfig {
    /// Human-readable label (not transmitted on the wire).
    #[serde(default)]
    pub name: String,

    /// Base64-encoded Curve25519 public key.
    pub public_key: String,

    /// Optional pre-shared key for PSK mode (Base64).
    #[serde(skip_serializing, default)]
    pub pre_shared_key: Option<String>,

    /// Remote UDP endpoint ("1.2.3.4:51820"). `None` for roaming clients.
    #[serde(default)]
    pub endpoint: Option<SocketAddr>,

    /// IP networks from which this peer may send traffic.
    pub allowed_ips: Vec<String>,

    /// Persistent keepalive interval in seconds (0 = disabled).
    #[serde(default)]
    pub persistent_keepalive: Option<u16>,
}

// ---------------------------------------------------------------------------
// API server
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiConfig {
    /// Bind address for the REST API (e.g. "127.0.0.1:8080").
    pub bind_addr: SocketAddr,

    /// HMAC-SHA256 secret for JWT signing.
    #[serde(skip_serializing)]
    pub jwt_secret: String,

    /// JWT token validity in seconds.
    #[serde(default = "default_token_ttl")]
    pub token_ttl_secs: u64,

    /// Enable TLS for the API server (requires `tls_cert` and `tls_key`).
    #[serde(default)]
    pub tls_enabled: bool,

    #[serde(default)]
    pub tls_cert: Option<PathBuf>,

    #[serde(default)]
    pub tls_key: Option<PathBuf>,

    /// Maximum requests per second per IP for the auth endpoint.
    #[serde(default = "default_rate_limit")]
    pub rate_limit_rps: u32,
}

fn default_token_ttl() -> u64 {
    3600
}

fn default_rate_limit() -> u32 {
    10
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    /// PostgreSQL connection URL.
    #[serde(skip_serializing)]
    pub url: String,

    /// Maximum connection pool size.
    #[serde(default = "default_pool_size")]
    pub max_connections: u32,
}

fn default_pool_size() -> u32 {
    20
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    /// Log level filter string (e.g. "info,securenet_core=debug").
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Output format: "pretty" | "json" | "compact".
    #[serde(default = "default_log_format")]
    pub format: String,

    /// Optional file path for log rotation.
    #[serde(default)]
    pub file: Option<PathBuf>,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    /// Expose Prometheus /metrics endpoint.
    #[serde(default = "bool_true")]
    pub enabled: bool,

    /// Bind address for the metrics endpoint.
    #[serde(default = "default_metrics_addr")]
    pub bind_addr: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_addr: default_metrics_addr(),
        }
    }
}

fn bool_true() -> bool {
    true
}

fn default_metrics_addr() -> String {
    "127.0.0.1:9090".to_string()
}

// ---------------------------------------------------------------------------
// Client configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientConfig {
    pub interface: InterfaceConfig,
    pub server: PeerConfig,
    pub logging: LoggingConfig,
    /// Kill-switch: block all non-VPN traffic if tunnel drops.
    #[serde(default = "bool_true")]
    pub kill_switch: bool,
    /// Auto-reconnect on disconnection.
    #[serde(default = "bool_true")]
    pub auto_reconnect: bool,
    /// Split-tunnel: route only these CIDRs through the VPN.
    #[serde(default)]
    pub split_tunnel: Vec<String>,
}

impl ClientConfig {
    pub fn from_file(path: &PathBuf) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| CoreError::ConfigParse(e.to_string()))?;
        toml::from_str(&raw).map_err(|e| CoreError::ConfigParse(e.to_string()))
    }
}
