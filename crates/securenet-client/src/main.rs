//! `sn` — SecureNet VPN CLI client.
//!
//! Usage:
//!   sn init                     Bootstrap local config via API provisioning
//!   sn up   [--config <path>]   Connect to the VPN
//!   sn down [--config <path>]   Disconnect
//!   sn status                   Show connection status
//!   sn keygen                   Generate a fresh key-pair and print it
//!   sn servers                  List available servers
//!   sn connect                  Select a server, provision, and connect

use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use securenet_core::{
    config::{ClientConfig, InterfaceConfig, LoggingConfig, PeerConfig},
    crypto::KeyPair,
    tun_device::TunDevice,
    tunnel::Tunnel,
};

#[derive(serde::Serialize)]
struct WritableClientConfig {
    interface: WritableInterfaceConfig,
    server: WritablePeerConfig,
    logging: LoggingConfig,
    kill_switch: bool,
    auto_reconnect: bool,
    split_tunnel: Vec<String>,
}

#[derive(serde::Serialize)]
struct WritableInterfaceConfig {
    private_key: String,
    listen_addr: SocketAddr,
    address: String,
    tun_name: String,
    mtu: u16,
    dns: Vec<String>,
    post_up: Vec<String>,
    post_down: Vec<String>,
}

#[derive(serde::Serialize)]
struct WritablePeerConfig {
    name: String,
    public_key: String,
    pre_shared_key: Option<String>,
    endpoint: Option<SocketAddr>,
    allowed_ips: Vec<String>,
    persistent_keepalive: Option<u16>,
}

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "sn",
    about = "SecureNet VPN client",
    version,
    propagate_version = true
)]
struct Cli {
    /// Path to the client configuration file.
    #[arg(
        short,
        long,
        default_value = "~/.config/securenet/client.toml",
        env = "SECURENET_CLIENT_CONFIG"
    )]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Bootstrap client config from API provisioning (no manual config edits).
    Init {
        /// API base URL.
        #[arg(long, env = "SECURENET_API_URL")]
        api_url: String,
        /// Optional bearer token.
        #[arg(long, env = "SECURENET_TOKEN")]
        token: Option<String>,
        /// Optional target server ID.
        #[arg(long)]
        server_id: Option<Uuid>,
        /// Optional device label.
        #[arg(long)]
        device_name: Option<String>,
    },
    /// Connect to the VPN server.
    Up {
        /// Override server endpoint (host:port).
        #[arg(long)]
        endpoint: Option<String>,
    },
    /// Disconnect from the VPN server.
    Down,
    /// Show current connection status.
    Status,
    /// Generate a new Curve25519 key-pair and print public + private keys.
    Keygen,
    /// List available VPN servers from the API.
    Servers {
        /// API base URL (e.g. https://api.securenet.example.com).
        #[arg(long, env = "SECURENET_API_URL")]
        api_url: String,
        /// Optional bearer token.
        #[arg(long, env = "SECURENET_TOKEN")]
        token: Option<String>,
    },
    /// Interactive prompt to select a server, provision config, and connect.
    Connect {
        /// API base URL.
        #[arg(long, env = "SECURENET_API_URL")]
        api_url: String,
        /// Optional bearer token.
        #[arg(long, env = "SECURENET_TOKEN")]
        token: Option<String>,
    },
}

#[derive(Debug, serde::Deserialize)]
struct ServerEntry {
    id: Uuid,
    name: String,
    country: String,
    city: String,
    endpoint: String,
    load_percent: u8,
    latency_ms: Option<u32>,
    plan: String,
}

#[derive(serde::Serialize)]
struct ProvisionRequest {
    client_public_key: String,
    server_id: Option<Uuid>,
    device_name: Option<String>,
}

#[derive(serde::Deserialize)]
struct ProvisionResponse {
    server_public_key: String,
    server_endpoint: String,
    tunnel_ip: String,
    pre_shared_key: Option<String>,
    persistent_keepalive: Option<u16>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .compact()
        .init();

    match cli.command {
        Command::Init {
            api_url,
            token,
            server_id,
            device_name,
        } => {
            cmd_init(
                &cli.config,
                &api_url,
                token.as_deref(),
                server_id,
                device_name,
            )
            .await
        }
        Command::Keygen => cmd_keygen(),
        Command::Up { endpoint } => cmd_up(&cli.config, endpoint).await,
        Command::Down => cmd_down().await,
        Command::Status => cmd_status().await,
        Command::Servers { api_url, token } => cmd_servers(&api_url, token.as_deref()).await,
        Command::Connect { api_url, token } => {
            cmd_connect(&cli.config, &api_url, token.as_deref()).await
        }
    }
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

fn cmd_keygen() -> Result<()> {
    let kp = KeyPair::generate();
    println!("private_key = \"{}\"", kp.private.to_base64());
    println!("public_key  = \"{}\"", kp.public.to_base64());
    println!();
    println!("# Share only the public key with your control-plane API.");
    println!("# Keep the private key SECRET — never share it.");
    Ok(())
}

// ---------------------------------------------------------------------------
// init (API provisioning)
// ---------------------------------------------------------------------------

async fn cmd_init(
    config_path: &PathBuf,
    api_url: &str,
    token: Option<&str>,
    server_id: Option<Uuid>,
    device_name: Option<String>,
) -> Result<()> {
    let resolved_path = resolve_path(config_path);
    let seed = load_existing_or_default(&resolved_path);
    let merged = provision_client_config(seed, api_url, token, server_id, device_name).await?;
    save_client_config(&resolved_path, &merged)?;

    println!("Provisioning complete.");
    println!("Config written: {}", resolved_path.display());
    println!("Assigned tunnel IP: {}", merged.interface.address);
    println!(
        "Server endpoint: {}",
        merged
            .server
            .endpoint
            .map(|s| s.to_string())
            .unwrap_or_else(|| "<none>".to_string())
    );

    Ok(())
}

async fn provision_client_config(
    mut seed: ClientConfig,
    api_url: &str,
    token: Option<&str>,
    server_id: Option<Uuid>,
    device_name: Option<String>,
) -> Result<ClientConfig> {
    let key_pair = KeyPair::generate();

    let req = ProvisionRequest {
        client_public_key: key_pair.public.to_base64(),
        server_id,
        device_name,
    };

    let client = reqwest::Client::new();
    let mut request = client.post(format!("{api_url}/v1/provision")).json(&req);
    if let Some(t) = token {
        request = request.bearer_auth(t);
    }

    let resp = request.send().await.context("API request failed")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        error!(%status, %body, "Provisioning API error");
        anyhow::bail!("Provisioning API returned {status}");
    }

    let provisioned: ProvisionResponse = resp
        .json()
        .await
        .context("Failed to parse provisioning response")?;

    seed.interface.private_key = key_pair.private.to_base64();
    seed.interface.address = provisioned.tunnel_ip;
    seed.server.public_key = provisioned.server_public_key;
    seed.server.endpoint = Some(
        provisioned
            .server_endpoint
            .parse()
            .context("Invalid server endpoint from provisioning")?,
    );
    seed.server.pre_shared_key = provisioned.pre_shared_key;
    seed.server.persistent_keepalive = provisioned.persistent_keepalive;

    Ok(seed)
}

fn load_existing_or_default(config_path: &Path) -> ClientConfig {
    if config_path.exists() {
        if let Ok(cfg) = ClientConfig::from_file(&config_path.to_path_buf()) {
            return cfg;
        }
    }

    ClientConfig {
        interface: InterfaceConfig {
            private_key: String::new(),
            listen_addr: "0.0.0.0:0"
                .parse::<SocketAddr>()
                .expect("default socket address must be valid"),
            address: "10.0.0.2/32".to_string(),
            tun_name: "wg0".to_string(),
            mtu: 1420,
            dns: vec!["1.1.1.1".to_string(), "9.9.9.9".to_string()],
            post_up: vec![],
            post_down: vec![],
        },
        server: PeerConfig {
            name: "provisioned-server".to_string(),
            public_key: String::new(),
            pre_shared_key: None,
            endpoint: None,
            allowed_ips: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
            persistent_keepalive: Some(25),
        },
        logging: LoggingConfig {
            level: "info".to_string(),
            format: "compact".to_string(),
            file: None,
        },
        kill_switch: true,
        auto_reconnect: true,
        split_tunnel: vec![],
    }
}

fn save_client_config(path: &Path, cfg: &ClientConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create config directory {}", parent.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).ok();
        }
    }

    let writable = WritableClientConfig {
        interface: WritableInterfaceConfig {
            private_key: cfg.interface.private_key.clone(),
            listen_addr: cfg.interface.listen_addr,
            address: cfg.interface.address.clone(),
            tun_name: cfg.interface.tun_name.clone(),
            mtu: cfg.interface.mtu,
            dns: cfg.interface.dns.clone(),
            post_up: cfg.interface.post_up.clone(),
            post_down: cfg.interface.post_down.clone(),
        },
        server: WritablePeerConfig {
            name: cfg.server.name.clone(),
            public_key: cfg.server.public_key.clone(),
            pre_shared_key: cfg.server.pre_shared_key.clone(),
            endpoint: cfg.server.endpoint,
            allowed_ips: cfg.server.allowed_ips.clone(),
            persistent_keepalive: cfg.server.persistent_keepalive,
        },
        logging: cfg.logging.clone(),
        kill_switch: cfg.kill_switch,
        auto_reconnect: cfg.auto_reconnect,
        split_tunnel: cfg.split_tunnel.clone(),
    };

    let toml = toml::to_string_pretty(&writable).context("Failed to serialize client config")?;
    fs::write(path, toml).with_context(|| format!("Failed to write {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).ok();
    }

    Ok(())
}

fn resolve_path(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    if let Some(stripped) = path_str.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(stripped);
        }
    }
    path.to_path_buf()
}

// ---------------------------------------------------------------------------
// up
// ---------------------------------------------------------------------------

async fn cmd_up(config_path: &PathBuf, endpoint_override: Option<String>) -> Result<()> {
    let resolved_path = resolve_path(config_path);
    let cfg = ClientConfig::from_file(&resolved_path)
        .with_context(|| format!("Failed to read config {:?}", resolved_path))?;

    // Override endpoint if supplied on the command line
    let mut server_peer = cfg.server.clone();
    if let Some(ep) = endpoint_override {
        server_peer.endpoint = Some(ep.parse().context("Invalid endpoint address")?);
    }

    info!(server = ?server_peer.endpoint, "Connecting to SecureNet VPN");

    // Load our key pair
    let key_pair = KeyPair::from_private_key_base64(&cfg.interface.private_key)
        .context("Invalid interface private_key")?;

    let tun = TunDevice::create(
        &cfg.interface.tun_name,
        &cfg.interface.address,
        cfg.interface.mtu,
    )
    .context("Failed to create TUN device")?;
    info!(tun = %tun.name(), "TUN device created");

    // Start the tunnel
    let tunnel = Tunnel::start(key_pair, cfg.interface.listen_addr, vec![server_peer])
        .await
        .context("Failed to start tunnel")?;

    info!("VPN tunnel established");

    // TUN -> WireGuard
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
                        error!(err = %e, "Failed to send packet to peer");
                    }
                }
                Err(e) => {
                    error!(err = %e, "TUN recv error");
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
            }
        }
    });

    // WireGuard -> TUN
    let tun_tx = tun.clone();
    let tunnel_rx = tunnel.clone();
    let net_to_tun = tokio::spawn(async move {
        loop {
            match tunnel_rx.recv_packet().await {
                Ok((pkt, _peer_key)) => {
                    if let Err(e) = tun_tx.send(&pkt).await {
                        error!(err = %e, "Failed to write packet to TUN");
                    }
                }
                Err(e) => {
                    error!(err = %e, "Packet receive error");
                }
            }
        }
    });

    if cfg.kill_switch {
        apply_kill_switch(&cfg.interface.tun_name).await?;
    }

    tokio::signal::ctrl_c().await?;

    info!("Disconnecting…");
    tun_to_net.abort();
    net_to_tun.abort();
    if cfg.kill_switch {
        remove_kill_switch(&cfg.interface.tun_name).await?;
    }
    info!("Disconnected");
    Ok(())
}

// ---------------------------------------------------------------------------
// down
// ---------------------------------------------------------------------------

async fn cmd_down() -> Result<()> {
    // In production: send SIGTERM to the running `sn up` process via a
    // PID file at /run/securenet/client.pid.
    println!("Use Ctrl-C in the `sn up` session, or kill the process.");
    Ok(())
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

async fn cmd_status() -> Result<()> {
    // In production: query a local Unix socket or shared memory segment.
    println!("Status: no tunnel running (or not implemented in this build).");
    Ok(())
}

// ---------------------------------------------------------------------------
// servers
// ---------------------------------------------------------------------------

async fn cmd_servers(api_url: &str, token: Option<&str>) -> Result<()> {
    let client = reqwest::Client::new();
    let mut request = client.get(format!("{api_url}/v1/servers"));
    if let Some(t) = token {
        request = request.bearer_auth(t);
    }

    let resp = request.send().await.context("API request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        error!(%status, %body, "API error");
        return Err(anyhow::anyhow!("API returned {status}"));
    }

    let servers: serde_json::Value = resp.json().await.context("JSON parse failed")?;
    println!("{}", serde_json::to_string_pretty(&servers)?);
    Ok(())
}

// ---------------------------------------------------------------------------
// connect (Interactive Selection + Provision)
// ---------------------------------------------------------------------------

async fn cmd_connect(config_path: &PathBuf, api_url: &str, token: Option<&str>) -> Result<()> {
    let client = reqwest::Client::new();
    let mut request = client.get(format!("{api_url}/v1/servers"));
    if let Some(t) = token {
        request = request.bearer_auth(t);
    }

    let resp = request.send().await.context("API request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        error!(%status, %body, "API error fetching servers");
        return Err(anyhow::anyhow!("API returned {status}"));
    }

    let servers: Vec<ServerEntry> = resp.json().await.context("Failed to parse server list")?;

    if servers.is_empty() {
        println!("No servers available.");
        return Ok(());
    }

    let items: Vec<String> = servers
        .iter()
        .map(|s| {
            let latency = s
                .latency_ms
                .map(|l| format!("{}ms", l))
                .unwrap_or_else(|| "?".to_string());
            format!(
                "[{}] {} ({} - load: {}%, plan: {})",
                s.country, s.name, latency, s.load_percent, s.plan
            )
        })
        .collect();

    let selection = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt("Select a VPN server to connect to")
        .default(0)
        .items(&items)
        .interact()
        .context("Failed to render interactive menu")?;

    let selected_server = &servers[selection];
    println!(
        "Selected: {} ({}, {})",
        selected_server.name, selected_server.city, selected_server.endpoint
    );

    let resolved_path = resolve_path(config_path);
    let seed = load_existing_or_default(&resolved_path);
    let merged = provision_client_config(
        seed,
        api_url,
        token,
        Some(selected_server.id),
        Some(selected_server.name.clone()),
    )
    .await?;
    save_client_config(&resolved_path, &merged)?;

    info!("Provisioning complete, starting tunnel");
    cmd_up(&resolved_path, None).await
}

// ---------------------------------------------------------------------------
// Kill-switch helpers (Linux iptables)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
async fn apply_kill_switch(tun_name: &str) -> Result<()> {
    info!(%tun_name, "Applying kill-switch");
    let rules = vec![
        format!("iptables -I OUTPUT ! -o {tun_name} -m mark ! --mark 0xCAFE -j DROP"),
        format!("ip6tables -I OUTPUT ! -o {tun_name} -m mark ! --mark 0xCAFE -j DROP"),
    ];
    for rule in rules {
        run_cmd("sh", &["-c", &rule]).await?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn remove_kill_switch(tun_name: &str) -> Result<()> {
    info!(%tun_name, "Removing kill-switch");
    let rules = vec![
        format!("iptables -D OUTPUT ! -o {tun_name} -m mark ! --mark 0xCAFE -j DROP"),
        format!("ip6tables -D OUTPUT ! -o {tun_name} -m mark ! --mark 0xCAFE -j DROP"),
    ];
    for rule in rules {
        run_cmd("sh", &["-c", &rule]).await.ok(); // best-effort on shutdown
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn run_cmd(prog: &str, args: &[&str]) -> Result<()> {
    let status = tokio::process::Command::new(prog)
        .args(args)
        .status()
        .await
        .context("Failed to run command")?;
    if !status.success() {
        anyhow::bail!("Command failed with {:?}", status.code());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn apply_kill_switch(_tun_name: &str) -> Result<()> {
    info!("Kill-switch is currently supported only on Linux");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn remove_kill_switch(_tun_name: &str) -> Result<()> {
    Ok(())
}
