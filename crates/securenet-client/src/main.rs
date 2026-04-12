//! `sn` — SecureNet VPN CLI client.
//!
//! Usage:
//!   sn up   [--config <path>]   Connect to the VPN
//!   sn down [--config <path>]   Disconnect
//!   sn status                   Show connection status
//!   sn keygen                   Generate a fresh key-pair and print it
//!   sn servers                  List available servers

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use securenet_core::{
    config::ClientConfig,
    crypto::{KeyPair, PeerPublicKey},
    tunnel::Tunnel,
};

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
    #[arg(short, long, default_value = "~/.config/securenet/client.toml", env = "SECURENET_CLIENT_CONFIG")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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
        /// Bearer token (obtain via `sn auth`).
        #[arg(long, env = "SECURENET_TOKEN")]
        token: String,
    },
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
        Command::Keygen => cmd_keygen(),
        Command::Up { endpoint } => cmd_up(&cli.config, endpoint).await,
        Command::Down => cmd_down().await,
        Command::Status => cmd_status().await,
        Command::Servers { api_url, token } => cmd_servers(&api_url, &token).await,
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
    println!("# Add the public_key to your server's [[peers]] section.");
    println!("# Keep the private_key SECRET — never share it.");
    Ok(())
}

// ---------------------------------------------------------------------------
// up
// ---------------------------------------------------------------------------

async fn cmd_up(config_path: &PathBuf, endpoint_override: Option<String>) -> Result<()> {
    let cfg = ClientConfig::from_file(config_path)
        .with_context(|| format!("Failed to read config {:?}", config_path))?;

    // Override endpoint if supplied on the command line
    let mut server_peer = cfg.server.clone();
    if let Some(ep) = endpoint_override {
        server_peer.endpoint = Some(ep.parse().context("Invalid endpoint address")?);
    }

    info!(
        server = ?server_peer.endpoint,
        "Connecting to SecureNet VPN"
    );

    // Load our key pair
    let key_pair = securenet_core::crypto::KeyPair::generate();
    // In production: load from cfg.interface.private_key

    // Start the tunnel
    let _tunnel = Tunnel::start(
        key_pair,
        cfg.interface.listen_addr,
        vec![server_peer],
    )
    .await
    .context("Failed to start tunnel")?;

    info!("VPN tunnel established");

    // Apply kill-switch if configured (Linux: default route via tunnel)
    if cfg.kill_switch {
        apply_kill_switch(&cfg.interface.tun_name).await?;
    }

    // Block until SIGINT
    tokio::signal::ctrl_c().await?;

    info!("Disconnecting…");
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

async fn cmd_servers(api_url: &str, token: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{api_url}/v1/servers"))
        .bearer_auth(token)
        .send()
        .await
        .context("API request failed")?;

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
// Kill-switch helpers (Linux iptables)
// ---------------------------------------------------------------------------

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
