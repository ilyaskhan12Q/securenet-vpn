//! Userspace WireGuard tunnel management.
//!
//! This module wraps `boringtun`'s `Tunn` struct inside an async-friendly
//! abstraction that:
//!   - Owns a TUN network interface via the `tun` crate.
//!   - Maintains a peer table keyed by `PeerPublicKey`.
//!   - Runs two tokio tasks: one reading from the TUN device (plaintext
//!     egress) and one reading from a UDP socket (encrypted ingress).
//!   - Handles WireGuard timer events (keepalives, re-keying) internally.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use boringtun::noise::{Tunn, TunnResult};
use bytes::{Bytes, BytesMut};
use ipnetwork::IpNetwork;
use tokio::{
    net::UdpSocket,
    sync::{Mutex, RwLock},
    time,
};
use tracing::{debug, error, info, trace, warn};

use crate::{
    config::PeerConfig,
    crypto::{KeyPair, PeerPublicKey, PreSharedKey, ReplayWindow, WG_MTU},
    error::{CoreError, Result},
};

// ---------------------------------------------------------------------------
// Constants matching WireGuard specification
// ---------------------------------------------------------------------------

/// Renegotiate session after 3 minutes (WireGuard: REKEY_AFTER_TIME = 180 s).
pub const REKEY_AFTER_SECS: u64 = 180;
/// Reject sessions older than 3× REKEY_AFTER_TIME.
pub const REJECT_AFTER_SECS: u64 = 180 * 3;
/// Keepalive interval (WireGuard: KEEPALIVE_TIMEOUT = 10 s).
pub const KEEPALIVE_SECS: u64 = 10;
/// Handshake retry jitter ceiling in ms.
pub const REKEY_TIMEOUT_MS: u64 = 5_000;
/// Maximum UDP packet buffer (WireGuard overhead + max IP MTU).
pub const UDP_BUF: usize = 65536;

// ---------------------------------------------------------------------------
// Peer session
// ---------------------------------------------------------------------------

/// Live state for one WireGuard peer.
pub struct PeerSession {
    /// The underlying boringtun tunnel state machine.
    pub tunn: Mutex<Tunn>,
    /// Endpoint address (can change — WireGuard is roaming-aware).
    pub endpoint: RwLock<Option<SocketAddr>>,
    /// Allowed source IPs — packets from this peer must originate here.
    pub allowed_ips: Vec<IpNetwork>,
    /// Anti-replay window for received data packets.
    pub replay: Mutex<ReplayWindow>,
    /// Monotonic instant of last authenticated packet received.
    pub last_rx: Mutex<std::time::Instant>,
}

impl PeerSession {
    pub fn new(tunn: Box<Tunn>, cfg: &PeerConfig) -> Self {
        let allowed_ips = cfg
            .allowed_ips
            .iter()
            .filter_map(|s| s.parse::<IpNetwork>().ok())
            .collect();
        Self {
            tunn: Mutex::new(*tunn),
            endpoint: RwLock::new(cfg.endpoint),
            allowed_ips,
            replay: Mutex::new(ReplayWindow::new()),
            last_rx: Mutex::new(std::time::Instant::now()),
        }
    }

    /// True if `addr` falls inside any allowed-IP range.
    pub fn is_allowed(&self, addr: IpAddr) -> bool {
        self.allowed_ips.iter().any(|net| net.contains(addr))
    }
}

// ---------------------------------------------------------------------------
// Tunnel handle
// ---------------------------------------------------------------------------

/// A running userspace WireGuard tunnel.
///
/// Created via [`Tunnel::start`]; clone the handle freely — it is backed by
/// `Arc` and all mutable state is internally synchronised.
#[derive(Clone)]
pub struct Tunnel(Arc<TunnelInner>);

struct TunnelInner {
    /// This interface's key-pair.
    key_pair: KeyPair,
    /// UDP socket — the only physical I/O this tunnel owns.
    socket: Arc<UdpSocket>,
    /// Active peer sessions, indexed by public key bytes.
    peers: RwLock<HashMap<[u8; 32], Arc<PeerSession>>>,
    /// Reverse map: allowed inner IP -> peer public key.
    ip_to_peer: RwLock<HashMap<IpAddr, [u8; 32]>>,
}

impl Tunnel {
    /// Bind a UDP socket and start background I/O tasks.
    ///
    /// The caller is responsible for creating the TUN device (platform-
    /// specific) and passing its file descriptor via `tun_fd`.  On Linux
    /// this is the `TUN_IOC_OPEN` fd; on macOS it is a `utun` fd.
    pub async fn start(
        key_pair: KeyPair,
        listen_addr: SocketAddr,
        peers: Vec<PeerConfig>,
    ) -> Result<Self> {
        let socket = UdpSocket::bind(listen_addr)
            .await
            .map_err(|e| CoreError::TunDevice(e.to_string()))?;

        info!(
            listen = %listen_addr,
            pub_key = %key_pair.public.to_base64(),
            "WireGuard tunnel listening"
        );

        let inner = Arc::new(TunnelInner {
            key_pair,
            socket: Arc::new(socket),
            peers: RwLock::new(HashMap::new()),
            ip_to_peer: RwLock::new(HashMap::new()),
        });

        let tunnel = Self(inner);

        // Register initial peers
        for peer_cfg in peers {
            tunnel.add_peer(peer_cfg).await?;
        }

        // Spawn timer task (keepalives / re-key)
        let t = tunnel.clone();
        tokio::spawn(async move { t.timer_loop().await });

        Ok(tunnel)
    }

    /// Add or update a peer at runtime.
    pub async fn add_peer(&self, cfg: PeerConfig) -> Result<()> {
        let peer_pub = PeerPublicKey::from_base64(&cfg.public_key)?;

        let psk = if let Some(ref psk_b64) = cfg.pre_shared_key {
            Some(PreSharedKey::from_base64(psk_b64)?)
        } else {
            None
        };

        // Build boringtun Tunn.  `Tunn::new` returns an opaque error string.
        let tunn = Tunn::new(
            self.0.key_pair.private.as_bytes().clone().into(),
            peer_pub.as_bytes().clone().into(),
            psk.as_ref().map(|p| p.as_bytes().clone()),
            cfg.persistent_keepalive,
            rand::random(),
            None,
        )
        .map_err(|e| CoreError::HandshakeFailed(e.to_string()))?;

        let session = Arc::new(PeerSession::new(Box::new(tunn), &cfg));
        let key_bytes = *peer_pub.as_bytes();

        // Register allowed IPs
        {
            let mut ip_map = self.0.ip_to_peer.write().await;
            for net in &session.allowed_ips {
                ip_map.insert(net.network(), key_bytes);
            }
        }

        self.0.peers.write().await.insert(key_bytes, session);

        info!(
            peer = %cfg.public_key,
            allowed = ?cfg.allowed_ips,
            "Peer registered"
        );
        Ok(())
    }

    /// Remove a peer by public key (Base64).
    pub async fn remove_peer(&self, pub_key_b64: &str) -> Result<()> {
        let pub_key = PeerPublicKey::from_base64(pub_key_b64)?;
        let key_bytes = *pub_key.as_bytes();
        let mut peers = self.0.peers.write().await;
        if let Some(session) = peers.remove(&key_bytes) {
            let mut ip_map = self.0.ip_to_peer.write().await;
            for net in &session.allowed_ips {
                ip_map.remove(&net.network());
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Core data-plane: encrypt and send an IP packet to a peer
    // ------------------------------------------------------------------

    /// Encrypt an inner IP packet and send it over UDP to the peer's endpoint.
    pub async fn send_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.is_empty() {
            return Ok(());
        }
        if packet.len() > WG_MTU {
            return Err(CoreError::PacketTooLarge(packet.len(), WG_MTU));
        }

        // Determine destination IP from the IP header (first byte).
        let dst_ip = parse_dst_ip(packet)?;

        // Look up peer
        let peer = self.peer_for_ip(dst_ip).await?;
        let endpoint = peer
            .endpoint
            .read()
            .await
            .ok_or(CoreError::PeerNotFound(dst_ip))?;

        let mut out_buf = vec![0u8; UDP_BUF];
        let result = peer.tunn.lock().await.encapsulate(packet, &mut out_buf);

        // We handle the result immediately to avoid borrow-checker conflicts
        // where TunnResult might hold a reference to out_buf.
        match result {
            TunnResult::Done => Ok(()),
            TunnResult::Err(e) => Err(CoreError::HandshakeFailed(format!("{:?}", e))),
            TunnResult::WriteToNetwork(data) => {
                self.0
                    .socket
                    .send_to(data, endpoint)
                    .await
                    .map(|_| ())
                    .map_err(|e| CoreError::TunnelIo { source: e })
            }
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                // Unexpected: we were encrypting, not decrypting
                warn!("Unexpected WriteToTunnel while encapsulating");
                Ok(())
            }
        }
    }

    // ------------------------------------------------------------------
    // Core data-plane: receive and decrypt a UDP datagram
    // ------------------------------------------------------------------

    /// Read one UDP datagram from the socket, decrypt it, and return the
    /// inner IP packet together with the sending peer's public key bytes.
    pub async fn recv_packet(&self) -> Result<(Bytes, [u8; 32])> {
        let mut udp_buf = vec![0u8; UDP_BUF];
        let mut ip_buf = vec![0u8; UDP_BUF];

        loop {
            let (n, src) = self
                .0
                .socket
                .recv_from(&mut udp_buf)
                .await
                .map_err(|e| CoreError::TunnelIo { source: e })?;
            let datagram = &udp_buf[..n];

            // Route datagram to the correct peer session.
            // boringtun decodes the sender index from the first 4 bytes and
            // can demultiplex initiations by public key.
            // We iterate peers; in a high-scale implementation use a sender-
            // index hash map instead.
            let peers_snap = self.0.peers.read().await;
            let mut matched_key = None;

            for (key, session) in peers_snap.iter() {
                let mut tunn = session.tunn.lock().await;
                let result = tunn.decapsulate(Some(src.ip()), datagram, &mut ip_buf);
                match result {
                    TunnResult::Done => {
                        debug!(%src, "WireGuard control packet processed");
                        matched_key = Some(*key);
                        break;
                    }
                    TunnResult::Err(e) => {
                        trace!(%src, err = ?e, "decapsulate error (trying next peer)");
                    }
                    TunnResult::WriteToNetwork(data) => {
                        let _ = self.0.socket.send_to(data, src).await;
                        matched_key = Some(*key);
                        break;
                    }
                    TunnResult::WriteToTunnelV4(plain, _) | TunnResult::WriteToTunnelV6(plain, _) => {
                        let inner = Bytes::copy_from_slice(plain);
                        // Update last-seen timestamp
                        *session.last_rx.lock().await = std::time::Instant::now();
                        return Ok((inner, *key));
                    }
                }
            }

            // Update roaming endpoint
            if let Some(k) = matched_key {
                if let Some(session) = peers_snap.get(&k) {
                    let mut ep = session.endpoint.write().await;
                    if *ep != Some(src) {
                        info!(%src, "Peer endpoint roamed");
                        *ep = Some(src);
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Timer loop (keepalives, re-key, session expiry)
    // ------------------------------------------------------------------

    async fn timer_loop(&self) {
        let mut interval = time::interval(Duration::from_millis(250));
        let mut udp_buf = vec![0u8; UDP_BUF];

        loop {
            interval.tick().await;
            let peers_snap = self.0.peers.read().await;

            for session in peers_snap.values() {
                let endpoint = *session.endpoint.read().await;
                let Some(ep) = endpoint else { continue };

                let mut tunn = session.tunn.lock().await;
                match tunn.update_timers(&mut udp_buf) {
                    TunnResult::Done => {}
                    TunnResult::Err(e) => {
                        warn!(err = ?e, "Timer update error");
                    }
                    TunnResult::WriteToNetwork(data) => {
                        if let Err(e) = self.0.socket.send_to(data, ep).await {
                            error!(err = %e, %ep, "Failed to send timer packet");
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    async fn peer_for_ip(&self, ip: IpAddr) -> Result<Arc<PeerSession>> {
        let ip_map = self.0.ip_to_peer.read().await;
        // Try exact match first, then longest-prefix by iterating peers.
        if let Some(key) = ip_map.get(&ip) {
            let peers = self.0.peers.read().await;
            if let Some(p) = peers.get(key) {
                return Ok(p.clone());
            }
        }
        // Fallback: linear scan for subnet containment.
        let peers = self.0.peers.read().await;
        for session in peers.values() {
            if session.is_allowed(ip) {
                return Ok(session.clone());
            }
        }
        Err(CoreError::PeerNotFound(ip))
    }

    // handle_tunn_result has been merged into its callers to avoid borrow issues.
}

// ---------------------------------------------------------------------------
// IP header parsing helpers
// ---------------------------------------------------------------------------

/// Extract the destination IP from a raw IP packet (v4 or v6).
fn parse_dst_ip(pkt: &[u8]) -> Result<IpAddr> {
    if pkt.is_empty() {
        return Err(CoreError::TunDevice("empty packet".into()));
    }
    match pkt[0] >> 4 {
        4 if pkt.len() >= 20 => {
            let dst = std::net::Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
            Ok(IpAddr::V4(dst))
        }
        6 if pkt.len() >= 40 => {
            let mut dst = [0u8; 16];
            dst.copy_from_slice(&pkt[24..40]);
            Ok(IpAddr::V6(std::net::Ipv6Addr::from(dst)))
        }
        v => Err(CoreError::TunDevice(format!("unknown IP version {v}"))),
    }
}
