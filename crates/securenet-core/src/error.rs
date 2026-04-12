use thiserror::Error;

/// Top-level error type for the SecureNet core library.
#[derive(Debug, Error)]
pub enum CoreError {
    // ------------------------------------------------------------------
    // Cryptography errors
    // ------------------------------------------------------------------
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    #[error("invalid public key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    #[error("AEAD encryption failed")]
    EncryptionFailed,

    #[error("AEAD decryption / authentication failed")]
    DecryptionFailed,

    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("replay attack detected: counter {counter} is below window floor {floor}")]
    ReplayDetected { counter: u64, floor: u64 },

    // ------------------------------------------------------------------
    // Tunnel errors
    // ------------------------------------------------------------------
    #[error("TUN device error: {0}")]
    TunDevice(String),

    #[error("tunnel I/O error: {source}")]
    TunnelIo {
        #[from]
        source: std::io::Error,
    },

    #[error("tunnel packet too large: {0} bytes (max {1})")]
    PacketTooLarge(usize, usize),

    #[error("tunnel peer not found for allowed IP {0}")]
    PeerNotFound(std::net::IpAddr),

    #[error("tunnel session expired")]
    SessionExpired,

    // ------------------------------------------------------------------
    // Configuration errors
    // ------------------------------------------------------------------
    #[error("configuration parse error: {0}")]
    ConfigParse(String),

    #[error("configuration field missing: {0}")]
    ConfigMissing(String),

    #[error("invalid CIDR notation: {0}")]
    InvalidCidr(String),

    // ------------------------------------------------------------------
    // Authentication errors
    // ------------------------------------------------------------------
    #[error("authentication token invalid or expired")]
    TokenInvalid,

    #[error("peer authentication failed: public key mismatch")]
    PeerAuthFailed,

    // ------------------------------------------------------------------
    // Miscellaneous
    // ------------------------------------------------------------------
    #[error("DNS resolution failed for {host}: {reason}")]
    DnsResolution { host: String, reason: String },

    #[error("rate limit exceeded")]
    RateLimit,

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;
