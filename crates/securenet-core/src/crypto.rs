//! Cryptographic primitives used throughout SecureNet.
//!
//! All key material is wrapped in `Zeroize`-on-drop types so secrets are
//! wiped from memory as soon as they go out of scope.  No secret byte
//! ever escapes this module as a bare `Vec<u8>` or `[u8; N]`.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AeadOsRng},
    ChaCha20Poly1305, Nonce,
};
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CoreError, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Length of a Curve25519 public or private key in bytes.
pub const KEY_LEN: usize = 32;
/// Length of a ChaCha20-Poly1305 nonce in bytes.
pub const NONCE_LEN: usize = 12;
/// Length of a Poly1305 authentication tag in bytes.
pub const TAG_LEN: usize = 16;
/// Maximum WireGuard transport message payload (MTU ceiling before padding).
pub const MAX_PACKET: usize = 65535;
/// WireGuard interface MTU (IPv6-safe, accounts for WireGuard overhead).
pub const WG_MTU: usize = 1420;

// ---------------------------------------------------------------------------
// Key types
// ---------------------------------------------------------------------------

/// A Curve25519 static private key.  Memory is zeroed on drop.
#[derive(ZeroizeOnDrop)]
pub struct PrivateKey(StaticSecret);

impl PrivateKey {
    /// Generate a fresh random private key.
    pub fn generate() -> Self {
        Self(StaticSecret::random_from_rng(OsRng))
    }

    /// Reconstruct from raw 32-byte little-endian scalar.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    /// Decode from standard Base64.
    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = B64
            .decode(s)
            .map_err(|e| CoreError::KeyGeneration(e.to_string()))?;
        if bytes.len() != KEY_LEN {
            return Err(CoreError::InvalidKeyLength(bytes.len()));
        }
        let mut arr = [0u8; KEY_LEN];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_bytes(arr))
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> PeerPublicKey {
        PeerPublicKey(PublicKey::from(&self.0))
    }

    /// Perform a Diffie-Hellman exchange, returning the shared secret.
    pub fn diffie_hellman(&self, peer: &PeerPublicKey) -> SharedSecret {
        SharedSecret(self.0.diffie_hellman(&peer.0))
    }

    /// Expose raw bytes (use only at serialisation boundaries).
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        self.0.as_bytes()
    }

    pub fn to_base64(&self) -> String {
        B64.encode(self.0.as_bytes())
    }
}

/// A Curve25519 public key — safe to share.
#[derive(Clone, PartialEq, Eq)]
pub struct PeerPublicKey(PublicKey);

impl PeerPublicKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(PublicKey::from(bytes))
    }

    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = B64
            .decode(s)
            .map_err(|e| CoreError::KeyGeneration(e.to_string()))?;
        if bytes.len() != KEY_LEN {
            return Err(CoreError::InvalidKeyLength(bytes.len()));
        }
        let mut arr = [0u8; KEY_LEN];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_bytes(arr))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        self.0.as_bytes()
    }

    pub fn to_base64(&self) -> String {
        B64.encode(self.0.as_bytes())
    }
}

impl std::fmt::Debug for PeerPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PeerPublicKey({})", &self.to_base64()[..8])
    }
}

/// A Curve25519 ephemeral private key — consumed on use.
pub struct EphemeralPrivateKey(EphemeralSecret);

impl EphemeralPrivateKey {
    pub fn generate() -> Self {
        Self(EphemeralSecret::random_from_rng(OsRng))
    }

    pub fn public_key(&self) -> PeerPublicKey {
        PeerPublicKey(PublicKey::from(&self.0))
    }

    /// Consume the ephemeral key, performing DH.
    pub fn diffie_hellman(self, peer: &PeerPublicKey) -> SharedSecret {
        SharedSecret(self.0.diffie_hellman(&peer.0))
    }
}

/// Result of a DH exchange.  Zeroed on drop.
#[derive(ZeroizeOnDrop)]
pub struct SharedSecret(x25519_dalek::SharedSecret);

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        self.0.as_bytes()
    }
}

// ---------------------------------------------------------------------------
// Pre-Shared Key (optional, for PSK mode)
// ---------------------------------------------------------------------------

/// Optional pre-shared symmetric key for additional protection.
#[derive(Clone, ZeroizeOnDrop)]
pub struct PreSharedKey([u8; KEY_LEN]);

impl PreSharedKey {
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut buf = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut buf);
        Self(buf)
    }

    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = B64
            .decode(s)
            .map_err(|e| CoreError::KeyGeneration(e.to_string()))?;
        if bytes.len() != KEY_LEN {
            return Err(CoreError::InvalidKeyLength(bytes.len()));
        }
        let mut arr = [0u8; KEY_LEN];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub fn to_base64(&self) -> String {
        B64.encode(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Symmetric encryption helpers (ChaCha20-Poly1305)
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` under `key` with a random 96-bit nonce.
/// Returns `nonce || ciphertext || tag` concatenated.
pub fn aead_seal(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CoreError::EncryptionFailed)?;
    let nonce = ChaCha20Poly1305::generate_nonce(&mut AeadOsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CoreError::EncryptionFailed)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a blob produced by [`aead_seal`].
pub fn aead_open(key: &[u8; KEY_LEN], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN {
        return Err(CoreError::DecryptionFailed);
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CoreError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|_| CoreError::DecryptionFailed)
}

// ---------------------------------------------------------------------------
// BLAKE2s-based HKDF (mirrors WireGuard's KDF)
// ---------------------------------------------------------------------------

use blake2::Blake2s256;
use hmac::{SimpleHmac, Mac};
type HmacBlake2s = SimpleHmac<Blake2s256>;

/// Single-step HMAC-Blake2s: compute HMAC(key, data).
pub fn hmac_blake2s(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        <HmacBlake2s as hmac::digest::KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&result);
    arr
}

/// Two-output KDF matching WireGuard's `KDF2(key, input) -> (T1, T2)`.
pub fn kdf2(key: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let t1 = hmac_blake2s(key, input);
    let t2 = {
        let mut data = Vec::with_capacity(33);
        data.extend_from_slice(&t1);
        data.push(0x01);
        hmac_blake2s(&t1, &data)
    };
    (t1, t2)
}

/// Three-output KDF matching WireGuard's `KDF3`.
pub fn kdf3(key: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let (t1, t2) = kdf2(key, input);
    let t3 = {
        let mut data = Vec::with_capacity(33);
        data.extend_from_slice(&t2);
        data.push(0x02);
        hmac_blake2s(&t1, &data)
    };
    (t1, t2, t3)
}

// ---------------------------------------------------------------------------
// Anti-replay sliding window (RFC 6479)
// ---------------------------------------------------------------------------

/// Sliding-window counter tracking received packet indices.
/// Window size matches WireGuard's `REKEY_AFTER_MESSAGES`.
pub struct ReplayWindow {
    /// Highest counter seen so far.
    top: u64,
    /// Bitfield of the last `WINDOW_SIZE` counters.
    window: u128,
}

const WINDOW_SIZE: u64 = 128;

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            top: 0,
            window: 0,
        }
    }

    /// Returns `Ok(())` if this counter is fresh, or a `ReplayDetected`
    /// error if we have already seen it.
    pub fn check_and_update(&mut self, counter: u64) -> Result<()> {
        if counter + WINDOW_SIZE < self.top {
            return Err(CoreError::ReplayDetected {
                counter,
                floor: self.top.saturating_sub(WINDOW_SIZE),
            });
        }
        if counter > self.top {
            let shift = counter - self.top;
            if shift >= WINDOW_SIZE {
                self.window = 1;
            } else {
                self.window = (self.window << shift) | 1;
            }
            self.top = counter;
        } else {
            let bit = self.top - counter;
            let mask = 1u128 << bit;
            if self.window & mask != 0 {
                return Err(CoreError::ReplayDetected {
                    counter,
                    floor: self.top.saturating_sub(WINDOW_SIZE),
                });
            }
            self.window |= mask;
        }
        Ok(())
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Key-pair helper
// ---------------------------------------------------------------------------

/// A static key-pair (private + public) for a WireGuard interface.
pub struct KeyPair {
    pub private: PrivateKey,
    pub public: PeerPublicKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let private = PrivateKey::generate();
        let public = private.public_key();
        Self { private, public }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_round_trip() {
        let mut key = [0u8; KEY_LEN];
        rand::RngCore::fill_bytes(&mut OsRng, &mut key);
        let plaintext = b"Hello, SecureNet!";
        let blob = aead_seal(&key, plaintext).unwrap();
        let recovered = aead_open(&key, &blob).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn aead_tamper_detection() {
        let mut key = [0u8; KEY_LEN];
        rand::RngCore::fill_bytes(&mut OsRng, &mut key);
        let mut blob = aead_seal(&key, b"secret").unwrap();
        // Flip a byte in the ciphertext
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert!(aead_open(&key, &blob).is_err());
    }

    #[test]
    fn replay_window_basic() {
        let mut win = ReplayWindow::new();
        assert!(win.check_and_update(1).is_ok());
        assert!(win.check_and_update(1).is_err()); // duplicate
        assert!(win.check_and_update(2).is_ok());
        assert!(win.check_and_update(0).is_err()); // too old
    }

    #[test]
    fn dh_exchange() {
        let alice_priv = PrivateKey::generate();
        let alice_pub = alice_priv.public_key();
        let bob_priv = PrivateKey::generate();
        let bob_pub = bob_priv.public_key();

        let alice_shared = alice_priv.diffie_hellman(&bob_pub);
        let bob_shared = bob_priv.diffie_hellman(&alice_pub);
        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn key_base64_round_trip() {
        let kp = KeyPair::generate();
        let b64 = kp.public.to_base64();
        let restored = PeerPublicKey::from_base64(&b64).unwrap();
        assert_eq!(kp.public.as_bytes(), restored.as_bytes());
    }
}
