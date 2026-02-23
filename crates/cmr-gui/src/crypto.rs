//! Cryptographic helper utilities for the CMR GUI.
//!
//! Key generation for the pairwise HMAC-SHA-256 signing keys used between a
//! client and a router.

use rand::RngCore;

/// Generates `n` cryptographically random bytes.
#[must_use]
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0_u8; n];
    rand::rng().fill_bytes(&mut buf);
    buf
}

/// Generates a fresh 32-byte HMAC key and returns it as lower-case hex.
///
/// The hex string can be placed directly in the config file and exchanged
/// with the router operator so both sides share the same secret.
#[must_use]
pub fn generate_key_hex() -> String {
    hex::encode(random_bytes(32))
}

/// Validates that `s` is a non-empty even-length lower-case hex string and
/// decodes it to bytes.
///
/// # Errors
///
/// Returns a human-readable error message string on failure.
pub fn parse_key_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("Key must not be empty.".to_owned());
    }
    if s.len() % 2 != 0 {
        return Err("Key hex string must have an even number of characters.".to_owned());
    }
    if !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Key must be a valid hexadecimal string (0-9, a-f, A-F).".to_owned());
    }
    hex::decode(s).map_err(|e| format!("Hex decode failed: {e}"))
}
