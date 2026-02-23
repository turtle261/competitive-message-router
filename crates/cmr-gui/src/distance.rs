//! Compression-based information-distance computation.
//!
//! The CMR protocol defines the distance between messages X and Y as:
//!
//! ```text
//! D(X, Y) = K(Y|X) + K(X|Y)
//! ```
//!
//! where K is Kolmogorov complexity.  In practice this is approximated by
//! compression differences:
//!
//! ```text
//! D(X, Y) ≈ C(XY) − C(X) + C(YX) − C(Y)
//! ```
//!
//! where C(·) denotes the compressed size of the argument and XY denotes
//! concatenation.  The better the compressor, the tighter the approximation.
//!
//! This module uses DEFLATE (via `flate2`) as the compressor, which is fast
//! and deterministic, making it suitable for real-time display in the GUI.

use flate2::{Compression, write::DeflateEncoder};
use std::io::Write;

/// Returns the DEFLATE-compressed size of `data` in bytes.
fn compressed_size(data: &[u8]) -> usize {
    if data.is_empty() {
        return 0;
    }
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::best());
    // Errors are not expected for in-memory writes; fall back to raw length.
    if enc.write_all(data).is_ok() {
        enc.finish().map(|v| v.len()).unwrap_or(data.len())
    } else {
        data.len()
    }
}

/// Computes the *normalized* information distance between two byte slices.
///
/// The result is in the range `[0.0, 1.0]`:
/// - `0.0` — messages are identical / trivially related
/// - `1.0` — messages are completely unrelated
///
/// Uses the Normalized Compression Distance (NCD) formula:
///
/// ```text
/// NCD(X, Y) = (C(XY) − min(C(X), C(Y))) / max(C(X), C(Y))
/// ```
///
/// which is bounded between 0 and 1 for a normal compressor.
#[must_use]
pub fn normalized_distance(x: &[u8], y: &[u8]) -> f64 {
    if x.is_empty() && y.is_empty() {
        return 0.0;
    }
    let cx = compressed_size(x) as f64;
    let cy = compressed_size(y) as f64;

    let mut xy = Vec::with_capacity(x.len() + y.len());
    xy.extend_from_slice(x);
    xy.extend_from_slice(y);
    let cxy = compressed_size(&xy) as f64;

    let max_c = cx.max(cy);
    let min_c = cx.min(cy);

    if max_c == 0.0 {
        return 0.0;
    }
    ((cxy - min_c) / max_c).clamp(0.0, 1.0)
}

/// Computes the NCD of a new message against *all* existing messages.
///
/// The return value is the **minimum** NCD across all existing messages,
/// which represents how closely the new message matches the "nearest
/// neighbour" in the current inbox corpus — analogous to the routing
/// distance a router would compute.
///
/// Returns `1.0` when `existing` is empty (no context to compare against).
#[must_use]
pub fn nearest_neighbor_distance(new_msg: &[u8], existing: &[&[u8]]) -> f64 {
    if existing.is_empty() {
        return 1.0;
    }
    existing
        .iter()
        .map(|e| normalized_distance(new_msg, e))
        .fold(f64::INFINITY, f64::min)
}

/// Formats a distance value as a short human-readable string, e.g. `"0.42"`.
#[must_use]
pub fn format_distance(d: f64) -> String {
    format!("{d:.2}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_messages_have_low_distance() {
        let msg = b"Jupiter is the largest planet.";
        let d = normalized_distance(msg, msg);
        // Identical messages: d should be near 0 (may not be exactly 0 due
        // to compressor overhead, but must be below 0.1).
        assert!(d < 0.1, "expected near-zero distance, got {d}");
    }

    #[test]
    fn unrelated_messages_have_high_distance() {
        let x = b"Jupiter is the largest planet in the solar system.";
        let y = b"The recipe calls for two cups of flour and one egg.";
        let d = normalized_distance(x, y);
        assert!(d > 0.3, "expected non-trivial distance, got {d}");
    }

    #[test]
    fn empty_slices_yield_zero() {
        assert_eq!(normalized_distance(b"", b""), 0.0);
    }

    #[test]
    fn distance_is_symmetric() {
        let x = b"Hello World";
        let y = b"Mercury is the innermost planet";
        let d1 = normalized_distance(x, y);
        let d2 = normalized_distance(y, x);
        // Allow tiny floating-point asymmetry.
        assert!((d1 - d2).abs() < 0.05, "d(x,y)={d1} d(y,x)={d2}");
    }
}
