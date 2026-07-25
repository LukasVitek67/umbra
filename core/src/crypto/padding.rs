// SPDX-License-Identifier: AGPL-3.0-or-later
//! Length-hiding message padding.
//!
//! # Why
//!
//! Encryption hides *content* but not *length*. If a 1-character message
//! produced a 1-character ciphertext, an observer watching the (Tor) traffic
//! could still distinguish "yes"/"no", read typing cadence, fingerprint known
//! phrases, and correlate senders and receivers by size. This module removes
//! that channel by padding every payload up to a fixed size class ("bucket")
//! *before* it is encrypted, so a 1-byte message and a 200-byte message are
//! byte-for-byte the same length on the wire.
//!
//! This is the concrete realisation of the product requirement "even a single
//! character must become several characters": the smallest frame is
//! [`BUCKETS`]`[0]` = 256 bytes, so a single character leaves the device as (at
//! least) a 256-byte frame, which the AEAD then turns into ~272 bytes of
//! ciphertext.
//!
//! # Frame format (plaintext, pre-encryption)
//!
//! ```text
//! ┌───────────────┬─────────────────────┬───────────────────────┐
//! │ len: u32 (BE) │ payload (len bytes) │ zero padding          │
//! └───────────────┴─────────────────────┴───────────────────────┘
//! │<── 4 bytes ──>│                                             │
//! │<──────────────── total == one bucket size ────────────────>│
//! ```
//!
//! The whole frame is always sealed inside an authenticated cipher (AEAD)
//! before it touches the network, so the padding bytes are never observable and
//! zeros are as safe as random here; zeros keep [`pad`] deterministic and
//! trivially testable. Only the *length* is visible to a network observer, and
//! that length is one of a small fixed set.
//!
//! # Residual leak (documented, not hidden)
//!
//! Padding quantises size; it does not make all messages equal. A 2 MB file and
//! a 3-word text land in different buckets, so their *size class* still leaks.
//! For payloads larger than [`MAX_BUCKET`] the frame is rounded up to a whole
//! multiple of it, so very large transfers leak coarse magnitude. Closing this
//! fully requires constant-rate cover traffic (planned, Fáze 2). See
//! `docs/THREAT_MODEL.md`.

use crate::error::PadError;

/// Bytes used to store the true payload length at the front of every frame,
/// as a big-endian `u32`.
pub const LEN_PREFIX: usize = 4;

/// Fixed size classes, ascending. Every payload is padded up to exactly one of
/// these (or a whole multiple of the largest). The smallest is the minimum
/// frame size, so even an empty message occupies `BUCKETS[0]` bytes.
pub const BUCKETS: [usize; 5] = [256, 1024, 4096, 16384, 65536];

/// The largest fixed bucket. Framed payloads bigger than this are padded up to
/// the next whole multiple of it.
pub const MAX_BUCKET: usize = BUCKETS[BUCKETS.len() - 1];

/// Compute the total padded length for a payload of `payload_len` bytes.
fn framed_len(payload_len: usize) -> Result<usize, PadError> {
    // The true length must be representable in the u32 prefix.
    if payload_len > u32::MAX as usize {
        return Err(PadError::TooLarge);
    }
    let needed = payload_len
        .checked_add(LEN_PREFIX)
        .ok_or(PadError::TooLarge)?;

    for &bucket in BUCKETS.iter() {
        if needed <= bucket {
            return Ok(bucket);
        }
    }

    // Larger than the biggest bucket: round up to a whole multiple of it.
    let multiples = needed.div_ceil(MAX_BUCKET);
    multiples.checked_mul(MAX_BUCKET).ok_or(PadError::TooLarge)
}

/// Return `true` if `n` is a length this padder could legitimately have
/// produced. Used by [`unpad`] as a defence-in-depth check (authenticated
/// decryption is the primary guard against tampering).
fn is_valid_frame_len(n: usize) -> bool {
    if BUCKETS.contains(&n) {
        return true;
    }
    n > MAX_BUCKET && n % MAX_BUCKET == 0
}

/// Pad `payload` into a fixed-size frame ready to be encrypted.
///
/// The returned vector's length is always one of [`BUCKETS`] (or a multiple of
/// [`MAX_BUCKET`]), and always at least `BUCKETS[0]` = 256 bytes.
///
/// # Errors
/// Returns [`PadError::TooLarge`] if `payload` exceeds `u32::MAX` bytes.
///
/// # Example
/// ```
/// use umbra_core::crypto::padding::{pad, unpad, BUCKETS};
/// let frame = pad(b"hi").unwrap();
/// assert_eq!(frame.len(), BUCKETS[0]); // 2 bytes -> 256-byte frame
/// assert_eq!(unpad(&frame).unwrap(), b"hi");
/// ```
pub fn pad(payload: &[u8]) -> Result<Vec<u8>, PadError> {
    let total = framed_len(payload.len())?;
    let mut frame = vec![0u8; total];
    // Safe cast: framed_len guaranteed payload.len() <= u32::MAX.
    let len = payload.len() as u32;
    frame[..LEN_PREFIX].copy_from_slice(&len.to_be_bytes());
    frame[LEN_PREFIX..LEN_PREFIX + payload.len()].copy_from_slice(payload);
    // Remaining bytes are already zero from the allocation.
    Ok(frame)
}

/// Recover the original payload from a padded frame produced by [`pad`].
///
/// # Errors
/// - [`PadError::MalformedFrame`] if the frame is shorter than the length
///   prefix, or its declared inner length runs past the end of the frame.
/// - [`PadError::InvalidFrameLength`] if the frame's total length is not one
///   this padder could have produced.
pub fn unpad(frame: &[u8]) -> Result<Vec<u8>, PadError> {
    if frame.len() < LEN_PREFIX {
        return Err(PadError::MalformedFrame);
    }
    if !is_valid_frame_len(frame.len()) {
        return Err(PadError::InvalidFrameLength);
    }

    let mut len_bytes = [0u8; LEN_PREFIX];
    len_bytes.copy_from_slice(&frame[..LEN_PREFIX]);
    let real_len = u32::from_be_bytes(len_bytes) as usize;

    let end = real_len
        .checked_add(LEN_PREFIX)
        .ok_or(PadError::MalformedFrame)?;
    if end > frame.len() {
        return Err(PadError::MalformedFrame);
    }

    Ok(frame[LEN_PREFIX..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny deterministic PRNG (SplitMix64) so the property-style tests need no
    /// external crates — keeps the core crate dependency-free and testable on a
    /// space-constrained machine.
    struct SplitMix64(u64);
    impl SplitMix64 {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn bytes(&mut self, len: usize) -> Vec<u8> {
            let mut v = Vec::with_capacity(len);
            while v.len() < len {
                v.extend_from_slice(&self.next_u64().to_le_bytes());
            }
            v.truncate(len);
            v
        }
    }

    #[test]
    fn empty_payload_fills_min_bucket() {
        let frame = pad(b"").unwrap();
        assert_eq!(frame.len(), BUCKETS[0]);
        assert_eq!(unpad(&frame).unwrap(), b"");
    }

    #[test]
    fn single_char_becomes_full_frame() {
        // The headline requirement: 1 char -> many bytes.
        let frame = pad(b"x").unwrap();
        assert_eq!(frame.len(), 256);
        assert_eq!(unpad(&frame).unwrap(), b"x");
    }

    #[test]
    fn bucket_boundaries_are_exact() {
        // 252 + 4-byte prefix == 256 -> smallest bucket.
        assert_eq!(pad(&vec![0u8; 252]).unwrap().len(), 256);
        // One more byte spills into the next bucket.
        assert_eq!(pad(&vec![0u8; 253]).unwrap().len(), 1024);
        assert_eq!(pad(&vec![0u8; 1020]).unwrap().len(), 1024);
        assert_eq!(pad(&vec![0u8; 1021]).unwrap().len(), 4096);
        assert_eq!(pad(&vec![0u8; 65532]).unwrap().len(), 65536);
    }

    #[test]
    fn oversized_rounds_to_multiple_of_max_bucket() {
        // 65533 + 4 = 65537 > MAX_BUCKET -> next multiple = 2 * 65536.
        let frame = pad(&vec![7u8; 65533]).unwrap();
        assert_eq!(frame.len(), 2 * MAX_BUCKET);
        assert_eq!(is_valid_frame_len(frame.len()), true);
        assert_eq!(unpad(&frame).unwrap(), vec![7u8; 65533]);
    }

    #[test]
    fn unpad_rejects_too_short() {
        assert_eq!(unpad(&[0, 0, 0]), Err(PadError::MalformedFrame));
    }

    #[test]
    fn unpad_rejects_non_bucket_length() {
        // 300 is neither a bucket nor a multiple of MAX_BUCKET.
        assert_eq!(unpad(&vec![0u8; 300]), Err(PadError::InvalidFrameLength));
    }

    #[test]
    fn unpad_rejects_length_prefix_past_end() {
        let mut frame = pad(b"hello").unwrap(); // valid 256-byte frame
        // Claim an inner length far bigger than the frame.
        frame[..4].copy_from_slice(&1000u32.to_be_bytes());
        assert_eq!(unpad(&frame), Err(PadError::MalformedFrame));
    }

    #[test]
    fn roundtrip_is_reversible_and_length_hiding() {
        // Property: across many payloads, pad is reversible and always lands on
        // a legal, length-hiding size.
        let mut rng = SplitMix64(0x0C0F_FEE1_2345_6789);
        for _ in 0..1000 {
            let len = (rng.next_u64() % 20_000) as usize;
            let payload = rng.bytes(len);
            let framed = pad(&payload).unwrap();
            assert!(is_valid_frame_len(framed.len()));
            assert!(framed.len() >= BUCKETS[0]);
            assert!(framed.len() >= payload.len() + LEN_PREFIX);
            assert_eq!(unpad(&framed).unwrap(), payload);
        }
    }

    #[test]
    fn payloads_sharing_a_bucket_have_equal_wire_length() {
        // Property: two payloads that both fit the smallest bucket are
        // byte-length indistinguishable on the wire.
        let mut rng = SplitMix64(42);
        for _ in 0..1000 {
            let la = (rng.next_u64() % 252) as usize;
            let lb = (rng.next_u64() % 252) as usize;
            let a = rng.bytes(la);
            let b = rng.bytes(lb);
            assert_eq!(pad(&a).unwrap().len(), pad(&b).unwrap().len());
        }
    }
}
