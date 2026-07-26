// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cryptographic building blocks.
//!
//! Landed:
//! - [`padding`] — length-hiding framing (a 1-byte message and a 200-byte
//!   message become the same size on the wire).
//!
//! - [`keystore`] — Argon2id + XChaCha20-Poly1305 at-rest key protection.
//!
//! - [`ratchet`] — Double Ratchet E2E sessions via `vodozemac`.

pub mod keystore;
pub mod padding;
pub mod ratchet;
pub mod signal;
