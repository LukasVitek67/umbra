// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Umbra core — the memory-safe Rust heart of the messenger.
//
// Design rule #1 (see docs/THREAT_MODEL.md): we do NOT invent cryptography.
// Every primitive is a well-reviewed, open-source crate; this crate only
// composes them and owns the framing/state-machine glue.
//
// Modules are added one vertical, compiling+tested slice at a time. Today's
// slice: length-hiding message padding. Everything else is documented in
// docs/ARCHITECTURE.md and wired in as it lands.

#![forbid(unsafe_code)] // relaxed only in the FFI layer, behind its own review
#![warn(missing_docs)]

//! Umbra core library.
//!
//! Currently exposes the [`crypto`] module. See `docs/ARCHITECTURE.md` for the
//! full planned surface (identity, transport, store, api).

pub mod crypto;
pub mod envelope;
pub mod error;
pub mod group;
pub mod identity;
pub mod invite;
pub mod store;

/// Semantic version of the wire/framing format. Bump on any incompatible change
/// to how bytes are laid out on the wire, so peers can refuse mismatched peers
/// instead of silently corrupting.
pub const WIRE_VERSION: u16 = 1;
