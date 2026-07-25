// SPDX-License-Identifier: AGPL-3.0-or-later
//! Contact invites — the self-contained "add me" code you share out-of-band.
//!
//! An invite carries everything a peer needs to reach you **without any server**:
//! your identity public key, your Tor onion address, and your chosen username.
//! It is encoded as `umbra1:<base64url>` with a short checksum so a mistyped
//! code is rejected rather than silently connecting to the wrong place.
//!
//! The short [`crate::identity::user_code`] (e.g. `K7QF-2M9X-4TP1-9WZ3`) is the
//! *searchable* handle for discovery; the invite is the *complete* connection
//! blob. Neither is secret — a contact is still verified against the full public
//! key (safety numbers) after connecting.

use crate::error::InviteError;
use crate::identity::{user_code, PublicKey};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

const PREFIX: &str = "umbra1:";
const VERSION: u8 = 1;
const CHECKSUM_LEN: usize = 4;

/// A shareable contact invite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// The inviter's identity public key (the real identity).
    pub identity: PublicKey,
    /// The inviter's chosen username (display only, not unique).
    pub username: String,
    /// The inviter's Tor onion service address.
    pub onion: String,
}

impl Invite {
    /// Build an invite.
    pub fn new(identity: PublicKey, username: impl Into<String>, onion: impl Into<String>) -> Self {
        Self { identity, username: username.into(), onion: onion.into() }
    }

    /// The short searchable code for this identity.
    pub fn user_code(&self) -> String {
        user_code(&self.identity)
    }

    /// Encode to a `umbra1:…` string.
    pub fn encode(&self) -> String {
        let mut buf = Vec::new();
        buf.push(VERSION);
        buf.extend_from_slice(&self.identity);
        put_str(&mut buf, &self.username);
        put_str(&mut buf, &self.onion);
        let sum = Sha256::digest(&buf);
        buf.extend_from_slice(&sum[..CHECKSUM_LEN]);
        format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(&buf))
    }

    /// Parse and validate a `umbra1:…` string.
    ///
    /// # Errors
    /// [`InviteError::BadFormat`] on a bad prefix, bad base64, wrong length, or a
    /// failed checksum (mistyped code); [`InviteError::BadVersion`] for an
    /// unknown version.
    pub fn decode(s: &str) -> Result<Invite, InviteError> {
        let b64 = s.trim().strip_prefix(PREFIX).ok_or(InviteError::BadFormat)?;
        let buf = URL_SAFE_NO_PAD.decode(b64).map_err(|_| InviteError::BadFormat)?;
        if buf.len() < 1 + 32 + 2 + 2 + CHECKSUM_LEN {
            return Err(InviteError::BadFormat);
        }

        let (payload, sum) = buf.split_at(buf.len() - CHECKSUM_LEN);
        if sum != &Sha256::digest(payload)[..CHECKSUM_LEN] {
            return Err(InviteError::BadFormat);
        }

        let mut o = 0usize;
        let version = payload[o];
        o += 1;
        if version != VERSION {
            return Err(InviteError::BadVersion);
        }
        let identity: PublicKey = payload[o..o + 32].try_into().unwrap();
        o += 32;
        let username = take_str(payload, &mut o)?;
        let onion = take_str(payload, &mut o)?;
        if o != payload.len() {
            return Err(InviteError::BadFormat); // trailing garbage
        }
        Ok(Invite { identity, username, onion })
    }
}

fn put_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(u16::MAX as usize);
    buf.extend_from_slice(&(len as u16).to_be_bytes());
    buf.extend_from_slice(&bytes[..len]);
}

fn take_str(buf: &[u8], o: &mut usize) -> Result<String, InviteError> {
    if *o + 2 > buf.len() {
        return Err(InviteError::BadFormat);
    }
    let len = u16::from_be_bytes([buf[*o], buf[*o + 1]]) as usize;
    *o += 2;
    if *o + len > buf.len() {
        return Err(InviteError::BadFormat);
    }
    let s = core::str::from_utf8(&buf[*o..*o + len])
        .map_err(|_| InviteError::BadFormat)?
        .to_string();
    *o += len;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Invite {
        Invite::new([7u8; 32], "alice", "v3k2mabcdef0123456789.onion")
    }

    #[test]
    fn roundtrip() {
        let inv = sample();
        let encoded = inv.encode();
        assert!(encoded.starts_with("umbra1:"));
        assert_eq!(Invite::decode(&encoded).unwrap(), inv);
    }

    #[test]
    fn user_code_matches_identity() {
        let inv = sample();
        assert_eq!(inv.user_code(), user_code(&[7u8; 32]));
    }

    #[test]
    fn unicode_username_survives() {
        let inv = Invite::new([3u8; 32], "Klára 🦊", "abc.onion");
        assert_eq!(Invite::decode(&inv.encode()).unwrap(), inv);
    }

    #[test]
    fn typo_is_rejected_by_checksum() {
        let mut bytes = sample().encode().into_bytes();
        let i = bytes.len() - 2; // inside the base64 body
        bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
        let mangled = String::from_utf8(bytes).unwrap();
        assert!(Invite::decode(&mangled).is_err());
    }

    #[test]
    fn bad_prefix_and_truncation_rejected() {
        assert_eq!(Invite::decode("hello"), Err(InviteError::BadFormat));
        assert_eq!(Invite::decode("umbra1:AAAA"), Err(InviteError::BadFormat));
    }

    #[test]
    fn unknown_version_rejected() {
        // Hand-craft a well-formed but version-2 invite.
        let mut buf = vec![2u8];
        buf.extend_from_slice(&[9u8; 32]);
        buf.extend_from_slice(&0u16.to_be_bytes()); // empty username
        buf.extend_from_slice(&0u16.to_be_bytes()); // empty onion
        let sum = Sha256::digest(&buf);
        buf.extend_from_slice(&sum[..CHECKSUM_LEN]);
        let s = format!("umbra1:{}", URL_SAFE_NO_PAD.encode(&buf));
        assert_eq!(Invite::decode(&s), Err(InviteError::BadVersion));
    }
}
