// SPDX-License-Identifier: AGPL-3.0-or-later
//! Crate-wide error types.

use core::fmt;

/// Errors produced by the message-padding layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PadError {
    /// The payload is larger than the format can describe (length prefix is a
    /// `u32`, so the hard ceiling is `u32::MAX` payload bytes).
    TooLarge,
    /// A frame handed to `unpad` is shorter than the mandatory length prefix,
    /// or its declared inner length runs past the end of the frame.
    MalformedFrame,
    /// A frame's total length is not a value this padder could ever have
    /// produced (not a known bucket, nor a whole multiple of the largest one).
    /// Authenticated decryption should catch tampering first; this is a
    /// defence-in-depth check.
    InvalidFrameLength,
}

impl fmt::Display for PadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PadError::TooLarge => write!(f, "payload too large to pad"),
            PadError::MalformedFrame => write!(f, "malformed padded frame"),
            PadError::InvalidFrameLength => write!(f, "invalid padded frame length"),
        }
    }
}

impl std::error::Error for PadError {}

/// Errors from the at-rest keystore ([`crate::crypto::keystore`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeystoreError {
    /// The blob is too short, has a bad magic, or carries out-of-range KDF
    /// parameters. Distinct from a wrong passphrase on purpose: this means the
    /// bytes are not a well-formed keystore blob at all.
    InvalidBlob,
    /// Argon2 rejected the requested parameters.
    Params,
    /// The key-derivation step failed.
    Kdf,
    /// A symmetric-crypto setup step failed (e.g. bad key length).
    Crypto,
    /// Authenticated decryption failed. Either the passphrase is wrong or the
    /// blob was tampered with — deliberately indistinguishable, to avoid a
    /// padding/decryption oracle.
    WrongPassphraseOrCorrupt,
    /// The OS random number generator failed.
    Rng,
}

impl fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            KeystoreError::InvalidBlob => "malformed keystore blob",
            KeystoreError::Params => "invalid Argon2 parameters",
            KeystoreError::Kdf => "key derivation failed",
            KeystoreError::Crypto => "cipher setup failed",
            KeystoreError::WrongPassphraseOrCorrupt => "wrong passphrase or corrupt data",
            KeystoreError::Rng => "OS random number generator failed",
        };
        write!(f, "{s}")
    }
}

impl std::error::Error for KeystoreError {}

/// Errors from the [`crate::identity`] module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// The OS random number generator failed while generating a key.
    Rng,
    /// Tried to sign a roster with a key that isn't the roster's identity.
    IdentityMismatch,
    /// Serialized bytes are truncated, have a bad magic, or a bad field.
    InvalidData,
    /// The roster's signature did not verify against its identity key.
    SignatureInvalid,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            IdentityError::Rng => "OS random number generator failed",
            IdentityError::IdentityMismatch => "signing key is not this roster's identity",
            IdentityError::InvalidData => "malformed identity/roster data",
            IdentityError::SignatureInvalid => "roster signature did not verify",
        };
        write!(f, "{s}")
    }
}

impl std::error::Error for IdentityError {}

/// Errors from the [`crate::crypto::ratchet`] module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RatchetError {
    /// No one-time key was available to build a prekey bundle.
    NoOneTimeKey,
    /// Establishing an inbound session needs a pre-key message, but a normal
    /// message was supplied.
    ExpectedPreKey,
    /// The peer's pre-key message could not start a session.
    SessionCreation,
    /// A message failed to decrypt (bad key, tampering, or replay).
    Decryption,
}

impl fmt::Display for RatchetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            RatchetError::NoOneTimeKey => "no one-time key available",
            RatchetError::ExpectedPreKey => "expected a pre-key message",
            RatchetError::SessionCreation => "could not create inbound session",
            RatchetError::Decryption => "message failed to decrypt",
        };
        write!(f, "{s}")
    }
}

impl std::error::Error for RatchetError {}

/// Errors from the [`crate::store`] module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The underlying SQLite layer returned an error (message preserved).
    Db(String),
    /// Encrypting or decrypting a stored value failed.
    Crypto,
    /// The OS random number generator failed.
    Rng,
    /// A stored value was structurally invalid (wrong length, bad UTF-8, …) —
    /// typically a wrong data key or a corrupted database.
    Corrupt,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Db(m) => write!(f, "database error: {m}"),
            StoreError::Crypto => write!(f, "value encryption/decryption failed"),
            StoreError::Rng => write!(f, "OS random number generator failed"),
            StoreError::Corrupt => write!(f, "corrupt or wrong-key database value"),
        }
    }
}

impl std::error::Error for StoreError {}

/// Errors from the [`crate::invite`] module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteError {
    /// Missing prefix, bad base64, wrong length, or a failed checksum (a typo in
    /// a hand-copied code lands here).
    BadFormat,
    /// The invite uses a version this build does not understand.
    BadVersion,
}

impl fmt::Display for InviteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InviteError::BadFormat => write!(f, "malformed invite code"),
            InviteError::BadVersion => write!(f, "unsupported invite version"),
        }
    }
}

impl std::error::Error for InviteError {}

/// Errors from the [`crate::group`] module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupError {
    /// The OS random number generator failed while making a group id.
    Rng,
}

impl fmt::Display for GroupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GroupError::Rng => write!(f, "OS random number generator failed"),
        }
    }
}

impl std::error::Error for GroupError {}
