// SPDX-License-Identifier: AGPL-3.0-or-later
//! At-rest secret protection: passphrase -> key -> authenticated encryption.
//!
//! Used to wrap anything that must survive on disk but never leak if the device
//! is imaged: the identity private key, the local database key, etc.
//!
//! # Construction (no home-grown crypto)
//!
//! - **KDF:** Argon2id (memory-hard) turns the user passphrase + a random salt
//!   into a 32-byte key. Parameters are stored in the blob so a future stronger
//!   default can still open old blobs.
//! - **AEAD:** XChaCha20-Poly1305 (24-byte random nonce) encrypts and
//!   authenticates the secret. A wrong passphrase or any tampering fails the
//!   Poly1305 tag check.
//!
//! # Blob layout
//!
//! ```text
//! ┌────────┬───────┬───────┬───────┬────────────┬─────────────┬────────────┐
//! │ magic  │ m_cost│ t_cost│ p_cost│ salt (16 B)│ nonce (24 B)│ ciphertext │
//! │ 8 B    │ u32 BE│ u32 BE│ u32 BE│            │             │ + tag      │
//! └────────┴───────┴───────┴───────┴────────────┴─────────────┴────────────┘
//! │<───────────────── HEADER_LEN = 60 bytes ─────────────────>│
//! ```

use crate::error::KeystoreError;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"UMBRAKS1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const HEADER_LEN: usize = MAGIC.len() + 4 + 4 + 4 + SALT_LEN + NONCE_LEN; // 60

// Sanity bounds so a corrupt/hostile blob can't turn `open` into a memory bomb.
const MAX_M_COST: u32 = 2 * 1024 * 1024; // 2 GiB of KDF memory, hard ceiling
const MAX_T_COST: u32 = 64;
const MAX_P_COST: u32 = 16;

/// Argon2id defaults: **256 MiB**, 3 passes, 4 lanes.
///
/// The OWASP minimum (19 MiB) is aimed at a server hashing many logins per
/// second. Umbra derives this key once, when a person unlocks their own
/// messages, and the thing it defends against is someone with the database file
/// and unlimited time. Memory is what makes that expensive on GPUs, so we spend
/// a quarter of a gigabyte for the second it costs the user.
///
/// Older keystores keep working: the parameters that made a blob are stored in
/// its header and used when opening it.
fn default_params() -> Result<Params, KeystoreError> {
    Params::new(256 * 1024, 3, 4, Some(KEY_LEN)).map_err(|_| KeystoreError::Params)
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    params: &Params,
) -> Result<Zeroizing<[u8; KEY_LEN]>, KeystoreError> {
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase, salt, &mut *key)
        .map_err(|_| KeystoreError::Kdf)?;
    Ok(key)
}

/// Derive a 32-byte key from a passphrase and salt, using the same Argon2id
/// parameters as [`seal`]. Used to key the local [`crate::store::Store`] from a
/// user passphrase (store the salt alongside the database).
pub fn derive_store_key(
    passphrase: &[u8],
    salt: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, KeystoreError> {
    derive_store_key_with(passphrase, salt, LEGACY_M_COST, LEGACY_T_COST, LEGACY_P_COST)
}

/// Parameters used by databases created before the defaults were raised. They
/// are not a recommendation — they are what those files were built with, and
/// the only way to open them.
pub const LEGACY_M_COST: u32 = 19 * 1024;
pub const LEGACY_T_COST: u32 = 2;
pub const LEGACY_P_COST: u32 = 1;

/// What a new database should use: see [`default_params`].
pub const STORE_M_COST: u32 = 256 * 1024;
pub const STORE_T_COST: u32 = 3;
pub const STORE_P_COST: u32 = 4;

/// Derive a database key with explicit parameters.
///
/// The database key has no header to describe itself (unlike a sealed blob), so
/// the caller keeps the parameters next to the salt and passes them back here.
/// That is what lets the defaults rise without locking anyone out of the
/// messages they already have.
pub fn derive_store_key_with(
    passphrase: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>, KeystoreError> {
    let params =
        Params::new(m_cost, t_cost, p_cost, Some(KEY_LEN)).map_err(|_| KeystoreError::Params)?;
    derive_key(passphrase, salt, &params)
}

/// Encrypt `plaintext` under `passphrase`, returning a self-describing blob.
///
/// Every call draws a fresh random salt and nonce, so sealing the same secret
/// twice yields different blobs.
///
/// # Errors
/// [`KeystoreError::Rng`] if the OS RNG fails, or a `Params`/`Crypto`/`Kdf`
/// error if a crypto step fails.
pub fn seal(passphrase: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    let params = default_params()?;

    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|_| KeystoreError::Rng)?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| KeystoreError::Rng)?;

    let key = derive_key(passphrase, &salt, &params)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| KeystoreError::Crypto)?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| KeystoreError::Crypto)?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&params.m_cost().to_be_bytes());
    out.extend_from_slice(&params.t_cost().to_be_bytes());
    out.extend_from_slice(&params.p_cost().to_be_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob produced by [`seal`]. The plaintext is returned in a
/// [`Zeroizing`] buffer so it is wiped when dropped.
///
/// # Errors
/// [`KeystoreError::InvalidBlob`] if the bytes are not a well-formed blob,
/// [`KeystoreError::WrongPassphraseOrCorrupt`] if authentication fails.
pub fn open(passphrase: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    if blob.len() < HEADER_LEN || &blob[..MAGIC.len()] != MAGIC {
        return Err(KeystoreError::InvalidBlob);
    }

    // Fixed-offset header parse. try_into on a known-length slice can't fail.
    let m_cost = u32::from_be_bytes(blob[8..12].try_into().unwrap());
    let t_cost = u32::from_be_bytes(blob[12..16].try_into().unwrap());
    let p_cost = u32::from_be_bytes(blob[16..20].try_into().unwrap());
    if m_cost > MAX_M_COST || t_cost > MAX_T_COST || p_cost > MAX_P_COST {
        return Err(KeystoreError::InvalidBlob);
    }
    let salt = &blob[20..20 + SALT_LEN]; // 20..36
    let nonce = &blob[36..36 + NONCE_LEN]; // 36..60
    let ciphertext = &blob[HEADER_LEN..];

    let params = Params::new(m_cost, t_cost, p_cost, Some(KEY_LEN)).map_err(|_| KeystoreError::Params)?;
    let key = derive_key(passphrase, salt, &params)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| KeystoreError::Crypto)?;
    let plaintext = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| KeystoreError::WrongPassphraseOrCorrupt)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let secret = b"my ed25519 private key bytes...";
        let blob = seal(b"correct horse battery staple", secret).unwrap();
        let out = open(b"correct horse battery staple", &blob).unwrap();
        assert_eq!(&*out, secret);
    }

    #[test]
    fn empty_secret_roundtrips() {
        let blob = seal(b"pw", b"").unwrap();
        assert_eq!(&*open(b"pw", &blob).unwrap(), b"");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let blob = seal(b"right", b"secret").unwrap();
        assert_eq!(
            open(b"wrong", &blob),
            Err(KeystoreError::WrongPassphraseOrCorrupt)
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut blob = seal(b"pw", b"secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01; // flip a bit in the tag/ciphertext
        assert_eq!(
            open(b"pw", &blob),
            Err(KeystoreError::WrongPassphraseOrCorrupt)
        );
    }

    #[test]
    fn truncated_blob_fails() {
        let blob = seal(b"pw", b"secret").unwrap();
        assert_eq!(open(b"pw", &blob[..HEADER_LEN - 1]), Err(KeystoreError::InvalidBlob));
    }

    #[test]
    fn bad_magic_fails() {
        let mut blob = seal(b"pw", b"secret").unwrap();
        blob[0] ^= 0xff;
        assert_eq!(open(b"pw", &blob), Err(KeystoreError::InvalidBlob));
    }

    #[test]
    fn absurd_kdf_params_are_rejected_without_allocating() {
        let mut blob = seal(b"pw", b"secret").unwrap();
        // Set m_cost to u32::MAX; open must reject on the bound, not try to
        // allocate gigabytes.
        blob[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(open(b"pw", &blob), Err(KeystoreError::InvalidBlob));
    }

    #[test]
    fn fresh_randomness_each_seal() {
        let a = seal(b"pw", b"secret").unwrap();
        let b = seal(b"pw", b"secret").unwrap();
        assert_ne!(a, b); // different salt+nonce => different blobs
    }
}
