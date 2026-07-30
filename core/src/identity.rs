// SPDX-License-Identifier: AGPL-3.0-or-later
//! Self-sovereign identity and the signed, revocable device roster.
//!
//! There is **no account server**. An account *is* an Ed25519 [`Keypair`]. The
//! same key type identifies each linked **device**. Which devices are currently
//! valid for an identity is expressed by a [`Roster`] that the identity key
//! signs ([`SignedRoster`]); revoking a device appends a revocation and re-signs.
//! Contacts fetch the signed roster, verify it against the identity public key,
//! and trust only the active device keys. This is the "absolute overview of your
//! devices" requirement, realised without any central authority.
//!
//! The module is **clock-free**: timestamps (`now`, unix seconds) are supplied
//! by the caller, so behaviour is deterministic and testable.
//!
//! Wire encoding is a fixed, deterministic layout (below) so signatures are
//! reproducible. Signing is domain-separated to prevent cross-protocol reuse.

use crate::error::IdentityError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroizing;

/// Domain-separation tag mixed into every roster signature.
const ROSTER_DOMAIN: &[u8] = b"nullchat-roster-v1\0";
/// Magic prefixing a serialized [`SignedRoster`].
const ROSTER_MAGIC: &[u8; 8] = b"UMBRARO1";

/// A 32-byte Ed25519 public key (identity or device).
pub type PublicKey = [u8; 32];

/// An Ed25519 keypair. Used both for the account identity and for each device.
///
/// The secret seed lives in a [`Zeroizing`] buffer and is wiped on drop.
pub struct Keypair {
    signing: SigningKey,
}

impl Keypair {
    /// Generate a fresh keypair from the OS CSPRNG.
    pub fn generate() -> Result<Self, IdentityError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut *seed).map_err(|_| IdentityError::Rng)?;
        Ok(Self::from_seed(&seed))
    }

    /// Reconstruct a keypair from a 32-byte secret seed (e.g. after decrypting
    /// it out of the [`crate::crypto::keystore`]).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// This keypair's 32-byte secret seed, for sealing into the keystore. Handle
    /// with care; it is the whole secret.
    pub fn secret_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    /// The 32-byte public key.
    pub fn public(&self) -> PublicKey {
        self.signing.verifying_key().to_bytes()
    }

    /// Sign `msg`, returning a 64-byte detached signature.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let sig: Signature = self.signing.sign(msg);
        sig.to_bytes()
    }
}

/// Verify a detached Ed25519 signature. Returns `false` on any error (bad key
/// encoding, bad signature) — callers get a plain yes/no.
pub fn verify(public: &PublicKey, msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(public) else {
        return false;
    };
    vk.verify(msg, &Signature::from_bytes(sig)).is_ok()
}

/// A short, human-shareable code derived from the identity public key: Crockford
/// base32 of the first 80 bits, in dash-separated groups of four, e.g.
/// `K7QF-2M9X-4TP1-9WZ3`.
///
/// It is a *finding handle* for discovery/display only — the full 32-byte public
/// key stays the real identity, and a contact is always verified against it
/// (safety numbers), never against this shortened code alone.
pub fn user_code(pubkey: &PublicKey) -> String {
    // Crockford base32 (no I, L, O, U to avoid confusion).
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut chars = Vec::with_capacity(16);
    for chunk in pubkey[..10].chunks(5) {
        // Pack 5 bytes (40 bits) into the low bits of a u64.
        let mut five = [0u8; 5];
        five[..chunk.len()].copy_from_slice(chunk);
        let n = u64::from_be_bytes([0, 0, 0, five[0], five[1], five[2], five[3], five[4]]);
        for i in 0..8 {
            let idx = ((n >> ((7 - i) * 5)) & 0x1f) as usize;
            chars.push(ALPHABET[idx]);
        }
    }
    chars
        .chunks(4)
        .map(|g| core::str::from_utf8(g).expect("ascii"))
        .collect::<Vec<_>>()
        .join("-")
}

/// One device's standing within an identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEntry {
    /// The device's Ed25519 public key.
    pub pubkey: PublicKey,
    /// When the device was linked (unix seconds, caller-supplied).
    pub added_at: u64,
    /// Whether the device has been revoked. Revoked entries are kept (not
    /// deleted) so the revocation stays visible to peers.
    pub revoked: bool,
}

/// The set of devices for one identity, at one point in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roster {
    /// The identity this roster belongs to.
    pub identity: PublicKey,
    /// Monotonic-ish version stamp (unix seconds of last change). Peers keep the
    /// roster with the newer `updated_at`.
    pub updated_at: u64,
    /// Device entries, in insertion order.
    pub devices: Vec<DeviceEntry>,
}

impl Roster {
    /// A new, empty roster for `identity`.
    pub fn new(identity: PublicKey, now: u64) -> Self {
        Self { identity, updated_at: now, devices: Vec::new() }
    }

    /// Link a device. Returns `false` (and does nothing) if already present.
    pub fn add_device(&mut self, pubkey: PublicKey, now: u64) -> bool {
        if self.devices.iter().any(|d| d.pubkey == pubkey) {
            return false;
        }
        self.devices.push(DeviceEntry { pubkey, added_at: now, revoked: false });
        self.updated_at = now;
        true
    }

    /// Revoke a device. Returns `false` if it isn't present or was already
    /// revoked.
    pub fn revoke_device(&mut self, pubkey: &PublicKey, now: u64) -> bool {
        for d in &mut self.devices {
            if &d.pubkey == pubkey && !d.revoked {
                d.revoked = true;
                self.updated_at = now;
                return true;
            }
        }
        false
    }

    /// Is this device currently linked and not revoked?
    pub fn is_active(&self, pubkey: &PublicKey) -> bool {
        self.devices.iter().any(|d| &d.pubkey == pubkey && !d.revoked)
    }

    /// Deterministic byte encoding of the roster contents (no domain tag, no
    /// signature). Used for both signing and serialization.
    fn encode_core(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(32 + 8 + 4 + self.devices.len() * 41);
        v.extend_from_slice(&self.identity);
        v.extend_from_slice(&self.updated_at.to_be_bytes());
        v.extend_from_slice(&(self.devices.len() as u32).to_be_bytes());
        for d in &self.devices {
            v.extend_from_slice(&d.pubkey);
            v.extend_from_slice(&d.added_at.to_be_bytes());
            v.push(u8::from(d.revoked));
        }
        v
    }

    /// The exact bytes signed for this roster: domain tag then core encoding.
    fn signing_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(ROSTER_DOMAIN.len() + 44);
        v.extend_from_slice(ROSTER_DOMAIN);
        v.extend_from_slice(&self.encode_core());
        v
    }
}

/// A [`Roster`] plus the identity key's signature over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRoster {
    /// The signed roster contents.
    pub roster: Roster,
    /// Ed25519 signature by `roster.identity`.
    pub sig: [u8; 64],
}

impl SignedRoster {
    /// Sign `roster` with its identity keypair.
    ///
    /// # Errors
    /// [`IdentityError::IdentityMismatch`] if `identity`'s public key is not the
    /// roster's `identity`.
    pub fn sign(roster: Roster, identity: &Keypair) -> Result<Self, IdentityError> {
        if identity.public() != roster.identity {
            return Err(IdentityError::IdentityMismatch);
        }
        let sig = identity.sign(&roster.signing_bytes());
        Ok(Self { roster, sig })
    }

    /// Verify the signature against the roster's own identity key.
    pub fn verify(&self) -> bool {
        verify(&self.roster.identity, &self.roster.signing_bytes(), &self.sig)
    }

    /// Serialize to bytes: `MAGIC || core || signature`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let core = self.roster.encode_core();
        let mut v = Vec::with_capacity(ROSTER_MAGIC.len() + core.len() + 64);
        v.extend_from_slice(ROSTER_MAGIC);
        v.extend_from_slice(&core);
        v.extend_from_slice(&self.sig);
        v
    }

    /// Parse and **verify** a serialized signed roster. Never returns an
    /// unverified roster: a bad signature is [`IdentityError::SignatureInvalid`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        const HEAD: usize = 8 + 32 + 8 + 4; // magic + identity + updated_at + count
        if bytes.len() < HEAD || &bytes[..8] != ROSTER_MAGIC {
            return Err(IdentityError::InvalidData);
        }
        let mut o = 8;
        let identity: PublicKey = bytes[o..o + 32].try_into().unwrap();
        o += 32;
        let updated_at = u64::from_be_bytes(bytes[o..o + 8].try_into().unwrap());
        o += 8;
        let count = u32::from_be_bytes(bytes[o..o + 4].try_into().unwrap()) as usize;
        o += 4;

        // Remaining must be exactly count*41 device bytes + 64 signature bytes.
        let entries_len = count.checked_mul(41).ok_or(IdentityError::InvalidData)?;
        let expected = o
            .checked_add(entries_len)
            .and_then(|x| x.checked_add(64))
            .ok_or(IdentityError::InvalidData)?;
        if bytes.len() != expected {
            return Err(IdentityError::InvalidData);
        }

        let mut devices = Vec::with_capacity(count);
        for _ in 0..count {
            let pubkey: PublicKey = bytes[o..o + 32].try_into().unwrap();
            o += 32;
            let added_at = u64::from_be_bytes(bytes[o..o + 8].try_into().unwrap());
            o += 8;
            let revoked = match bytes[o] {
                0 => false,
                1 => true,
                _ => return Err(IdentityError::InvalidData),
            };
            o += 1;
            devices.push(DeviceEntry { pubkey, added_at, revoked });
        }

        let sig: [u8; 64] = bytes[o..o + 64].try_into().unwrap();
        let signed = Self { roster: Roster { identity, updated_at, devices }, sig };
        if !signed.verify() {
            return Err(IdentityError::SignatureInvalid);
        }
        Ok(signed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp_from(byte: u8) -> Keypair {
        Keypair::from_seed(&[byte; 32])
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let id = kp_from(1);
        let sig = id.sign(b"hello");
        assert!(verify(&id.public(), b"hello", &sig));
        assert!(!verify(&id.public(), b"hell0", &sig)); // wrong message
    }

    #[test]
    fn seed_roundtrip_is_stable() {
        let id = Keypair::from_seed(&[7u8; 32]);
        let again = Keypair::from_seed(&id.secret_seed());
        assert_eq!(id.public(), again.public());
    }

    #[test]
    fn generate_produces_distinct_keys() {
        let a = Keypair::generate().unwrap();
        let b = Keypair::generate().unwrap();
        assert_ne!(a.public(), b.public());
    }

    #[test]
    fn user_code_is_deterministic_and_formatted() {
        let a = kp_from(1).public();
        assert_eq!(user_code(&a), user_code(&a)); // deterministic
        let code = user_code(&a);
        assert_eq!(code.len(), 19); // 16 base32 chars + 3 dashes
        assert_eq!(code.chars().filter(|&c| c == '-').count(), 3);
        assert_eq!(user_code(&[0u8; 32]), "0000-0000-0000-0000");
        assert_ne!(user_code(&kp_from(1).public()), user_code(&kp_from(2).public()));
    }

    #[test]
    fn roster_add_revoke_is_active() {
        let id = kp_from(1);
        let dev = kp_from(2).public();
        let mut r = Roster::new(id.public(), 1000);
        assert!(r.add_device(dev, 1001));
        assert!(!r.add_device(dev, 1002)); // duplicate rejected
        assert!(r.is_active(&dev));
        assert_eq!(r.updated_at, 1001);
        assert!(r.revoke_device(&dev, 1003));
        assert!(!r.is_active(&dev));
        assert_eq!(r.updated_at, 1003);
        assert!(!r.revoke_device(&dev, 1004)); // already revoked
    }

    #[test]
    fn signed_roster_serialize_roundtrip() {
        let id = kp_from(9);
        let mut r = Roster::new(id.public(), 100);
        r.add_device(kp_from(2).public(), 101);
        r.add_device(kp_from(3).public(), 102);
        r.revoke_device(&kp_from(2).public(), 103);
        let signed = SignedRoster::sign(r.clone(), &id).unwrap();
        assert!(signed.verify());

        let bytes = signed.to_bytes();
        let parsed = SignedRoster::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.roster, r);
        assert_eq!(parsed, signed);
    }

    #[test]
    fn empty_roster_roundtrips() {
        let id = kp_from(5);
        let signed = SignedRoster::sign(Roster::new(id.public(), 0), &id).unwrap();
        let parsed = SignedRoster::from_bytes(&signed.to_bytes()).unwrap();
        assert!(parsed.roster.devices.is_empty());
    }

    #[test]
    fn wrong_identity_cannot_sign() {
        let id = kp_from(1);
        let other = kp_from(2);
        let r = Roster::new(id.public(), 0);
        assert_eq!(
            SignedRoster::sign(r, &other).map(|_| ()),
            Err(IdentityError::IdentityMismatch)
        );
    }

    #[test]
    fn tampered_roster_fails_signature() {
        let id = kp_from(1);
        let mut r = Roster::new(id.public(), 0);
        r.add_device(kp_from(2).public(), 1);
        let signed = SignedRoster::sign(r, &id).unwrap();
        let mut bytes = signed.to_bytes();
        // Flip a bit inside a device pubkey (after the 8+32+8+4 header).
        let idx = 8 + 32 + 8 + 4 + 1;
        bytes[idx] ^= 0x01;
        assert_eq!(
            SignedRoster::from_bytes(&bytes),
            Err(IdentityError::SignatureInvalid)
        );
    }

    #[test]
    fn truncated_and_bad_magic_rejected() {
        let id = kp_from(1);
        let signed = SignedRoster::sign(Roster::new(id.public(), 0), &id).unwrap();
        let bytes = signed.to_bytes();
        assert_eq!(SignedRoster::from_bytes(&bytes[..10]), Err(IdentityError::InvalidData));
        let mut bad = bytes.clone();
        bad[0] ^= 0xff;
        assert_eq!(SignedRoster::from_bytes(&bad), Err(IdentityError::InvalidData));
    }

    #[test]
    fn lying_count_is_rejected() {
        let id = kp_from(1);
        let signed = SignedRoster::sign(Roster::new(id.public(), 0), &id).unwrap();
        let mut bytes = signed.to_bytes();
        // Claim a huge device count; length check must reject cleanly.
        bytes[48..52].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(SignedRoster::from_bytes(&bytes), Err(IdentityError::InvalidData));
    }
}
