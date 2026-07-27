// SPDX-License-Identifier: AGPL-3.0-or-later
//! Post-quantum identity: Ed25519 **and** ML-DSA-65, together.
//!
//! # Why this exists
//!
//! Umbra already resists a future quantum computer where *confidentiality* is
//! concerned: sessions are set up with PQXDH, which mixes a post-quantum key
//! exchange into the handshake, so traffic recorded today cannot be opened
//! later. Identity was the hole. Every signature that says "this key bundle is
//! mine" was Ed25519, and Ed25519 is exactly what a quantum computer breaks.
//!
//! What that would buy an attacker is not old messages — it is the ability to
//! *become you*: forge an invite, sign a key bundle in your name, and sit in
//! the middle of a conversation in real time. Signal has the same gap and says
//! so; so does Briar. Closing it is what makes an identity issued today still
//! trustworthy after the machines arrive.
//!
//! # Hybrid, on purpose
//!
//! A signature counts only when **both** halves verify. ML-DSA is young — this
//! implementation more so — and a flaw in it must not be able to forge
//! anything, so Ed25519 stays underneath as the floor. The reverse also holds:
//! break Ed25519 with a quantum computer and ML-DSA still refuses. An attacker
//! needs both, which is the same reasoning PQXDH uses for key agreement.
//!
//! # One seed
//!
//! The ML-DSA key is derived from the *same* 32-byte identity seed as the
//! Ed25519 key, through a domain-separated hash. Nothing new to back up, and
//! every existing account grows a post-quantum half on its next start without
//! being asked anything.

use crate::identity::{self, Keypair, PublicKey};
use ml_dsa::{
    signature::{Signer, Verifier},
    EncodedSignature, EncodedVerifyingKey, KeyInit, Keypair as _, MlDsa65, Signature as MlSignature,
    SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};

/// Bytes of an encoded ML-DSA-65 public key.
pub const PQ_PUBLIC_LEN: usize = 1952;

/// Bytes of an encoded ML-DSA-65 signature.
pub const PQ_SIGNATURE_LEN: usize = 3309;

/// Separates the post-quantum key derivation from every other use of the seed.
const PQ_SEED_INFO: &[u8] = b"umbra post-quantum identity v1";

/// An identity that signs with both schemes.
pub struct HybridIdentity {
    ed: Keypair,
    pq: SigningKey<MlDsa65>,
}

impl HybridIdentity {
    /// Derive both halves from one 32-byte identity seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self { ed: Keypair::from_seed(seed), pq: pq_key_from_seed(seed) }
    }

    /// The classical half — what older peers and existing invites use.
    pub fn ed25519_public(&self) -> PublicKey {
        self.ed.public()
    }

    /// The post-quantum half, encoded (1952 bytes).
    pub fn pq_public(&self) -> Vec<u8> {
        self.pq.verifying_key().encode().to_vec()
    }

    /// A short commitment to the post-quantum key.
    ///
    /// This is what travels in an invite. The full key is 1952 bytes — too much
    /// for something people paste into a chat — so the invite carries 32 bytes
    /// and the key itself arrives during the handshake, where it is checked
    /// against this. An attacker who swaps the key has to break SHA-256.
    pub fn pq_fingerprint(&self) -> [u8; 32] {
        pq_fingerprint(&self.pq_public())
    }

    /// Sign with both keys. Layout: `ed25519 (64) || ml-dsa (3309)`.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + PQ_SIGNATURE_LEN);
        out.extend_from_slice(&self.ed.sign(message));
        out.extend_from_slice(&self.pq.sign(message).encode());
        out
    }
}

/// Derive the ML-DSA key from the identity seed, deterministically.
fn pq_key_from_seed(seed: &[u8; 32]) -> SigningKey<MlDsa65> {
    let mut h = Sha256::new();
    h.update(PQ_SEED_INFO);
    h.update(seed);
    let derived: [u8; 32] = h.finalize().into();
    SigningKey::<MlDsa65>::new(&derived.into())
}

/// The commitment an invite carries for a given encoded public key.
pub fn pq_fingerprint(pq_public: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"umbra pq fingerprint v1");
    h.update(pq_public);
    h.finalize().into()
}

/// Verify a hybrid signature. **Both** halves must check out.
///
/// Returns false on anything malformed rather than guessing, and never falls
/// back to verifying only the classical half — a downgrade of exactly that kind
/// is what an attacker would aim for.
pub fn verify_hybrid(
    ed_public: &PublicKey,
    pq_public: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    if signature.len() != 64 + PQ_SIGNATURE_LEN || pq_public.len() != PQ_PUBLIC_LEN {
        return false;
    }
    let (ed_sig, pq_sig) = signature.split_at(64);
    let ed_sig: [u8; 64] = match ed_sig.try_into() {
        Ok(s) => s,
        Err(_) => return false,
    };
    if !identity::verify(ed_public, message, &ed_sig) {
        return false;
    }

    let Ok(encoded_key) = EncodedVerifyingKey::<MlDsa65>::try_from(pq_public) else {
        return false;
    };
    let Ok(encoded_sig) = EncodedSignature::<MlDsa65>::try_from(pq_sig) else {
        return false;
    };
    let Some(sig) = MlSignature::<MlDsa65>::decode(&encoded_sig) else {
        return false;
    };
    VerifyingKey::<MlDsa65>::decode(&encoded_key).verify(message, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity_of(seed: u8) -> HybridIdentity {
        HybridIdentity::from_seed(&[seed; 32])
    }

    #[test]
    fn a_hybrid_signature_verifies_under_both_schemes() {
        let me = identity_of(1);
        let msg = b"prekey bundle";
        let sig = me.sign(msg);
        assert_eq!(sig.len(), 64 + PQ_SIGNATURE_LEN);
        assert!(verify_hybrid(&me.ed25519_public(), &me.pq_public(), msg, &sig));
        // A different message, or a different identity, must not pass.
        assert!(!verify_hybrid(&me.ed25519_public(), &me.pq_public(), b"other", &sig));
        let other = identity_of(2);
        assert!(!verify_hybrid(&other.ed25519_public(), &other.pq_public(), msg, &sig));
    }

    /// The whole point of the hybrid: breaking one scheme is not enough. Each
    /// half is corrupted in turn, and each time the signature must be refused.
    #[test]
    fn tampering_with_either_half_is_refused() {
        let me = identity_of(3);
        let msg = b"this is what gets signed";
        let good = me.sign(msg);

        let mut classical_broken = good.clone();
        classical_broken[0] ^= 0x01;
        assert!(
            !verify_hybrid(&me.ed25519_public(), &me.pq_public(), msg, &classical_broken),
            "a broken Ed25519 half must not be carried by the post-quantum one"
        );

        let mut pq_broken = good.clone();
        pq_broken[64] ^= 0x01;
        assert!(
            !verify_hybrid(&me.ed25519_public(), &me.pq_public(), msg, &pq_broken),
            "a broken ML-DSA half must not be carried by the classical one"
        );

        // Truncated to just the classical half: this is the downgrade an
        // attacker with a quantum computer would try, and it must not work.
        assert!(!verify_hybrid(&me.ed25519_public(), &me.pq_public(), msg, &good[..64]));
    }

    #[test]
    fn a_substituted_post_quantum_key_is_caught_by_the_fingerprint() {
        let me = identity_of(4);
        let impostor = identity_of(5);
        assert_eq!(me.pq_fingerprint(), pq_fingerprint(&me.pq_public()));
        assert_ne!(me.pq_fingerprint(), impostor.pq_fingerprint());
        // Swapping the key that arrives in the handshake changes the
        // fingerprint, which the invite already committed to.
        assert_ne!(me.pq_fingerprint(), pq_fingerprint(&impostor.pq_public()));
    }

    #[test]
    fn both_halves_come_from_the_one_seed() {
        let seed = [9u8; 32];
        let a = HybridIdentity::from_seed(&seed);
        let b = HybridIdentity::from_seed(&seed);
        assert_eq!(a.ed25519_public(), b.ed25519_public());
        assert_eq!(a.pq_public(), b.pq_public());
        assert_eq!(a.pq_public().len(), PQ_PUBLIC_LEN);
        // Existing accounts keep the identity their contacts already know.
        assert_eq!(a.ed25519_public(), Keypair::from_seed(&seed).public());
    }

    #[test]
    fn junk_is_rejected_rather_than_guessed_at() {
        let me = identity_of(6);
        let msg = b"x";
        let sig = me.sign(msg);
        assert!(!verify_hybrid(&me.ed25519_public(), &[], msg, &sig));
        assert!(!verify_hybrid(&me.ed25519_public(), &me.pq_public(), msg, &[]));
        assert!(!verify_hybrid(&me.ed25519_public(), &vec![0u8; PQ_PUBLIC_LEN], msg, &sig));
    }
}
