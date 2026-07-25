// SPDX-License-Identifier: AGPL-3.0-or-later
//! End-to-end message sessions built on the Olm Double Ratchet (`vodozemac`).
//!
//! This is the layer that gives forward secrecy and post-compromise security:
//! each message uses a fresh key, so stealing one key neither decrypts history
//! nor all future messages. We do not implement the ratchet ourselves — this is
//! a thin, testable wrapper over `vodozemac`'s audited Olm implementation.
//!
//! Flow (MVP, both peers exchange a prekey bundle out-of-band in the invite):
//! 1. Bob publishes a [`PreKeyBundle`] (his identity key + a one-time key).
//! 2. Alice creates an outbound [`RatchetSession`] to that bundle and sends a
//!    first message (an Olm "pre-key" message).
//! 3. Bob turns that first message into an inbound session and recovers the
//!    plaintext. From then on both sides ratchet normally.

use crate::error::RatchetError;
use vodozemac::olm::{Account, OlmMessage, Session, SessionConfig};
use vodozemac::Curve25519PublicKey;

/// A published bundle another peer uses to start a session with us.
#[derive(Debug, Clone)]
pub struct PreKeyBundle {
    /// Our long-term Curve25519 identity key.
    pub identity_key: Curve25519PublicKey,
    /// A one-time Curve25519 key, consumed on first use.
    pub one_time_key: Curve25519PublicKey,
}

/// A per-account Olm store: our identity keys plus unpublished one-time keys.
pub struct RatchetAccount {
    inner: Account,
}

impl RatchetAccount {
    /// Create a fresh account with new identity keys.
    pub fn new() -> Self {
        Self { inner: Account::new() }
    }

    /// Our long-term Curve25519 identity key.
    pub fn identity_key(&self) -> Curve25519PublicKey {
        self.inner.curve25519_key()
    }

    /// Generate and return a fresh [`PreKeyBundle`] (one one-time key), marking
    /// keys as published so they aren't handed out twice.
    pub fn publish_prekey_bundle(&mut self) -> Result<PreKeyBundle, RatchetError> {
        self.inner.generate_one_time_keys(1);
        let one_time_key = *self
            .inner
            .one_time_keys()
            .values()
            .next()
            .ok_or(RatchetError::NoOneTimeKey)?;
        let bundle = PreKeyBundle { identity_key: self.inner.curve25519_key(), one_time_key };
        self.inner.mark_keys_as_published();
        Ok(bundle)
    }

    /// Start an outbound session toward `bundle`.
    pub fn create_outbound(&self, bundle: &PreKeyBundle) -> RatchetSession {
        let session = self.inner.create_outbound_session(
            SessionConfig::version_2(),
            bundle.identity_key,
            bundle.one_time_key,
        );
        RatchetSession { inner: session }
    }

    /// Turn a peer's first (pre-key) message into an inbound session, returning
    /// the session and the recovered first plaintext.
    pub fn create_inbound(
        &mut self,
        their_identity_key: Curve25519PublicKey,
        first_message: &OlmMessage,
    ) -> Result<(RatchetSession, Vec<u8>), RatchetError> {
        let prekey = match first_message {
            OlmMessage::PreKey(m) => m,
            OlmMessage::Normal(_) => return Err(RatchetError::ExpectedPreKey),
        };
        let result = self
            .inner
            .create_inbound_session(their_identity_key, prekey)
            .map_err(|_| RatchetError::SessionCreation)?;
        Ok((RatchetSession { inner: result.session }, result.plaintext))
    }
}

impl Default for RatchetAccount {
    fn default() -> Self {
        Self::new()
    }
}

/// An established E2E session. Encrypt/decrypt ratcheting message keys.
pub struct RatchetSession {
    inner: Session,
}

impl RatchetSession {
    /// Encrypt `plaintext` into an Olm message.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> OlmMessage {
        self.inner.encrypt(plaintext)
    }

    /// Decrypt an Olm message.
    pub fn decrypt(&mut self, message: &OlmMessage) -> Result<Vec<u8>, RatchetError> {
        self.inner.decrypt(message).map_err(|_| RatchetError::Decryption)
    }
}

// --- byte-oriented wire API (keeps vodozemac types inside core) ------------

impl RatchetAccount {
    /// This account's Curve25519 identity key as raw bytes.
    pub fn identity_key_bytes(&self) -> [u8; 32] {
        self.inner.curve25519_key().to_bytes()
    }

    /// Generate a one-time prekey and return `(curve25519 identity, one-time key)`
    /// as raw bytes, for putting on the wire during a handshake.
    pub fn publish_prekey_bytes(&mut self) -> Result<([u8; 32], [u8; 32]), RatchetError> {
        let bundle = self.publish_prekey_bundle()?;
        Ok((bundle.identity_key.to_bytes(), bundle.one_time_key.to_bytes()))
    }

    /// Create an outbound session from a peer's prekey bytes.
    pub fn create_outbound_bytes(
        &self,
        peer_identity: [u8; 32],
        peer_one_time: [u8; 32],
    ) -> Result<RatchetSession, RatchetError> {
        let identity_key =
            Curve25519PublicKey::from_bytes(peer_identity);
        let one_time_key =
            Curve25519PublicKey::from_bytes(peer_one_time);
        Ok(self.create_outbound(&PreKeyBundle { identity_key, one_time_key }))
    }

    /// Accept an inbound session from a peer's first wire message
    /// `(msg_type, body)`, returning the session and the recovered first payload.
    pub fn create_inbound_wire(
        &mut self,
        peer_identity: [u8; 32],
        msg_type: u8,
        body: &[u8],
    ) -> Result<(RatchetSession, Vec<u8>), RatchetError> {
        let their_identity = Curve25519PublicKey::from_bytes(peer_identity);
        let msg = OlmMessage::from_parts(msg_type as usize, body)
            .map_err(|_| RatchetError::SessionCreation)?;
        self.create_inbound(their_identity, &msg)
    }
}

impl RatchetSession {
    /// Encrypt to wire form: `(message type, ciphertext bytes)`.
    pub fn encrypt_wire(&mut self, plaintext: &[u8]) -> (u8, Vec<u8>) {
        let (t, body) = self.inner.encrypt(plaintext).to_parts();
        (t as u8, body)
    }

    /// Decrypt from wire form `(message type, ciphertext bytes)`.
    pub fn decrypt_wire(&mut self, msg_type: u8, body: &[u8]) -> Result<Vec<u8>, RatchetError> {
        let msg = OlmMessage::from_parts(msg_type as usize, body)
            .map_err(|_| RatchetError::Decryption)?;
        self.decrypt(&msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_bytes_roundtrip() {
        // Same as the full conversation, but through the byte-oriented API.
        let alice = RatchetAccount::new();
        let mut bob = RatchetAccount::new();
        let (bob_id, bob_otk) = bob.publish_prekey_bytes().unwrap();
        let mut alice_s = alice.create_outbound_bytes(bob_id, bob_otk).unwrap();

        let (t, body) = alice_s.encrypt_wire(b"hello over the wire");
        let (mut bob_s, first) =
            bob.create_inbound_wire(alice.identity_key_bytes(), t, &body).unwrap();
        assert_eq!(first, b"hello over the wire");

        let (t2, body2) = bob_s.encrypt_wire(b"reply");
        assert_eq!(alice_s.decrypt_wire(t2, &body2).unwrap(), b"reply");
    }

    #[test]
    fn full_e2e_conversation() {
        let alice = RatchetAccount::new();
        let mut bob = RatchetAccount::new();

        // Bob publishes a bundle; Alice starts a session and says hi.
        let bundle = bob.publish_prekey_bundle().unwrap();
        let mut alice_session = alice.create_outbound(&bundle);
        let msg1 = alice_session.encrypt(b"hi bob");

        // Bob accepts the pre-key message and recovers the plaintext.
        let (mut bob_session, first) =
            bob.create_inbound(alice.identity_key(), &msg1).unwrap();
        assert_eq!(first, b"hi bob");

        // Ratchet both directions.
        let reply = bob_session.encrypt(b"hi alice");
        assert_eq!(alice_session.decrypt(&reply).unwrap(), b"hi alice");

        let msg3 = alice_session.encrypt(b"how are you");
        assert_eq!(bob_session.decrypt(&msg3).unwrap(), b"how are you");
    }

    #[test]
    fn create_inbound_requires_a_prekey_message() {
        let alice = RatchetAccount::new();
        let mut bob = RatchetAccount::new();
        let bundle = bob.publish_prekey_bundle().unwrap();
        let mut alice_session = alice.create_outbound(&bundle);

        let first = alice_session.encrypt(b"hi"); // pre-key message
        let (mut bob_session, _) = bob.create_inbound(alice.identity_key(), &first).unwrap();

        // Once the session has ratcheted, Alice's messages become "normal".
        let reply = bob_session.encrypt(b"yo");
        alice_session.decrypt(&reply).unwrap();
        let normal = alice_session.encrypt(b"second");

        // Feeding a normal (non-pre-key) message to create_inbound is a usage
        // error our wrapper reports cleanly.
        let mut fresh = RatchetAccount::new();
        assert!(matches!(
            fresh.create_inbound(alice.identity_key(), &normal),
            Err(RatchetError::ExpectedPreKey)
        ));
    }

    #[test]
    fn stranger_cannot_forge_into_session() {
        let alice = RatchetAccount::new();
        let mut bob = RatchetAccount::new();
        let bundle = bob.publish_prekey_bundle().unwrap();
        let mut alice_session = alice.create_outbound(&bundle);
        let first = alice_session.encrypt(b"hi");
        let (mut bob_session, _) = bob.create_inbound(alice.identity_key(), &first).unwrap();

        // A third party opening its own session to a different account produces
        // messages Bob's alice-session must reject.
        let mallory = RatchetAccount::new();
        let mut victim = RatchetAccount::new();
        let vb = victim.publish_prekey_bundle().unwrap();
        let mut mallory_session = mallory.create_outbound(&vb);
        let forged = mallory_session.encrypt(b"i am alice");
        assert!(bob_session.decrypt(&forged).is_err());
    }
}
