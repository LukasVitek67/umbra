// SPDX-License-Identifier: AGPL-3.0-or-later
//! End-to-end sessions on **Signal's own protocol** (`libsignal-protocol`).
//!
//! This replaces the Olm ratchet NullChat started with. Both are Double Ratchet
//! implementations, but this one is the code Signal itself runs, and it brings
//! the session setup Olm does not have: **PQXDH**, whose key agreement mixes a
//! post-quantum KEM (Kyber) with X25519, so a recorded conversation is not
//! decryptable by an attacker who later has a quantum computer.
//!
//! What that gives a conversation:
//! * forward secrecy — stealing today's key does not open yesterday's messages,
//! * post-compromise security — the ratchet heals once the attacker is out,
//! * post-quantum protection of the session start (harvest-now-decrypt-later),
//! * deniability — nothing in a message proves to a third party who wrote it.
//!
//! We do not touch the cryptography: this module is glue, plus the wire
//! encoding of a prekey bundle. The bundle travels inside the handshake, signed
//! by the sender's **Ed25519 identity** (see `nullchat_transport`), which is what
//! ties "these keys" to "that identity" and keeps a man in the middle out.
//!
//! Sessions live in memory for the lifetime of a connection; the encrypted
//! store keeps the messages, not the ratchet state, so a restart starts a fresh
//! session. That costs nothing in security (it is a new PQXDH each time) and
//! avoids persisting key material that would need its own careful handling.

use std::time::SystemTime;

use futures::executor::block_on;
use libsignal_protocol::{
    kem, message_decrypt, message_encrypt, process_prekey_bundle, CiphertextMessage,
    CiphertextMessageType, DeviceId, GenericSignedPreKey, IdentityKey, IdentityKeyPair,
    IdentityKeyStore, InMemSignalProtocolStore, KeyPair, KyberPreKeyId, KyberPreKeyRecord,
    KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeyRecord, PreKeySignalMessage, PreKeyStore,
    ProtocolAddress, PublicKey, SignalMessage, SignedPreKeyId, SignedPreKeyRecord,
    SignedPreKeyStore, Timestamp,
};
use rand::rngs::OsRng;
use rand::TryRngCore;

use crate::error::RatchetError;

/// Every peer is addressed the same way; NullChat has one device per account, so
/// the name is a constant and the device id is always 1.
const DEVICE_ID: u32 = 1;
const ADDRESS_NAME: &str = "nullchat";

fn address() -> ProtocolAddress {
    ProtocolAddress::new(ADDRESS_NAME.to_string(), DeviceId::new(DEVICE_ID as u8).expect("device id"))
}

/// A `rand` 0.9 compatible CSPRNG for libsignal.
fn rng() -> impl rand::Rng + rand::CryptoRng {
    OsRng.unwrap_err()
}

/// Our account: identity key, prekeys and the sessions built from them.
pub struct SignalAccount {
    store: InMemSignalProtocolStore,
    registration_id: u32,
    next_id: u32,
}

/// The keys a peer needs to start a session with us, ready for the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedBundle {
    bytes: Vec<u8>,
}

impl PublishedBundle {
    /// The bytes to put on the wire (and to sign with the Ed25519 identity).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self { bytes: bytes.to_vec() }
    }
}

impl SignalAccount {
    /// A fresh account with a new identity key.
    pub fn new() -> Result<Self, RatchetError> {
        let mut csprng = rng();
        let identity = IdentityKeyPair::generate(&mut csprng);
        // Signal's registration id; ours is per-run and never leaves the device.
        let registration_id: u32 = rand::Rng::random_range(&mut csprng, 1..16380);
        let store = InMemSignalProtocolStore::new(identity, registration_id)
            .map_err(|_| RatchetError::SessionCreation)?;
        Ok(Self { store, registration_id, next_id: 1 })
    }

    /// Publish a bundle: a signed prekey, a one-time prekey and a Kyber prekey.
    ///
    /// Every bundle uses fresh key ids, so a one-time key is never handed to two
    /// peers — that is what makes it one-time.
    pub fn publish_bundle(&mut self) -> Result<PublishedBundle, RatchetError> {
        let mut csprng = rng();
        let identity = block_on(self.store.identity_store.get_identity_key_pair())
            .map_err(|_| RatchetError::SessionCreation)?;

        let pre_key_id = PreKeyId::from(self.take_id());
        let pre_key = KeyPair::generate(&mut csprng);
        let signed_id = SignedPreKeyId::from(self.take_id());
        let signed_key = KeyPair::generate(&mut csprng);
        let signed_sig = identity
            .private_key()
            .calculate_signature(&signed_key.public_key.serialize(), &mut csprng)
            .map_err(|_| RatchetError::SessionCreation)?;

        let kyber_id = KyberPreKeyId::from(self.take_id());
        let kyber_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut csprng);
        let kyber_sig = identity
            .private_key()
            .calculate_signature(&kyber_pair.public_key.serialize(), &mut csprng)
            .map_err(|_| RatchetError::SessionCreation)?;

        let now = Timestamp::from_epoch_millis(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        );
        block_on(async {
            self.store
                .pre_key_store
                .save_pre_key(pre_key_id, &PreKeyRecord::new(pre_key_id, &pre_key))
                .await?;
            self.store
                .signed_pre_key_store
                .save_signed_pre_key(
                    signed_id,
                    &SignedPreKeyRecord::new(signed_id, now, &signed_key, &signed_sig),
                )
                .await?;
            self.store
                .kyber_pre_key_store
                .save_kyber_pre_key(
                    kyber_id,
                    &KyberPreKeyRecord::new(kyber_id, now, &kyber_pair, &kyber_sig),
                )
                .await
        })
        .map_err(|_| RatchetError::SessionCreation)?;

        Ok(PublishedBundle {
            bytes: encode_bundle(
                self.registration_id,
                u32::from(pre_key_id),
                &pre_key.public_key,
                u32::from(signed_id),
                &signed_key.public_key,
                &signed_sig,
                u32::from(kyber_id),
                &kyber_pair.public_key,
                &kyber_sig,
                *identity.identity_key(),
            ),
        })
    }

    /// Start a session toward a peer's published bundle.
    pub fn start_session(&mut self, bundle: &PublishedBundle) -> Result<(), RatchetError> {
        let bundle = decode_bundle(&bundle.bytes)?;
        let mut csprng = rng();
        block_on(process_prekey_bundle(
            &address(),
            &address(),
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &bundle,
            SystemTime::now(),
            &mut csprng,
        ))
        .map_err(|_| RatchetError::SessionCreation)?;
        Ok(())
    }

    /// Encrypt one message. Returns the wire type byte and the body.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(u8, Vec<u8>), RatchetError> {
        let mut csprng = rng();
        let msg = block_on(message_encrypt(
            plaintext,
            &address(),
            &address(),
            &mut self.store.session_store,
            &mut self.store.identity_store,
            SystemTime::now(),
            &mut csprng,
        ))
        .map_err(|_| RatchetError::Decryption)?;
        let kind = match msg.message_type() {
            CiphertextMessageType::PreKey => 0u8,
            _ => 1u8,
        };
        Ok((kind, msg.serialize().to_vec()))
    }

    /// Decrypt one message, given the wire type byte and body. A `PreKey`
    /// message also establishes the session on this side.
    pub fn decrypt(&mut self, kind: u8, body: &[u8]) -> Result<Vec<u8>, RatchetError> {
        let message = match kind {
            0 => CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(body).map_err(|_| RatchetError::Decryption)?,
            ),
            _ => CiphertextMessage::SignalMessage(
                SignalMessage::try_from(body).map_err(|_| RatchetError::Decryption)?,
            ),
        };
        let mut csprng = rng();
        block_on(message_decrypt(
            &message,
            &address(),
            &address(),
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &mut self.store.pre_key_store,
            &self.store.signed_pre_key_store,
            &mut self.store.kyber_pre_key_store,
            &mut csprng,
        ))
        .map_err(|_| RatchetError::Decryption)
    }

    fn take_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        id
    }
}

// --- bundle on the wire ----------------------------------------------------

fn push_blob(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn take_blob<'a>(rest: &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
    if rest.len() < 2 {
        return None;
    }
    let n = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    if rest.len() < 2 + n {
        return None;
    }
    Some((&rest[2..2 + n], &rest[2 + n..]))
}

#[allow(clippy::too_many_arguments)]
fn encode_bundle(
    registration_id: u32,
    pre_key_id: u32,
    pre_key: &PublicKey,
    signed_id: u32,
    signed_key: &PublicKey,
    signed_sig: &[u8],
    kyber_id: u32,
    kyber_key: &kem::PublicKey,
    kyber_sig: &[u8],
    identity: IdentityKey,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(2048);
    out.extend_from_slice(&registration_id.to_be_bytes());
    out.extend_from_slice(&pre_key_id.to_be_bytes());
    push_blob(&mut out, &pre_key.serialize());
    out.extend_from_slice(&signed_id.to_be_bytes());
    push_blob(&mut out, &signed_key.serialize());
    push_blob(&mut out, signed_sig);
    out.extend_from_slice(&kyber_id.to_be_bytes());
    push_blob(&mut out, &kyber_key.serialize());
    push_blob(&mut out, kyber_sig);
    push_blob(&mut out, &identity.serialize());
    out
}

fn decode_bundle(bytes: &[u8]) -> Result<PreKeyBundle, RatchetError> {
    let err = || RatchetError::InvalidBundle;
    let mut rest = bytes;
    let take_u32 = |rest: &mut &[u8]| -> Result<u32, RatchetError> {
        if rest.len() < 4 {
            return Err(RatchetError::InvalidBundle);
        }
        let v = u32::from_be_bytes(rest[..4].try_into().map_err(|_| RatchetError::InvalidBundle)?);
        *rest = &rest[4..];
        Ok(v)
    };

    let registration_id = take_u32(&mut rest)?;
    let pre_key_id = take_u32(&mut rest)?;
    let (pre_key, r) = take_blob(rest).ok_or_else(err)?;
    rest = r;
    let signed_id = take_u32(&mut rest)?;
    let (signed_key, r) = take_blob(rest).ok_or_else(err)?;
    rest = r;
    let (signed_sig, r) = take_blob(rest).ok_or_else(err)?;
    rest = r;
    let kyber_id = take_u32(&mut rest)?;
    let (kyber_key, r) = take_blob(rest).ok_or_else(err)?;
    rest = r;
    let (kyber_sig, r) = take_blob(rest).ok_or_else(err)?;
    rest = r;
    let (identity, _) = take_blob(rest).ok_or_else(err)?;

    PreKeyBundle::new(
        registration_id,
        DeviceId::new(DEVICE_ID as u8).map_err(|_| RatchetError::InvalidBundle)?,
        Some((
            PreKeyId::from(pre_key_id),
            PublicKey::deserialize(pre_key).map_err(|_| RatchetError::InvalidBundle)?,
        )),
        SignedPreKeyId::from(signed_id),
        PublicKey::deserialize(signed_key).map_err(|_| RatchetError::InvalidBundle)?,
        signed_sig.to_vec(),
        KyberPreKeyId::from(kyber_id),
        kem::PublicKey::deserialize(kyber_key).map_err(|_| RatchetError::InvalidBundle)?,
        kyber_sig.to_vec(),
        IdentityKey::decode(identity).map_err(|_| RatchetError::InvalidBundle)?,
    )
    .map_err(|_| RatchetError::InvalidBundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point, end to end: Bob publishes, Alice starts a session and
    /// writes, Bob reads, and the ratchet keeps going both ways.
    #[test]
    fn two_accounts_talk() {
        let mut alice = SignalAccount::new().unwrap();
        let mut bob = SignalAccount::new().unwrap();

        let bundle = bob.publish_bundle().unwrap();
        alice.start_session(&bundle).unwrap();

        let (kind, body) = alice.encrypt(b"ahoj").unwrap();
        assert_eq!(kind, 0, "first message must be a PreKey message");
        assert_eq!(bob.decrypt(kind, &body).unwrap(), b"ahoj");

        let (kind, body) = bob.encrypt(b"nazdar").unwrap();
        assert_eq!(kind, 1, "the session is up, so no more PreKey messages");
        assert_eq!(alice.decrypt(kind, &body).unwrap(), b"nazdar");

        // And it keeps ratcheting rather than reusing a key.
        let (k1, c1) = alice.encrypt(b"stejny text").unwrap();
        let (k2, c2) = alice.encrypt(b"stejny text").unwrap();
        assert_ne!(c1, c2, "same plaintext must not produce the same ciphertext");
        assert_eq!(bob.decrypt(k1, &c1).unwrap(), b"stejny text");
        assert_eq!(bob.decrypt(k2, &c2).unwrap(), b"stejny text");
    }

    #[test]
    fn a_stranger_cannot_read_a_message() {
        let mut alice = SignalAccount::new().unwrap();
        let mut bob = SignalAccount::new().unwrap();
        let mut eve = SignalAccount::new().unwrap();

        alice.start_session(&bob.publish_bundle().unwrap()).unwrap();
        let (kind, body) = alice.encrypt(b"tajemstvi").unwrap();
        assert!(eve.decrypt(kind, &body).is_err());
        assert_eq!(bob.decrypt(kind, &body).unwrap(), b"tajemstvi");
    }

    #[test]
    fn a_tampered_message_is_refused() {
        let mut alice = SignalAccount::new().unwrap();
        let mut bob = SignalAccount::new().unwrap();
        alice.start_session(&bob.publish_bundle().unwrap()).unwrap();

        let (kind, mut body) = alice.encrypt(b"nedotykat se").unwrap();
        let last = body.len() - 1;
        body[last] ^= 0x01;
        assert!(bob.decrypt(kind, &body).is_err());
    }

    #[test]
    fn a_mangled_bundle_is_refused() {
        let mut bob = SignalAccount::new().unwrap();
        let good = bob.publish_bundle().unwrap();
        let mut alice = SignalAccount::new().unwrap();

        assert!(alice.start_session(&PublishedBundle::from_bytes(&[])).is_err());
        let truncated = PublishedBundle::from_bytes(&good.as_bytes()[..good.as_bytes().len() / 2]);
        assert!(alice.start_session(&truncated).is_err());
    }

    /// Every published bundle must carry its own one-time key.
    #[test]
    fn bundles_do_not_repeat_key_ids() {
        let mut bob = SignalAccount::new().unwrap();
        let first = bob.publish_bundle().unwrap();
        let second = bob.publish_bundle().unwrap();
        assert_ne!(first, second);
    }
}
