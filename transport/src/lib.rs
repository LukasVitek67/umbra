// SPDX-License-Identifier: AGPL-3.0-or-later
//! Umbra transport: the session handshake and framed message protocol that
//! carries the Double Ratchet over any byte stream (TCP now, Tor onion next).
//!
//! # Handshake (MITM-resistant)
//!
//! The account identity is an Ed25519 [`Keypair`] (the thing in the invite /
//! user code). The ratchet uses its own Curve25519 keys; we *bind* the two by
//! signing the Curve25519 key with the account key, so a peer can confirm the
//! ratchet key really belongs to the identity they expect.
//!
//! ```text
//! responder → PREKEY : curve_id(32) ‖ one_time(32) ‖ sig_acct(curve‖otk)(64)
//! initiator → HELLO  : ed25519(32) ‖ curve_id(32) ‖ sig_acct(curve)(64) ‖ type(1) ‖ olm_body
//! ```
//!
//! The initiator verifies PREKEY against the identity from the invite; the
//! responder verifies HELLO's binding signature. After that both sides hold a
//! ratchet session and exchange `type(1) ‖ olm_body` message frames.

use anyhow::{anyhow, bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use umbra_core::crypto::padding::{pad, unpad};
use umbra_core::crypto::ratchet::{RatchetAccount, RatchetSession};
use umbra_core::identity::{self, Keypair};

pub mod ctor;
pub mod tcp;

/// Reject absurd frame lengths (defends against a hostile/garbled peer).
const MAX_FRAME: usize = 1 << 20; // 1 MiB

/// Protocol magic the initiator sends first.
///
/// It identifies the protocol, and — importantly over Tor — it makes the client
/// speak first: a rendezvous stream is only driven end-to-end once the client
/// side has sent a data cell, so a protocol where the *responder* speaks first
/// can stall. Sending this greeting primes the circuit.
const HELLO_MAGIC: &[u8; 4] = b"UMB1";

/// A local node: the account identity plus its ratchet key store.
pub struct LocalNode {
    pub account: Keypair,
    pub ratchet: RatchetAccount,
}

impl LocalNode {
    /// Generate a brand-new node (fresh identity + ratchet keys).
    pub fn generate() -> Result<Self> {
        Ok(Self {
            account: Keypair::generate().map_err(|e| anyhow!("identity: {e}"))?,
            ratchet: RatchetAccount::new(),
        })
    }

    /// Rebuild a node from a saved identity seed (ratchet keys are fresh).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self { account: Keypair::from_seed(seed), ratchet: RatchetAccount::new() }
    }

    /// This node's Ed25519 identity public key.
    pub fn ed25519(&self) -> [u8; 32] {
        self.account.public()
    }
}

/// An established, ratcheting session with a peer.
pub struct Session {
    inner: RatchetSession,
}

impl Session {
    /// Turn a plaintext into a message-frame payload (`type ‖ olm_body`), with
    /// the payload length-hidden by padding first.
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let framed = pad(plaintext).expect("padding never fails for in-range input");
        let (t, body) = self.inner.encrypt_wire(&framed);
        let mut out = Vec::with_capacity(1 + body.len());
        out.push(t);
        out.extend_from_slice(&body);
        out
    }

    /// Recover a plaintext from a message-frame payload.
    pub fn decrypt_message(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let (&t, body) = payload.split_first().ok_or_else(|| anyhow!("empty message"))?;
        let framed = self.inner.decrypt_wire(t, body).map_err(|e| anyhow!("decrypt: {e}"))?;
        unpad(&framed).map_err(|e| anyhow!("unpad: {e}"))
    }
}

// --- framing ---------------------------------------------------------------

/// Write a length-prefixed frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> Result<()> {
    w.write_all(&(payload.len() as u32).to_be_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

/// Read a length-prefixed frame.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        bail!("frame too large: {len}");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

// --- handshake -------------------------------------------------------------

/// Initiator side. `peer_ed25519` is the identity we expect (from their invite);
/// the PREKEY is verified against it to prevent a man-in-the-middle.
pub async fn initiate<S>(stream: &mut S, node: &LocalNode, peer_ed25519: [u8; 32]) -> Result<Session>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Speak first (see HELLO_MAGIC): this both identifies the protocol and
    // primes the Tor rendezvous stream so the responder's reply flows back.
    stream.write_all(HELLO_MAGIC).await?;
    stream.flush().await?;

    let prekey = read_frame(stream).await?;
    if prekey.len() != 128 {
        bail!("bad PREKEY length {}", prekey.len());
    }
    let curve: [u8; 32] = prekey[0..32].try_into().unwrap();
    let otk: [u8; 32] = prekey[32..64].try_into().unwrap();
    let sig: [u8; 64] = prekey[64..128].try_into().unwrap();
    if !identity::verify(&peer_ed25519, &prekey[0..64], &sig) {
        bail!("PREKEY signature invalid — possible man-in-the-middle");
    }

    let mut inner = node
        .ratchet
        .create_outbound_bytes(curve, otk)
        .map_err(|e| anyhow!("outbound session: {e}"))?;

    // First (empty) message doubles as the prekey message the responder needs.
    let (t, body) = inner.encrypt_wire(&pad(b"").unwrap());
    let curve_id = node.ratchet.identity_key_bytes();
    let bind_sig = node.account.sign(&curve_id);

    let mut hello = Vec::with_capacity(128 + 1 + body.len());
    hello.extend_from_slice(&node.account.public());
    hello.extend_from_slice(&curve_id);
    hello.extend_from_slice(&bind_sig);
    hello.push(t);
    hello.extend_from_slice(&body);
    write_frame(stream, &hello).await?;

    Ok(Session { inner })
}

/// Responder side. Returns the session and the peer's verified Ed25519 identity.
pub async fn accept<S>(stream: &mut S, node: &mut LocalNode) -> Result<(Session, [u8; 32])>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Wait for the initiator's greeting before answering.
    let mut magic = [0u8; 4];
    stream.read_exact(&mut magic).await?;
    if &magic != HELLO_MAGIC {
        bail!("not an Umbra peer");
    }

    let (curve, otk) = node
        .ratchet
        .publish_prekey_bytes()
        .map_err(|e| anyhow!("prekey: {e}"))?;
    let mut prekey = Vec::with_capacity(128);
    prekey.extend_from_slice(&curve);
    prekey.extend_from_slice(&otk);
    let sig = node.account.sign(&prekey);
    prekey.extend_from_slice(&sig);
    write_frame(stream, &prekey).await?;

    let hello = read_frame(stream).await?;
    if hello.len() < 129 {
        bail!("bad HELLO length {}", hello.len());
    }
    let peer_ed: [u8; 32] = hello[0..32].try_into().unwrap();
    let peer_curve: [u8; 32] = hello[32..64].try_into().unwrap();
    let bind_sig: [u8; 64] = hello[64..128].try_into().unwrap();
    let t = hello[128];
    let body = &hello[129..];
    if !identity::verify(&peer_ed, &peer_curve, &bind_sig) {
        bail!("HELLO binding signature invalid — possible man-in-the-middle");
    }

    let (inner, _first) = node
        .ratchet
        .create_inbound_wire(peer_curve, t, body)
        .map_err(|e| anyhow!("inbound session: {e}"))?;
    Ok((Session { inner }, peer_ed))
}

// --- public frame I/O over an established session --------------------------

/// Send one message over a writer.
pub async fn send_message<W: AsyncWrite + Unpin>(
    w: &mut W,
    session: &mut Session,
    plaintext: &[u8],
) -> Result<()> {
    let payload = session.encrypt_message(plaintext);
    write_frame(w, &payload).await
}

/// Receive one message from a reader.
pub async fn recv_message<R: AsyncRead + Unpin>(
    r: &mut R,
    session: &mut Session,
) -> Result<Vec<u8>> {
    let payload = read_frame(r).await?;
    session.decrypt_message(&payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn handshake_and_bidirectional_messaging() {
        let alice = LocalNode::generate().unwrap(); // initiator
        let mut bob = LocalNode::generate().unwrap(); // responder
        let alice_ed = alice.ed25519();
        let bob_ed = bob.ed25519();

        let (mut a, mut b) = tokio::io::duplex(65536);

        // Run both sides of the handshake concurrently.
        let (ra, rb) = tokio::join!(
            initiate(&mut a, &alice, bob_ed),
            accept(&mut b, &mut bob),
        );
        let mut alice_s = ra.expect("initiate");
        let (mut bob_s, peer_ed) = rb.expect("accept");
        assert_eq!(peer_ed, alice_ed, "responder learns initiator's real identity");

        // Alice → Bob
        send_message(&mut a, &mut alice_s, b"ahoj bobe, sifrovane").await.unwrap();
        assert_eq!(recv_message(&mut b, &mut bob_s).await.unwrap(), b"ahoj bobe, sifrovane");

        // Bob → Alice
        send_message(&mut b, &mut bob_s, b"ahoj alice").await.unwrap();
        assert_eq!(recv_message(&mut a, &mut alice_s).await.unwrap(), b"ahoj alice");

        // Another round, ratchet advancing
        send_message(&mut a, &mut alice_s, b"jak se mas").await.unwrap();
        assert_eq!(recv_message(&mut b, &mut bob_s).await.unwrap(), b"jak se mas");
    }

    #[tokio::test]
    async fn wrong_expected_identity_is_rejected() {
        let alice = LocalNode::generate().unwrap();
        let mut bob = LocalNode::generate().unwrap();
        let wrong = LocalNode::generate().unwrap().ed25519();

        let (mut a, mut b) = tokio::io::duplex(65536);
        // The responder sends its PREKEY then blocks waiting for a HELLO that
        // never comes (the initiator bails), so run it detached.
        let responder = tokio::spawn(async move {
            let _ = accept(&mut b, &mut bob).await;
        });

        let result = initiate(&mut a, &alice, wrong).await;
        assert!(
            result.is_err(),
            "initiator must reject a PREKEY not signed by the expected identity"
        );
        responder.abort();
    }
}
