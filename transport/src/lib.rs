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
use umbra_core::crypto::signal::{PublishedBundle, SignalAccount};
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

/// A local node: the account identity. The message keys are per-connection —
/// see [`Session`].
pub struct LocalNode {
    pub account: Keypair,
}

impl LocalNode {
    /// Generate a brand-new node (fresh identity).
    pub fn generate() -> Result<Self> {
        Ok(Self { account: Keypair::generate().map_err(|e| anyhow!("identity: {e}"))? })
    }

    /// Rebuild a node from a saved identity seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self { account: Keypair::from_seed(seed) }
    }

    /// This node's Ed25519 identity public key.
    pub fn ed25519(&self) -> [u8; 32] {
        self.account.public()
    }
}

/// An established Signal session with one peer.
///
/// Each connection gets its own account and store, so the keys of one
/// conversation are never in reach of another, and a fresh PQXDH runs every
/// time you reconnect.
pub struct Session {
    inner: SignalAccount,
}

impl Session {
    /// Turn a plaintext into a message-frame payload (`type ‖ body`), with the
    /// payload length-hidden by padding first.
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let framed = pad(plaintext).expect("padding never fails for in-range input");
        let (t, body) = self.inner.encrypt(&framed).expect("session is established");
        let mut out = Vec::with_capacity(1 + body.len());
        out.push(t);
        out.extend_from_slice(&body);
        out
    }

    /// Recover a plaintext from a message-frame payload.
    pub fn decrypt_message(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let (&t, body) = payload.split_first().ok_or_else(|| anyhow!("empty message"))?;
        let framed = self.inner.decrypt(t, body).map_err(|e| anyhow!("decrypt: {e}"))?;
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

    // The responder's bundle: their Signal prekeys, signed by the Ed25519
    // identity we expect. The signature is the whole defence against a man in
    // the middle — anyone can offer keys, only they can sign them.
    let frame = read_frame(stream).await?;
    if frame.len() < 64 {
        bail!("bad PREKEY length {}", frame.len());
    }
    let split = frame.len() - 64;
    let (bundle_bytes, sig) = frame.split_at(split);
    let sig: [u8; 64] = sig.try_into().unwrap();
    if !identity::verify(&peer_ed25519, bundle_bytes, &sig) {
        bail!("PREKEY signature invalid — possible man-in-the-middle");
    }

    let mut inner = SignalAccount::new().map_err(|e| anyhow!("session keys: {e}"))?;
    inner
        .start_session(&PublishedBundle::from_bytes(bundle_bytes))
        .map_err(|e| anyhow!("outbound session: {e}"))?;

    // First (empty) message doubles as the prekey message the responder needs.
    let (t, body) = inner.encrypt(&pad(b"").unwrap()).map_err(|e| anyhow!("first message: {e}"))?;
    // Bind our own identity to this connection the same way.
    let bind_sig = node.account.sign(&body);

    let mut hello = Vec::with_capacity(97 + body.len());
    hello.extend_from_slice(&node.account.public());
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

    // Fresh Signal keys for this connection, signed by our long-term identity.
    let mut inner = SignalAccount::new().map_err(|e| anyhow!("session keys: {e}"))?;
    let bundle = inner.publish_bundle().map_err(|e| anyhow!("prekey: {e}"))?;
    let mut prekey = bundle.as_bytes().to_vec();
    let sig = node.account.sign(bundle.as_bytes());
    prekey.extend_from_slice(&sig);
    write_frame(stream, &prekey).await?;

    let hello = read_frame(stream).await?;
    if hello.len() < 98 {
        bail!("bad HELLO length {}", hello.len());
    }
    let peer_ed: [u8; 32] = hello[0..32].try_into().unwrap();
    let bind_sig: [u8; 64] = hello[32..96].try_into().unwrap();
    let t = hello[96];
    let body = &hello[97..];
    // The signature covers their first message, so the identity they claim is
    // the identity that produced this session.
    if !identity::verify(&peer_ed, body, &bind_sig) {
        bail!("HELLO binding signature invalid — possible man-in-the-middle");
    }

    inner
        .decrypt(t, body)
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
