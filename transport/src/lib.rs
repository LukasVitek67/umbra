// SPDX-License-Identifier: AGPL-3.0-or-later
//! NullChat transport: the session handshake and framed message protocol that
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
use nullchat_core::crypto::padding::{pad, unpad};
use nullchat_core::crypto::pq::{self, HybridIdentity, PQ_PUBLIC_LEN, PQ_SIGNATURE_LEN};
use nullchat_core::crypto::signal::{PublishedBundle, SignalAccount};
use nullchat_core::identity::{self, Keypair};

/// Ed25519 (64) plus ML-DSA-65 (3309).
const HYBRID_SIG_LEN: usize = 64 + PQ_SIGNATURE_LEN;

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
///
/// It is also how the two sides agree on a wire version, and it has to be,
/// because the responder must know which PREKEY format to send *before* it
/// hears anything else. `UMB1` is the classical handshake (wire 2, Ed25519
/// only); `UMB3` is the hybrid one (wire 3, Ed25519 + ML-DSA).
const HELLO_MAGIC: &[u8; 4] = b"UMB1";
const HELLO_MAGIC_HYBRID: &[u8; 4] = b"UMB3";

/// Marks the one failure that may be retried without post-quantum signatures:
/// the peer hung up on the hybrid greeting without ever answering.
///
/// This distinction is the whole safety of the fallback. A handshake that got
/// as far as a *signature that did not verify* must never be retried at a lower
/// level — that is exactly the downgrade an attacker would engineer, blocking
/// the strong handshake to force the weak one. Only "they do not speak this at
/// all" qualifies.
pub const PEER_REFUSED_HYBRID: &str = "peer does not speak the hybrid handshake";

/// Which handshake a session ended up using.
///
/// Worth surfacing rather than hiding: a conversation that fell back to the
/// classical handshake is protected by Ed25519 alone, and the person having it
/// deserves to know that instead of assuming the newest guarantees apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireLevel {
    /// Ed25519 only — the other side is too old for post-quantum identities.
    Classical,
    /// Ed25519 + ML-DSA-65.
    Hybrid,
}

/// A local node: the account identity. The message keys are per-connection —
/// see [`Session`].
pub struct LocalNode {
    pub account: Keypair,
    /// The same identity, in both schemes. Derived from the same seed, so an
    /// existing account grows its post-quantum half without being asked.
    pq: HybridIdentity,
}

impl LocalNode {
    /// Generate a brand-new node (fresh identity).
    pub fn generate() -> Result<Self> {
        let account = Keypair::generate().map_err(|e| anyhow!("identity: {e}"))?;
        let seed = account.secret_seed();
        Ok(Self { pq: HybridIdentity::from_seed(&seed), account })
    }

    /// Rebuild a node from a saved identity seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self { account: Keypair::from_seed(seed), pq: HybridIdentity::from_seed(seed) }
    }

    /// This node's Ed25519 identity public key.
    pub fn ed25519(&self) -> [u8; 32] {
        self.account.public()
    }

    /// This node's ML-DSA public key, encoded.
    pub fn pq_public(&self) -> Vec<u8> {
        self.pq.pq_public()
    }

    /// The 32-byte commitment that goes into an invite.
    pub fn pq_fingerprint(&self) -> [u8; 32] {
        self.pq.pq_fingerprint()
    }
}

/// Who the other end turned out to be, in both schemes.
pub struct PeerIdentity {
    /// Their Ed25519 identity key.
    pub ed25519: [u8; 32],
    /// Their encoded ML-DSA public key, empty if they are too old to have one.
    pub pq_public: Vec<u8>,
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

/// Initiator side.
///
/// `peer_ed25519` is the identity we expect (from their invite) and
/// `peer_pq_fingerprint` is the commitment to their post-quantum key, when the
/// invite carried one. Verifying the bundle against both is what stops a man in
/// the middle — including one holding a quantum computer, who could forge the
/// Ed25519 half but not the ML-DSA half.
pub async fn initiate<S>(
    stream: &mut S,
    node: &LocalNode,
    peer_ed25519: [u8; 32],
    peer_pq_fingerprint: Option<[u8; 32]>,
) -> Result<Session>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    initiate_at(stream, node, peer_ed25519, peer_pq_fingerprint, WireLevel::Hybrid)
        .await
        .map(|(s, _)| s)
}

/// The same, at a chosen wire level, reporting which one was used.
///
/// [`WireLevel::Classical`] is the fallback for a peer that has not updated
/// yet. It is a real downgrade — no post-quantum signatures — so it is never
/// chosen automatically here: the caller decides, and tells the user.
pub async fn initiate_at<S>(
    stream: &mut S,
    node: &LocalNode,
    peer_ed25519: [u8; 32],
    peer_pq_fingerprint: Option<[u8; 32]>,
    level: WireLevel,
) -> Result<(Session, WireLevel)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if level == WireLevel::Classical {
        let session = initiate_classical(stream, node, peer_ed25519).await?;
        return Ok((session, WireLevel::Classical));
    }
    let session =
        initiate_hybrid(stream, node, peer_ed25519, peer_pq_fingerprint).await?;
    Ok((session, WireLevel::Hybrid))
}

async fn initiate_hybrid<S>(
    stream: &mut S,
    node: &LocalNode,
    peer_ed25519: [u8; 32],
    peer_pq_fingerprint: Option<[u8; 32]>,
) -> Result<Session>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Speak first (see HELLO_MAGIC): this both identifies the protocol and
    // primes the Tor rendezvous stream so the responder's reply flows back.
    stream.write_all(HELLO_MAGIC_HYBRID).await?;
    stream.flush().await?;

    // The responder's bundle: their Signal prekeys, their ML-DSA public key,
    // and a signature over both under *both* schemes. Anyone can offer keys;
    // only they can sign them, and breaking one scheme is not enough.
    //
    // A peer too old to know `UMB3` hangs up here, before it has said anything.
    // That, and *only* that, is what may be retried classically — see
    // [`PEER_REFUSED_HYBRID`].
    let frame = match read_frame(stream).await {
        Ok(frame) => frame,
        Err(e) => bail!("{PEER_REFUSED_HYBRID}: {e}"),
    };
    let overhead = PQ_PUBLIC_LEN + HYBRID_SIG_LEN;
    if frame.len() <= overhead {
        bail!("bad PREKEY length {}", frame.len());
    }
    let split = frame.len() - overhead;
    let (bundle_bytes, rest) = frame.split_at(split);
    let (peer_pq, sig) = rest.split_at(PQ_PUBLIC_LEN);

    // The key they just sent must be the key their invite promised. Without
    // this the post-quantum half would be worth nothing: an attacker would
    // simply substitute a key of their own alongside a forged Ed25519 half.
    if let Some(expected) = peer_pq_fingerprint {
        if pq::pq_fingerprint(peer_pq) != expected {
            bail!("post-quantum key does not match the invite — possible man-in-the-middle");
        }
    }
    // The signature covers the bundle *and* the key, so neither can be swapped
    // for the other's benefit.
    let mut signed = Vec::with_capacity(bundle_bytes.len() + PQ_PUBLIC_LEN);
    signed.extend_from_slice(bundle_bytes);
    signed.extend_from_slice(peer_pq);
    if !pq::verify_hybrid(&peer_ed25519, peer_pq, &signed, sig) {
        bail!("PREKEY signature invalid — possible man-in-the-middle");
    }

    let mut inner = SignalAccount::new().map_err(|e| anyhow!("session keys: {e}"))?;
    inner
        .start_session(&PublishedBundle::from_bytes(bundle_bytes))
        .map_err(|e| anyhow!("outbound session: {e}"))?;

    // First (empty) message doubles as the prekey message the responder needs.
    let (t, body) = inner.encrypt(&pad(b"").unwrap()).map_err(|e| anyhow!("first message: {e}"))?;
    // Bind our own identity to this connection, under both schemes.
    let our_pq = node.pq_public();
    let mut to_sign = Vec::with_capacity(body.len() + PQ_PUBLIC_LEN);
    to_sign.extend_from_slice(&body);
    to_sign.extend_from_slice(&our_pq);
    let bind_sig = node.pq.sign(&to_sign);

    let mut hello = Vec::with_capacity(33 + PQ_PUBLIC_LEN + HYBRID_SIG_LEN + body.len());
    hello.extend_from_slice(&node.account.public());
    hello.extend_from_slice(&our_pq);
    hello.extend_from_slice(&bind_sig);
    hello.push(t);
    hello.extend_from_slice(&body);
    write_frame(stream, &hello).await?;

    Ok(Session { inner })
}

/// The classical handshake, kept so a peer who has not updated can still be
/// talked to. Ed25519 only: no post-quantum protection at all.
async fn initiate_classical<S>(
    stream: &mut S,
    node: &LocalNode,
    peer_ed25519: [u8; 32],
) -> Result<Session>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(HELLO_MAGIC).await?;
    stream.flush().await?;

    let frame = read_frame(stream).await?;
    if frame.len() <= 64 {
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

    let (t, body) = inner.encrypt(&pad(b"").unwrap()).map_err(|e| anyhow!("first message: {e}"))?;
    let bind_sig = node.account.sign(&body);

    let mut hello = Vec::with_capacity(97 + body.len());
    hello.extend_from_slice(&node.account.public());
    hello.extend_from_slice(&bind_sig);
    hello.push(t);
    hello.extend_from_slice(&body);
    write_frame(stream, &hello).await?;

    Ok(Session { inner })
}

/// Responder side. Returns the session, the peer's verified identity, and which
/// handshake they were able to speak.
pub async fn accept<S>(
    stream: &mut S,
    node: &mut LocalNode,
) -> Result<(Session, PeerIdentity, WireLevel)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Wait for the initiator's greeting before answering. Which greeting it is
    // decides the format of everything that follows, which is why the version
    // has to live here and not in a later frame.
    let mut magic = [0u8; 4];
    stream.read_exact(&mut magic).await?;
    if &magic == HELLO_MAGIC {
        let (session, peer_ed) = accept_classical(stream, node).await?;
        return Ok((
            session,
            PeerIdentity { ed25519: peer_ed, pq_public: Vec::new() },
            WireLevel::Classical,
        ));
    }
    if &magic != HELLO_MAGIC_HYBRID {
        bail!("not an NullChat peer");
    }

    // Fresh Signal keys for this connection, signed by our long-term identity
    // under both schemes, together with the post-quantum key itself.
    let mut inner = SignalAccount::new().map_err(|e| anyhow!("session keys: {e}"))?;
    let bundle = inner.publish_bundle().map_err(|e| anyhow!("prekey: {e}"))?;
    let our_pq = node.pq_public();
    let mut signed = bundle.as_bytes().to_vec();
    signed.extend_from_slice(&our_pq);
    let sig = node.pq.sign(&signed);

    let mut prekey = signed;
    prekey.extend_from_slice(&sig);
    write_frame(stream, &prekey).await?;

    let hello = read_frame(stream).await?;
    let head = 32 + PQ_PUBLIC_LEN + HYBRID_SIG_LEN + 1;
    if hello.len() <= head {
        bail!("bad HELLO length {}", hello.len());
    }
    let peer_ed: [u8; 32] = hello[0..32].try_into().unwrap();
    let peer_pq = hello[32..32 + PQ_PUBLIC_LEN].to_vec();
    let bind_sig = &hello[32 + PQ_PUBLIC_LEN..head - 1];
    let t = hello[head - 1];
    let body = &hello[head..];

    // The signature covers their first message and their post-quantum key, so
    // the identity they claim is the identity that produced this session — and
    // the key they claim is the key that signed it.
    let mut signed = Vec::with_capacity(body.len() + PQ_PUBLIC_LEN);
    signed.extend_from_slice(body);
    signed.extend_from_slice(&peer_pq);
    if !pq::verify_hybrid(&peer_ed, &peer_pq, &signed, bind_sig) {
        bail!("HELLO binding signature invalid — possible man-in-the-middle");
    }

    inner
        .decrypt(t, body)
        .map_err(|e| anyhow!("inbound session: {e}"))?;
    Ok((
        Session { inner },
        PeerIdentity { ed25519: peer_ed, pq_public: peer_pq },
        WireLevel::Hybrid,
    ))
}

/// The classical responder, for peers that greeted us with `UMB1`.
async fn accept_classical<S>(
    stream: &mut S,
    node: &mut LocalNode,
) -> Result<(Session, [u8; 32])>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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
        let bob_pq = bob.pq_fingerprint();

        let (mut a, mut b) = tokio::io::duplex(1 << 20);

        // Run both sides of the handshake concurrently.
        let (ra, rb) = tokio::join!(
            initiate(&mut a, &alice, bob_ed, Some(bob_pq)),
            accept(&mut b, &mut bob),
        );
        let mut alice_s = ra.expect("initiate");
        let (mut bob_s, peer, level) = rb.expect("accept");
        assert_eq!(level, WireLevel::Hybrid, "two current peers use the hybrid handshake");
        assert_eq!(peer.ed25519, alice_ed, "responder learns initiator's real identity");
        assert_eq!(
            peer.pq_public,
            alice.pq_public(),
            "and their post-quantum key, verified by the same signature"
        );

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

        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        // The responder sends its PREKEY then blocks waiting for a HELLO that
        // never comes (the initiator bails), so run it detached.
        let responder = tokio::spawn(async move {
            let _ = accept(&mut b, &mut bob).await;
        });

        let result = initiate(&mut a, &alice, wrong, None).await;
        assert!(
            result.is_err(),
            "initiator must reject a PREKEY not signed by the expected identity"
        );
        responder.abort();
    }

    /// A peer that only speaks the classical handshake is still reachable, and
    /// the level is reported so the app can say the conversation is weaker.
    #[tokio::test]
    async fn an_old_peer_can_still_be_talked_to_and_it_is_reported() {
        let alice = LocalNode::generate().unwrap();
        let mut bob = LocalNode::generate().unwrap();
        let bob_ed = bob.ed25519();

        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        let (ra, rb) = tokio::join!(
            initiate_at(&mut a, &alice, bob_ed, None, WireLevel::Classical),
            accept(&mut b, &mut bob),
        );
        let (mut alice_s, level) = ra.expect("classical initiate");
        let (mut bob_s, peer, responder_level) = rb.expect("accept");

        assert_eq!(level, WireLevel::Classical);
        assert_eq!(responder_level, WireLevel::Classical, "the responder knows too");
        assert_eq!(peer.ed25519, alice.ed25519());
        assert!(peer.pq_public.is_empty(), "no post-quantum key at this level");

        // And it genuinely works — this is a usable conversation, not a stub.
        send_message(&mut a, &mut alice_s, b"stara verze, ale funguje").await.unwrap();
        assert_eq!(
            recv_message(&mut b, &mut bob_s).await.unwrap(),
            b"stara verze, ale funguje"
        );
    }

    /// The post-quantum commitment from the invite is enforced. Without this
    /// check the second scheme would be decoration: an attacker who forged the
    /// classical half would simply attach a post-quantum key of their own.
    #[tokio::test]
    async fn a_post_quantum_key_not_matching_the_invite_is_refused() {
        let alice = LocalNode::generate().unwrap();
        let mut bob = LocalNode::generate().unwrap();
        let bob_ed = bob.ed25519();
        // Bob's real Ed25519 identity, but somebody else's post-quantum key.
        let other_fingerprint = LocalNode::generate().unwrap().pq_fingerprint();

        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        let responder = tokio::spawn(async move {
            let _ = accept(&mut b, &mut bob).await;
        });

        let result = initiate(&mut a, &alice, bob_ed, Some(other_fingerprint)).await;
        assert!(
            result.is_err(),
            "a post-quantum key the invite did not promise must be refused"
        );
        responder.abort();
    }
}
