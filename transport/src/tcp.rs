// SPDX-License-Identifier: AGPL-3.0-or-later
//! Direct TCP transport. Works on a LAN or over the internet with a forwarded
//! port; it is the testable, no-dependencies path. The Tor onion transport
//! (which works through NAT with no server) reuses the exact same
//! [`crate::initiate`] / [`crate::accept`] handshake over its own stream.

use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};

use crate::{accept, initiate, LocalNode, Session};

/// Connect to `addr` (e.g. `"127.0.0.1:9000"`) and run the initiator handshake
/// against the identity we expect (`peer_ed25519`, from their invite).
pub async fn connect(
    addr: &str,
    node: &LocalNode,
    peer_ed25519: [u8; 32],
) -> Result<(TcpStream, Session)> {
    let mut stream = TcpStream::connect(addr).await?;
    let session = initiate(&mut stream, node, peer_ed25519).await?;
    Ok((stream, session))
}

/// Bind `bind` (e.g. `"0.0.0.0:9000"`), accept one peer, and run the responder
/// handshake. Returns the stream, the session, and the peer's verified identity.
pub async fn listen_once(bind: &str, node: &mut LocalNode) -> Result<(TcpStream, Session, [u8; 32])> {
    let listener = TcpListener::bind(bind).await?;
    let (mut stream, _peer_addr) = listener.accept().await?;
    let (session, peer_ed) = accept(&mut stream, node).await?;
    Ok((stream, session, peer_ed))
}
