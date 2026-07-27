// SPDX-License-Identifier: AGPL-3.0-or-later
//! Minimal two-party encrypted chat over TCP â€” the real, runnable proof that
//! two separate processes (or machines on a LAN / forwarded port) exchange
//! end-to-end encrypted messages through the Umbra session handshake.
//!
//!   Terminal A:  umbra-chat listen 9000
//!   Terminal B:  umbra-chat connect 127.0.0.1:9000 <identity-hex-from-A>

use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Mutex;
use umbra_core::identity::user_code;
use umbra_transport::{read_frame, tcp, write_frame, LocalNode, Session};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("listen") => {
            let port = args.get(2).cloned().unwrap_or_else(|| "9000".to_string());
            let mut node = LocalNode::generate()?;
            println!("TvĂˇ identita (pĹ™edej druhĂ© stranÄ›): {}", hex(&node.ed25519()));
            println!("UĹľivatelskĂ˝ kĂłd: {}", user_code(&node.ed25519()));
            println!("PoslouchĂˇm na 0.0.0.0:{port} â€¦ ÄŤekĂˇm na spojenĂ­.");
            let (stream, session, peer) =
                tcp::listen_once(&format!("0.0.0.0:{port}"), &mut node).await?;
            println!("Spojeno s {}. PiĹˇ zprĂˇvy (/quit ukonÄŤĂ­):", hex(&peer.ed25519));
            chat_loop(stream, session).await
        }
        Some("connect") => {
            let addr = args
                .get(2)
                .cloned()
                .ok_or_else(|| anyhow!("pouĹľitĂ­: connect <host:port> <identita-hex>"))?;
            let peer = args
                .get(3)
                .and_then(|s| unhex32(s))
                .ok_or_else(|| anyhow!("neplatnĂˇ identita (64 hex znakĹŻ)"))?;
            let node = LocalNode::generate()?;
            println!("TvĂˇ identita: {}", hex(&node.ed25519()));
            println!("PĹ™ipojuji se k {addr} â€¦");
            let (stream, session) = tcp::connect(&addr, &node, peer, None).await?;
            println!("Spojeno a ovÄ›Ĺ™eno. PiĹˇ zprĂˇvy (/quit ukonÄŤĂ­):");
            chat_loop(stream, session).await
        }
        _ => {
            eprintln!("pouĹľitĂ­: umbra-chat listen <port> | connect <host:port> <identita-hex>");
            std::process::exit(2);
        }
    }
}

async fn chat_loop(stream: tokio::net::TcpStream, session: Session) -> Result<()> {
    let (mut rd, mut wr) = stream.into_split();
    let session = Arc::new(Mutex::new(session));

    // Reader task: decrypt and print incoming messages.
    let rx_session = session.clone();
    let reader = tokio::spawn(async move {
        loop {
            match read_frame(&mut rd).await {
                Ok(payload) => {
                    let decrypted = { rx_session.lock().await.decrypt_message(&payload) };
                    match decrypted {
                        Ok(m) => println!("[peer] {}", String::from_utf8_lossy(&m)),
                        Err(e) => {
                            eprintln!("chyba deĹˇifrovĂˇnĂ­: {e}");
                            break;
                        }
                    }
                }
                Err(_) => {
                    println!("[spojenĂ­ uzavĹ™eno]");
                    break;
                }
            }
        }
    });

    // Main task: read stdin lines, encrypt and send.
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        if line == "/quit" {
            break;
        }
        let payload = { session.lock().await.encrypt_message(line.as_bytes()) };
        if write_frame(&mut wr, &payload).await.is_err() {
            break;
        }
    }
    reader.abort();
    Ok(())
}
