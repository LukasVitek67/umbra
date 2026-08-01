// SPDX-License-Identifier: AGPL-3.0-or-later
//! Two-node test of the Tor onion transport — the real scenario.
//!
//! Terminal A:  nullchat-tor-probe listen  <datadir-a>
//!              (prints its .onion address and identity)
//! Terminal B:  nullchat-tor-probe dial    <datadir-b> <onion> <identity-hex>
//!
//! Each side runs its own Tor daemon and its own onion service, exactly like two
//! people on two machines.

use std::path::PathBuf;

use anyhow::{bail, Result};
use nullchat_core::envelope;
use nullchat_core::identity::Keypair;
use nullchat_transport::ctor::TorService;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<[u8; 32]> {
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
    let mode = args.get(1).cloned().unwrap_or_else(|| "listen".into());
    let data_dir: PathBuf = args
        .get(2)
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("nullchat-node"));

    // A per-directory deterministic seed keeps identities stable across runs.
    let mut seed = [0u8; 32];
    let name = data_dir.to_string_lossy();
    for (i, b) in name.bytes().enumerate() {
        seed[i % 32] ^= b.wrapping_add(i as u8);
    }
    let identity = Keypair::from_seed(&seed).public();

    eprintln!("[*] Spouštím Tor ({})…", data_dir.display());
    let (svc, mut events) =
        TorService::start(seed, &data_dir, |m| eprintln!("    {m}")).await?;

    println!("ONION={}", svc.onion);
    println!("IDENTITY={}", hex(&identity));
    // A ready-to-paste invite, so this node can be added as a contact in the
    // GUI app and used as the "other person" when testing on one machine.
    let invite = nullchat_core::invite::Invite::new(identity, "Testovací uzel", svc.onion.clone());
    println!("INVITE={}", invite.encode());
    println!();
    println!("↑ Zkopíruj řádek INVITE (i s 'umbra1:') do aplikace: Chaty → Přidat");

    fn frame_name(p: &envelope::Payload) -> &'static str {
        match p {
            envelope::Payload::Text(_) => "text",
            envelope::Payload::Profile { .. } => "profil",
            envelope::Payload::FileOffer { .. } => "nabídka souboru",
            envelope::Payload::FileChunk { .. } => "kus souboru",
            envelope::Payload::FileEnd { .. } => "konec souboru",
            envelope::Payload::GroupText { .. } => "skupinová zpráva",
            envelope::Payload::GroupInfo { .. } => "roster skupiny",
            envelope::Payload::Address { .. } => "adresa protějšku",
            envelope::Payload::Receipt { .. } => "potvrzení doručení",
            envelope::Payload::Reply { .. } => "odpověď na zprávu",
            envelope::Payload::Reaction { .. } => "reakce",
            envelope::Payload::Capabilities { .. } => "co protějšek umí",
        }
    }

    match mode.as_str() {
        "listen" => {
            eprintln!("[*] Čekám na spojení… (Ctrl+C ukončí)");
            while let Some(ev) = events.recv().await {
                if ev.kind == "message" {
                    match envelope::decode(&ev.bytes) {
                        Some(envelope::Payload::Text(t)) => {
                            eprintln!("[*] ✓ PŘIJATA ZPRÁVA: {t:?}");
                            let _ = svc
                                .send_bytes(
                                    &ev.peer_hex,
                                    envelope::encode_text(&format!("echo: {t}")),
                                )
                                .await;
                        }
                        Some(envelope::Payload::Profile { name, picture }) => {
                            eprintln!("[*] profil protějšku: {name} ({} B obrázek)", picture.len());
                        }
                        Some(envelope::Payload::FileOffer { name, size, .. }) => {
                            eprintln!("[*] příchozí soubor: {name} ({size} B)");
                        }
                        Some(envelope::Payload::FileChunk { data, .. }) => {
                            eprintln!("[*] kus souboru: {} B", data.len());
                        }
                        Some(envelope::Payload::FileEnd { .. }) => {
                            eprintln!("[*] ✓ soubor kompletní");
                        }
                        // The probe only reports the app-level frames; groups,
                        // addresses and receipts are the app's business.
                        Some(other) => eprintln!("[*] rámec typu {}", frame_name(&other)),
                        None => eprintln!("[*] neznámý formát zprávy"),
                    }
                } else {
                    eprintln!("    [{}] {} {}", ev.kind, ev.peer_hex, ev.body);
                }
            }
        }
        "dial" => {
            let onion = args.get(3).cloned().unwrap_or_default();
            let peer = args.get(4).and_then(|s| unhex(s));
            let (Some(peer), false) = (peer, onion.is_empty()) else {
                bail!("použití: dial <datadir> <onion> <identity-hex>");
            };

            // Report events in the background while we dial.
            tokio::spawn(async move {
                while let Some(ev) = events.recv().await {
                    eprintln!("    [{}] {} {}", ev.kind, ev.peer_hex, ev.body);
                }
            });

            eprintln!("[*] Vytáčím {onion}…");
            let mut ok = false;
            for attempt in 1..=4 {
                match svc.connect(onion.clone(), peer, None).await {
                    Ok(()) => {
                        ok = true;
                        break;
                    }
                    Err(e) => {
                        eprintln!("    pokus {attempt} selhal: {e}");
                        tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
                    }
                }
            }
            if !ok {
                bail!("spojení se nepodařilo navázat");
            }
            eprintln!("[*] ✓ Spojeno a ověřeno. Posílám zprávu…");
            svc.send_bytes(&hex(&peer), envelope::encode_text("ahoj pres Tor, tady NullChat"))
                .await?;

            // Optional 5th argument: a file to send, to exercise file transfer.
            if let Some(path) = args.get(5) {
                let data = std::fs::read(path)?;
                let name = std::path::Path::new(path)
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "soubor".into());
                let id = [9u8; 16];
                eprintln!("[*] posílám soubor {name} ({} B)…", data.len());
                svc.send_bytes(&hex(&peer), envelope::encode_file_offer(&id, &name, data.len() as u64)).await?;
                for (seq, chunk) in data.chunks(envelope::CHUNK).enumerate() {
                    svc.send_bytes(&hex(&peer), envelope::encode_file_chunk(&id, seq as u32, chunk)).await?;
                }
                svc.send_bytes(&hex(&peer), envelope::encode_file_end(&id)).await?;
                eprintln!("[*] ✓ soubor odeslán");
            }
            eprintln!("[*] ✓ Odesláno. Čekám 60 s na echo…");
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
        // Raw byte-level probe: connect through Tor and dump whatever the peer
        // sends first, without running the handshake. Used to tell a transport
        // problem apart from a handshake problem.
        "raw" => {
            let onion = args.get(3).cloned().unwrap_or_default();
            let socks = nullchat_transport::ctor::socks_port_of(&svc);
            eprintln!("[*] raw: připojuji se na {onion} (SOCKS {socks})…");
            let mut stream = tokio::time::timeout(
                tokio::time::Duration::from_secs(120),
                nullchat_transport::ctor::socks5_connect(socks, &onion, 9735),
            )
            .await??;
            eprintln!("[*] SOCKS spojení otevřeno, čekám na data (60 s)…");
            use tokio::io::AsyncReadExt;
            let mut buf = vec![0u8; 256];
            match tokio::time::timeout(
                tokio::time::Duration::from_secs(60),
                stream.read(&mut buf),
            )
            .await
            {
                Ok(Ok(n)) => {
                    eprintln!("[*] ✓ PŘIJATO {n} bajtů:");
                    for chunk in buf[..n].chunks(16) {
                        let h: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
                        eprintln!("      {}", h.join(" "));
                    }
                }
                Ok(Err(e)) => eprintln!("[*] chyba čtení: {e}"),
                Err(_) => eprintln!("[*] ✗ nepřišlo nic do 60 s"),
            }
        }
        other => bail!("neznámý režim: {other}"),
    }
    Ok(())
}
