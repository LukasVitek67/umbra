// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tor onion transport driven by the official `tor` daemon (C-Tor).
//!
//! This is the same approach Briar, OnionShare and Tor Browser take: bundle the
//! mature, audited Tor implementation and drive it as a child process. Umbra
//! adds no trust — Tor only carries bytes that are already end-to-end encrypted
//! by [`crate::Session`].
//!
//! What it gives us:
//! * our own **v3 onion service** — reachable through NAT, with no server and no
//!   port forwarding, at a stable address that survives restarts;
//! * **dialling peers** by their `.onion` address through Tor's SOCKS5 port;
//! * **censorship resistance** — obfs4 / snowflake / webtunnel / meek bridges,
//!   configured from a `bridges.txt` shipped next to the executable.
//!
//! Layout on disk (all inside the app's data directory):
//! ```text
//! <data>/torrc          generated config
//! <data>/tor-data/      Tor's own state (consensus cache, keys)
//! <data>/hs/            onion service dir; `hostname` holds our .onion
//! ```

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

use crate::{accept, initiate, read_frame, write_frame, LocalNode, Session};

/// Virtual port our onion service listens on.
pub const ONION_PORT: u16 = 9735;

/// How long we allow Tor to reach "Bootstrapped 100%".
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(900);

/// An event surfaced to the app.
/// `kind`: `"status"`, `"onion"`, `"connected"`, `"disconnected"`, `"message"`, `"error"`.
pub struct Incoming {
    pub peer_hex: String,
    /// Human-readable text for status/error events.
    pub body: String,
    /// Raw decrypted payload for `"message"` events (see the app's envelope).
    pub bytes: Vec<u8>,
    pub kind: String,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Find a free localhost TCP port by binding and immediately releasing it.
fn free_port() -> Result<u16> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

/// Look for a bundled file next to the running executable.
fn beside_exe(name: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let p = exe.parent()?.join(name);
    p.exists().then_some(p)
}

/// A running `tor` daemon owned by this process; killed when dropped.
pub struct TorProcess {
    child: Child,
    /// Our onion address, e.g. `abcd…xyz.onion`.
    pub onion: String,
    /// Tor's SOCKS5 port, used to dial peers.
    pub socks_port: u16,
    /// Localhost port the onion service forwards inbound streams to.
    pub local_port: u16,
}

impl Drop for TorProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

impl TorProcess {
    /// Write a torrc, launch Tor, wait for a full bootstrap, and read back our
    /// onion address.
    ///
    /// `tor_exe` and `pt_exe` default to `tor.exe` / `lyrebird.exe` next to our
    /// own executable; `bridges` come from `bridges.txt` there. With no bridge
    /// file we connect to Tor directly.
    pub async fn start(
        data_dir: &Path,
        local_port: u16,
        progress: impl Fn(&str) + Send + 'static,
    ) -> Result<TorProcess> {
        let tor_exe = beside_exe("tor.exe")
            .or_else(|| beside_exe("tor"))
            .ok_or_else(|| anyhow!("tor.exe nenalezen vedle aplikace"))?;
        let pt_exe = beside_exe("lyrebird.exe").or_else(|| beside_exe("lyrebird"));
        let bridges = beside_exe("bridges.txt")
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|t| {
                t.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        std::fs::create_dir_all(data_dir).context("nelze vytvořit datový adresář")?;
        let tor_data = data_dir.join("tor-data");
        let hs_dir = data_dir.join("hs");
        std::fs::create_dir_all(&tor_data)?;
        let socks_port = free_port()?;

        let mut torrc = String::new();
        torrc.push_str(&format!("SocksPort 127.0.0.1:{socks_port}\n"));
        torrc.push_str(&format!("DataDirectory {}\n", tor_data.display()));
        torrc.push_str(&format!("HiddenServiceDir {}\n", hs_dir.display()));
        torrc.push_str(&format!("HiddenServicePort {ONION_PORT} 127.0.0.1:{local_port}\n"));
        torrc.push_str("SocksPolicy accept 127.0.0.1/32\n");
        // Tie the daemon's lifetime to ours: if the app crashes or is force
        // killed, Tor shuts itself down instead of lingering and holding the
        // data-directory lock (which would block the next start).
        torrc.push_str(&format!(
            "__OwningControllerProcess {}\n",
            std::process::id()
        ));
        torrc.push_str("Log notice stdout\n");
        // A persistent log makes connection problems diagnosable after the fact.
        // UMBRA_TOR_LOGLEVEL=info gives verbose onion-service diagnostics.
        let level = std::env::var("UMBRA_TOR_LOGLEVEL").unwrap_or_else(|_| "notice".into());
        torrc.push_str(&format!(
            "Log {level} file {}\n",
            data_dir.join("tor.log").display()
        ));
        if !bridges.is_empty() {
            if let Some(pt) = &pt_exe {
                torrc.push_str(&format!(
                    "ClientTransportPlugin obfs4,meek_lite,snowflake,webtunnel exec {}\n",
                    pt.display()
                ));
            }
            torrc.push_str("UseBridges 1\n");
            for b in &bridges {
                torrc.push_str(&format!("Bridge {b}\n"));
            }
        }
        let torrc_path = data_dir.join("torrc");
        std::fs::write(&torrc_path, torrc).context("nelze zapsat torrc")?;

        let mut cmd = Command::new(&tor_exe);
        cmd.arg("-f")
            .arg(&torrc_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .stdin(Stdio::null());
        // Run the daemon without a console window: users must never see (or be
        // able to close) a stray terminal belonging to the app's internals.
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = cmd.spawn().context("nepodařilo se spustit tor.exe")?;

        // Tor's stdout is a blocking pipe: read it on its own thread and report
        // bootstrap progress through a channel.
        let stdout = child.stdout.take().ok_or_else(|| anyhow!("no tor stdout"))?;
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        std::thread::spawn(move || {
            // Keep draining for the whole lifetime of the daemon: if we stopped
            // reading, Tor's stdout pipe would fill up and block the daemon.
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let _ = tx.send(line);
            }
        });

        let deadline = tokio::time::Instant::now() + BOOTSTRAP_TIMEOUT;
        let mut done = false;
        while let Ok(Some(line)) = tokio::time::timeout_at(deadline, rx.recv()).await {
            if let Some(pos) = line.find("Bootstrapped ") {
                let msg = line[pos..].trim().to_string();
                progress(&msg);
                if msg.starts_with("Bootstrapped 100%") {
                    done = true;
                    break;
                }
            }
        }
        if !done {
            let _ = child.kill();
            bail!("Tor se nepřipojil do {} s — síť ho nejspíš blokuje. Zkus jinou síť nebo aktualizuj bridges.txt", BOOTSTRAP_TIMEOUT.as_secs());
        }

        // The hostname file appears once the service keys exist.
        let hostname_path = hs_dir.join("hostname");
        let mut onion = String::new();
        for _ in 0..50 {
            if let Ok(s) = std::fs::read_to_string(&hostname_path) {
                let s = s.trim().to_string();
                if !s.is_empty() {
                    onion = s;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        if onion.is_empty() {
            let _ = child.kill();
            bail!("nepodařilo se získat onion adresu");
        }

        Ok(TorProcess { child, onion, socks_port, local_port })
    }
}

/// Open a TCP stream to `host:port` through Tor's SOCKS5 proxy.
pub async fn socks5_connect(socks_port: u16, host: &str, port: u16) -> Result<TcpStream> {
    socks5_connect_isolated(socks_port, host, port, "").await
}

/// The same, but on a circuit of its own when `isolation` is non-empty.
///
/// Tor isolates streams by SOCKS credentials (`IsolateSOCKSAuth`, on by
/// default), so a different user name means a different exit. That is how we
/// get a second opinion when an exit is rate-limited or blocked by the far end.
pub async fn socks5_connect_isolated(
    socks_port: u16,
    host: &str,
    port: u16,
    isolation: &str,
) -> Result<TcpStream> {
    let mut s = TcpStream::connect(("127.0.0.1", socks_port)).await?;

    if isolation.is_empty() {
        // Greeting: SOCKS5, one method, "no authentication".
        s.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut reply = [0u8; 2];
        s.read_exact(&mut reply).await?;
        if reply != [0x05, 0x00] {
            bail!("SOCKS5: proxy odmítla handshake");
        }
    } else {
        // Offer username/password; the values are only a circuit label.
        s.write_all(&[0x05, 0x01, 0x02]).await?;
        let mut reply = [0u8; 2];
        s.read_exact(&mut reply).await?;
        if reply != [0x05, 0x02] {
            bail!("SOCKS5: proxy odmítla přihlášení");
        }
        let user = isolation.as_bytes();
        if user.len() > 255 {
            bail!("izolační jmenovka je příliš dlouhá");
        }
        let mut auth = vec![0x01, user.len() as u8];
        auth.extend_from_slice(user);
        auth.push(1); // one-byte password, Tor ignores the value
        auth.push(b'x');
        s.write_all(&auth).await?;
        let mut auth_reply = [0u8; 2];
        s.read_exact(&mut auth_reply).await?;
        if auth_reply[1] != 0x00 {
            bail!("SOCKS5: přihlášení odmítnuto");
        }
    }

    // CONNECT to a domain name (Tor resolves .onion itself).
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        bail!("adresa je příliš dlouhá");
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;

    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        bail!("Tor nedokázal navázat spojení (SOCKS kód {})", head[1]);
    }
    // Consume the bound address so the stream starts at payload.
    match head[3] {
        0x01 => {
            let mut skip = [0u8; 4];
            s.read_exact(&mut skip).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            let mut skip = vec![0u8; len[0] as usize];
            s.read_exact(&mut skip).await?;
        }
        0x04 => {
            let mut skip = [0u8; 16];
            s.read_exact(&mut skip).await?;
        }
        other => bail!("SOCKS5: neznámý typ adresy {other}"),
    }
    let mut port_buf = [0u8; 2];
    s.read_exact(&mut port_buf).await?;
    Ok(s)
}

// --- service layer ---------------------------------------------------------

struct PeerConn {
    session: Arc<Mutex<Session>>,
    writer: Arc<Mutex<WriteHalf<TcpStream>>>,
}

struct Inner {
    seed: [u8; 32],
    socks_port: u16,
    /// Live sessions keyed by the peer's hex identity — several at once.
    peers: HashMap<String, PeerConn>,
    tx: mpsc::UnboundedSender<Incoming>,
}

/// A running Umbra node on Tor: our onion service plus live peer sessions.
#[derive(Clone)]
pub struct TorService {
    inner: Arc<Mutex<Inner>>,
    /// Our `.onion` address — this goes into the invite.
    pub onion: String,
    _tor: Arc<TorProcess>,
}

impl TorService {
    /// Start Tor, publish our onion service, and accept incoming peers.
    pub async fn start(
        seed: [u8; 32],
        data_dir: &Path,
        progress: impl Fn(&str) + Send + 'static,
    ) -> Result<(TorService, mpsc::UnboundedReceiver<Incoming>)> {
        // Bind the local listener first so Tor can forward straight to it.
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local_port = listener.local_addr()?.port();

        let tor = TorProcess::start(data_dir, local_port, progress).await?;
        let onion = tor.onion.clone();
        let socks_port = tor.socks_port;

        let (tx, rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Mutex::new(Inner {
            seed,
            socks_port,
            peers: HashMap::new(),
            tx,
        }));

        // Accept loop for inbound onion connections.
        let accept_inner = inner.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let inner2 = accept_inner.clone();
                tokio::spawn(async move {
                    {
                        let g = inner2.lock().await;
                        let _ = g.tx.send(Incoming {
                            peer_hex: String::new(),
                            body: "příchozí spojení, ověřuji…".to_string(),
                            bytes: Vec::new(),
                            kind: "status".to_string(),
                        });
                    }
                    let mut node = LocalNode::from_seed(&seed);
                    match accept(&mut stream, &mut node).await {
                        Ok((session, peer_ed)) => {
                            install_peer(inner2, stream, session, peer_ed).await;
                        }
                        Err(e) => {
                            let g = inner2.lock().await;
                            let _ = g.tx.send(Incoming {
                                peer_hex: String::new(),
                                body: format!("příchozí spojení odmítnuto: {e}"),
                                bytes: Vec::new(),
                                kind: "error".to_string(),
                            });
                        }
                    }
                });
            }
        });

        Ok((
            TorService { inner, onion, _tor: Arc::new(tor) },
            rx,
        ))
    }

    /// Dial a peer's onion address and run the verified handshake.
    pub async fn connect(&self, onion: String, peer_ed: [u8; 32]) -> Result<()> {
        let peer_hex = hex(&peer_ed);
        let (seed, socks_port) = {
            let g = self.inner.lock().await;
            if g.peers.contains_key(&peer_hex) {
                return Ok(()); // already connected
            }
            (g.seed, g.socks_port)
        };

        let host = onion.trim().trim_end_matches('/').to_string();
        // Reaching an onion service means fetching its descriptor and building a
        // rendezvous circuit; that is slow, but it must not hang forever.
        let mut stream = tokio::time::timeout(
            Duration::from_secs(180),
            socks5_connect(socks_port, &host, ONION_PORT),
        )
        .await
        .map_err(|_| anyhow!("kontakt neodpovídá (není online, nebo je adresa špatná)"))?
        .with_context(|| format!("nepodařilo se spojit s {host}"))?;

        let node = LocalNode::from_seed(&seed);
        let session = tokio::time::timeout(
            Duration::from_secs(180),
            initiate(&mut stream, &node, peer_ed),
        )
        .await
        .map_err(|_| anyhow!("protistrana neodpověděla na handshake"))??;
        install_peer(self.inner.clone(), stream, session, peer_ed).await;
        Ok(())
    }

    /// Send a text message to a connected peer.
    pub async fn send(&self, peer_hex: &str, text: String) -> Result<()> {
        self.send_bytes(peer_hex, text.into_bytes()).await
    }

    /// Send an arbitrary payload (the app's typed envelope) to a connected peer.
    pub async fn send_bytes(&self, peer_hex: &str, payload_bytes: Vec<u8>) -> Result<()> {
        let (session, writer) = {
            let g = self.inner.lock().await;
            let p = g
                .peers
                .get(peer_hex)
                .ok_or_else(|| anyhow!("s tímto kontaktem nejsi spojen"))?;
            (p.session.clone(), p.writer.clone())
        };
        let payload = { session.lock().await.encrypt_message(&payload_bytes) };
        let mut w = writer.lock().await;
        write_frame(&mut *w, &payload).await
    }

    /// Hex identities of all peers we currently have a session with.
    pub async fn connected_peers(&self) -> Vec<String> {
        self.inner.lock().await.peers.keys().cloned().collect()
    }
}

async fn install_peer(
    inner: Arc<Mutex<Inner>>,
    stream: TcpStream,
    session: Session,
    peer_ed: [u8; 32],
) {
    let peer_hex = hex(&peer_ed);
    let (rd, wr): (ReadHalf<TcpStream>, WriteHalf<TcpStream>) = split(stream);
    let session = Arc::new(Mutex::new(session));

    let tx = {
        let mut g = inner.lock().await;
        g.peers.insert(
            peer_hex.clone(),
            PeerConn { session: session.clone(), writer: Arc::new(Mutex::new(wr)) },
        );
        let _ = g.tx.send(Incoming {
            peer_hex: peer_hex.clone(),
            body: String::new(),
            bytes: Vec::new(),
            kind: "connected".to_string(),
        });
        g.tx.clone()
    };

    tokio::spawn(async move {
        let mut rd = rd;
        loop {
            let Ok(payload) = read_frame(&mut rd).await else {
                break;
            };
            let decrypted = { session.lock().await.decrypt_message(&payload) };
            match decrypted {
                Ok(body) => {
                    let _ = tx.send(Incoming {
                        peer_hex: peer_hex.clone(),
                        body: String::new(),
                        bytes: body,
                        kind: "message".to_string(),
                    });
                }
                Err(_) => break, // authentication failure: drop the session
            }
        }
        let mut g = inner.lock().await;
        g.peers.remove(&peer_hex);
        let _ = g.tx.send(Incoming {
            peer_hex,
            body: String::new(),
            bytes: Vec::new(),
            kind: "disconnected".to_string(),
        });
    });
}

/// The SOCKS port of a running service — used by diagnostics.
pub fn socks_port_of(svc: &TorService) -> u16 {
    svc._tor.socks_port
}
