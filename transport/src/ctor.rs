// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tor onion transport driven by the official `tor` daemon (C-Tor).
//!
//! This is the same approach Briar, OnionShare and Tor Browser take: bundle the
//! mature, audited Tor implementation and drive it as a child process. NullChat
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

use crate::{
    accept, initiate_at, read_frame, write_frame, LocalNode, Session, WireLevel,
    PEER_REFUSED_HYBRID,
};

/// Virtual port our onion service listens on.
pub const ONION_PORT: u16 = 9735;

/// How long a *direct* connection to the Tor network may take.
///
/// A direct bootstrap either works within a couple of minutes or is being
/// blocked; waiting longer only delays falling back to bridges.
const DIRECT_TIMEOUT: Duration = Duration::from_secs(150);

/// How long a bootstrap *through bridges* may take. Pluggable transports are
/// slower to come up, so they get more room than a direct attempt.
const BRIDGE_TIMEOUT: Duration = Duration::from_secs(300);

/// What we say when Tor refuses to share its data directory.
///
/// Matched on by [`TorService::start`], which waits and tries the same route
/// again rather than moving on: a daemon on its way out frees the directory
/// within seconds, and changing routes would not have helped anyway.
const DATA_DIR_BUSY: &str = "datový adresář Toru drží jiný běžící Tor";

/// A bootstrap that has not gained a single percent for this long is stuck.
///
/// Without this the app sat on a dead attempt until the full timeout expired —
/// which is where "Tor did not connect in 900 s" came from. Noticing the stall
/// early is what makes an automatic second attempt worth having.
const STALL_TIMEOUT: Duration = Duration::from_secs(75);

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

/// Where we remember the daemon we started ourselves.
fn pid_file(tor_data: &Path) -> PathBuf {
    tor_data.join("nullchat-tor.pid")
}

/// Is the process with this id still a running `tor`?
///
/// The gate in front of everything that kills: a "no" here means we keep our
/// hands off, so a recycled id belonging to someone else's program is safe.
fn process_is_tor(pid: u32) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map(|o| {
                let out = String::from_utf8_lossy(&o.stdout).to_lowercase();
                // tasklist answers with a friendly "no tasks" line rather than
                // an error when nothing matches, so look for the name itself.
                out.contains("\"tor.exe\"")
            })
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|name| name.trim() == "tor")
            .unwrap_or(false)
    }
}

/// End a `tor` that a previous run of NullChat left behind.
///
/// This is the single most common way the app got stuck: Tor refuses to share
/// its data directory, waits five seconds for the other one to go away, and
/// then exits. The leftover is *our own* child from a crashed or force-killed
/// run — `__OwningControllerProcess` normally takes it down with us, but that
/// does not survive every kind of death.
///
/// Only a process whose id we wrote down ourselves and which is still called
/// `tor` is touched. That matters: process ids get recycled, and killing a
/// stranger's program because it inherited a number would be inexcusable.
fn kill_orphan_tor(tor_data: &Path, progress: &impl Fn(&str)) {
    let path = pid_file(tor_data);
    let Ok(text) = std::fs::read_to_string(&path) else { return };
    let Ok(pid) = text.trim().parse::<u32>() else {
        let _ = std::fs::remove_file(&path);
        return;
    };
    let _ = std::fs::remove_file(&path);
    if pid == std::process::id() {
        return;
    }

    if !process_is_tor(pid) {
        return;
    }

    progress("ukončuji Tor, který zůstal po předchozím spuštění");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let _ = Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new("kill").arg("-9").arg(pid.to_string()).status();
    }
    // Windows releases the file handles a moment after the process dies.
    std::thread::sleep(Duration::from_millis(800));
}

/// Delete the data-directory lock if no live daemon holds it.
///
/// Windows keeps the file open while Tor runs, so a failed delete means "still
/// in use" and a successful one means the previous run died without cleaning
/// up. Either way this cannot break a running daemon.
fn clear_stale_lock(tor_data: &Path, progress: &impl Fn(&str)) {
    let lock = tor_data.join("lock");
    if !lock.exists() {
        return;
    }
    if std::fs::remove_file(&lock).is_ok() {
        progress("uklízím zámek po předchozím běhu");
    }
}

/// Throw away Tor's cached directory information, keeping the identity.
///
/// A half-downloaded or stale consensus is the usual reason a bootstrap stops
/// partway and never finishes. The onion service keys (`hs/`) and the torrc are
/// untouched, so the address — the thing contacts have — survives the repair.
pub fn clear_tor_cache(data_dir: &Path) -> Result<()> {
    let tor_data = data_dir.join("tor-data");
    let Ok(entries) = std::fs::read_dir(&tor_data) else { return Ok(()) };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        // Keep the daemon's own keys; everything cached can be fetched again.
        if name.starts_with("cached-") || name == "state" || name == "lock" {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    Ok(())
}

/// Where the platform keeps the binaries we ship.
///
/// On desktop they sit next to the app. On Android nothing outside the APK's
/// native library folder may be executed (W^X since API 29), so `tor` and the
/// pluggable transport travel as `libtor.so` / `liblyrebird.so` and the app
/// tells us that folder — it is not discoverable from here.
static NATIVE_DIR: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

/// Tell the transport where the executable binaries live (Android).
pub fn set_native_dir(dir: PathBuf) {
    *NATIVE_DIR.lock().unwrap() = Some(dir);
}

/// Find a bundled binary by its desktop name, falling back to the Android
/// library naming.
fn bundled(name: &str) -> Option<PathBuf> {
    if let Some(p) = beside_exe(name) {
        return Some(p);
    }
    let dir = NATIVE_DIR.lock().unwrap().clone()?;
    let stem = name.trim_end_matches(".exe").trim_end_matches(".txt");
    for candidate in [format!("lib{stem}.so"), name.to_string(), stem.to_string()] {
        let p = dir.join(candidate);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Read a bridge list, dropping comments and blank lines.
fn read_bridges(path: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(path) else { return Vec::new() };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// The last few complaints from Tor's own log.
///
/// When a start fails, "the network is probably blocking it" is a guess. Tor
/// usually says exactly what went wrong — an unreadable data directory, a
/// missing pluggable transport, a clock that is hours off — and that line is
/// worth far more to whoever has to fix it than our guess.
fn log_tail(data_dir: &Path) -> String {
    let Ok(text) = std::fs::read_to_string(data_dir.join("tor.log")) else {
        return String::new();
    };
    let mut lines: Vec<&str> = text
        .lines()
        .rev()
        .take(400)
        .filter(|l| l.contains("[warn]") || l.contains("[err]"))
        .collect();
    lines.dedup();
    let picked: Vec<String> = lines
        .into_iter()
        .take(2)
        // Drop the timestamp and level, keep what happened.
        .map(|l| l.split("] ").last().unwrap_or(l).trim().to_string())
        .collect();
    if picked.is_empty() {
        String::new()
    } else {
        format!(" (Tor hlásí: {})", picked.join(" / "))
    }
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
    /// `tor_exe` and `pt_exe` are the `tor.exe` / `lyrebird.exe` bundled next to
    /// our own executable. An empty `bridges` means a direct connection, which
    /// is what works on an ordinary network — bridges are the answer to
    /// censorship, and [`TorService::start`] falls back to them by itself.
    pub async fn start(
        data_dir: &Path,
        local_port: u16,
        bridges: &[String],
        timeout: Duration,
        progress: impl Fn(&str) + Send + 'static,
    ) -> Result<TorProcess> {
        let tor_exe = bundled("tor.exe")
            .or_else(|| bundled("tor"))
            .ok_or_else(|| anyhow!("tor nenalezen — chybí binárka vedle aplikace"))?;
        let pt_exe = bundled("lyrebird.exe").or_else(|| bundled("lyrebird"));

        std::fs::create_dir_all(data_dir).context("nelze vytvořit datový adresář")?;
        let tor_data = data_dir.join("tor-data");
        let hs_dir = data_dir.join("hs");
        std::fs::create_dir_all(&tor_data)?;
        // A crash (or a second copy of the app killed off) can leave the data
        // directory locked, and Tor then refuses to start until someone deletes
        // the file by hand — which is exactly the "Connecting to Tor" screen
        // that never finishes. Deleting it is safe precisely because Windows
        // refuses while a live daemon still holds it.
        kill_orphan_tor(&tor_data, &progress);
        clear_stale_lock(&tor_data, &progress);
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
            for b in bridges {
                torrc.push_str(&format!("Bridge {b}\n"));
            }
        }
        let torrc_path = data_dir.join("torrc");
        std::fs::write(&torrc_path, torrc).context("nelze zapsat torrc")?;

        let mut cmd = Command::new(&tor_exe);
        cmd.arg("-f")
            .arg(&torrc_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
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
        // Write the id down before anything else can fail: if this run dies
        // badly, the next one needs to know which process to clean up.
        let _ = std::fs::write(pid_file(&tor_data), child.id().to_string());

        // Tor's pipes block when nobody reads them, so both are drained on their
        // own thread for the whole life of the daemon. stderr is where a refused
        // config or a missing pluggable transport lands — discarding it is how a
        // failure to *start* used to be reported as a network problem.
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let stdout = child.stdout.take().ok_or_else(|| anyhow!("no tor stdout"))?;
        let out_tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let _ = out_tx.send(line);
            }
        });
        if let Some(stderr) = child.stderr.take() {
            let err_tx = tx.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    let _ = err_tx.send(line);
                }
            });
        }
        // Both senders now live in the threads; dropping ours is what lets the
        // channel close when Tor dies, which is how we tell "it exited" from
        // "it is still trying".
        drop(tx);

        let deadline = tokio::time::Instant::now() + timeout;
        let mut last_move = tokio::time::Instant::now();
        let mut pct: u32 = 0;
        let mut done = false;
        let mut fault = String::new();
        // Tor announces this on its way out, and it is worth telling apart from
        // every other failure: nothing about the network is wrong.
        let mut data_dir_busy = false;
        loop {
            // Wake either at the overall deadline or once the percentage has sat
            // still long enough to call the attempt dead, whichever comes first.
            let wake = std::cmp::min(deadline, last_move + STALL_TIMEOUT);
            match tokio::time::timeout_at(wake, rx.recv()).await {
                Ok(Some(line)) => {
                    if line.contains("same data directory") {
                        data_dir_busy = true;
                    }
                    let Some(pos) = line.find("Bootstrapped ") else { continue };
                    let msg = line[pos..].trim().to_string();
                    let reached = line[pos + "Bootstrapped ".len()..]
                        .split('%')
                        .next()
                        .and_then(|n| n.trim().parse::<u32>().ok())
                        .unwrap_or(pct);
                    if reached > pct {
                        pct = reached;
                        last_move = tokio::time::Instant::now();
                    }
                    progress(&msg);
                    if pct >= 100 {
                        done = true;
                        break;
                    }
                }
                Ok(None) => {
                    fault = if data_dir_busy {
                        DATA_DIR_BUSY.to_string()
                    } else {
                        format!("Tor skončil hned po spuštění{}", log_tail(data_dir))
                    };
                    break;
                }
                Err(_) => {
                    fault = if tokio::time::Instant::now() >= deadline {
                        format!(
                            "Tor se nepřipojil do {} s (zůstal na {pct} %){}",
                            timeout.as_secs(),
                            log_tail(data_dir)
                        )
                    } else {
                        format!(
                            "Tor uvízl na {pct} % a {} s se nepohnul{}",
                            STALL_TIMEOUT.as_secs(),
                            log_tail(data_dir)
                        )
                    };
                    break;
                }
            }
        }
        if !done {
            let _ = child.kill();
            bail!("{fault}");
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

/// A running NullChat node on Tor: our onion service plus live peer sessions.
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
        progress: impl Fn(&str) + Send + Sync + 'static,
    ) -> Result<(TorService, mpsc::UnboundedReceiver<Incoming>)> {
        // Bind the local listener first so Tor can forward straight to it.
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local_port = listener.local_addr()?.port();

        // What to try, in order.
        //
        // A **direct** connection is what works on an ordinary network, and it
        // is what Tor Browser does by default. Bridges exist for censorship and
        // are slower and less reliable everywhere else — the public ones we ship
        // are also the first a censor blocks, so most of them are dead. NullChat
        // used to force bridges on every single start, for no better reason than
        // that the file was bundled next to the executable; that is where the
        // hung "Connecting to Tor" screen came from.
        //
        // Each further attempt also clears Tor's cached directory data, the
        // other classic reason a bootstrap stops partway. Identity and onion
        // keys are never touched, so a repair costs the user nothing but time.
        let user = read_bridges(&data_dir.join("bridges.txt"));
        let shipped = bundled("bridges.txt").map(|p| read_bridges(&p)).unwrap_or_default();
        let mut plans: Vec<(String, Vec<String>, Duration)> = Vec::new();
        if user.is_empty() {
            plans.push(("přímé připojení".into(), Vec::new(), DIRECT_TIMEOUT));
            if !shipped.is_empty() {
                plans.push(("mosty".into(), shipped, BRIDGE_TIMEOUT));
            }
        } else {
            // Someone who pasted their own bridges is behind censorship: start
            // with what they gave us. A stale line must not lock them out, so
            // the other routes still follow.
            plans.push(("tvoje mosty".into(), user.clone(), BRIDGE_TIMEOUT));
            plans.push(("přímé připojení".into(), Vec::new(), DIRECT_TIMEOUT));
            if !shipped.is_empty() {
                let mut both = user;
                both.extend(shipped);
                plans.push(("tvoje i zabudované mosty".into(), both, BRIDGE_TIMEOUT));
            }
        }

        let progress = Arc::new(progress);
        let mut started = None;
        let mut failures: Vec<String> = Vec::new();
        for (i, (label, bridges, limit)) in plans.iter().enumerate() {
            if i == 0 {
                progress(&format!("spouštím Tor — {label}"));
            } else {
                progress(&format!("nepovedlo se, opravuji a zkouším {label}"));
                let _ = clear_tor_cache(data_dir);
            }
            // A daemon left over from a previous run is on its way out, not a
            // reason to change route: wait for it and try the same one again.
            // This is the failure that used to be reported as a 900 s timeout
            // even though Tor had given up after five seconds.
            let mut last: Option<anyhow::Error> = None;
            for wait in [0u64, 6, 12] {
                if wait > 0 {
                    progress("čekám, až se uvolní datový adresář po předchozím Toru");
                    tokio::time::sleep(Duration::from_secs(wait)).await;
                }
                let p = progress.clone();
                match TorProcess::start(data_dir, local_port, bridges, *limit, move |m| p(m)).await {
                    Ok(tor) => {
                        started = Some(tor);
                        break;
                    }
                    Err(e) => {
                        let busy = e.to_string().contains(DATA_DIR_BUSY);
                        last = Some(e);
                        if !busy {
                            break;
                        }
                    }
                }
            }
            if started.is_some() {
                break;
            }
            if let Some(e) = last {
                failures.push(format!("{label} — {e}"));
            }
        }
        let Some(tor) = started else {
            bail!("Tor se nepřipojil. {}", failures.join(" | "));
        };
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
                        Ok((session, peer, level)) => {
                            // Tell the app which handshake this peer managed, so
                            // a conversation without post-quantum protection is
                            // visible rather than assumed away.
                            {
                                let g = inner2.lock().await;
                                let _ = g.tx.send(Incoming {
                                    peer_hex: hex(&peer.ed25519),
                                    body: match level {
                                        WireLevel::Hybrid => "hybrid".to_string(),
                                        WireLevel::Classical => "classical".to_string(),
                                    },
                                    bytes: Vec::new(),
                                    kind: "wire".to_string(),
                                });
                            }
                            install_peer(inner2, stream, session, peer.ed25519).await;
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
    pub async fn connect(
        &self,
        onion: String,
        peer_ed: [u8; 32],
        peer_pq_fingerprint: Option<[u8; 32]>,
    ) -> Result<()> {
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
        let attempt = tokio::time::timeout(
            Duration::from_secs(180),
            initiate_at(&mut stream, &node, peer_ed, peer_pq_fingerprint, WireLevel::Hybrid),
        )
        .await
        .map_err(|_| anyhow!("protistrana neodpověděla na handshake"))?;

        let (session, level) = match attempt {
            Ok(ok) => ok,
            Err(e) if format!("{e:#}").contains(PEER_REFUSED_HYBRID) => {
                // They run a version from before post-quantum identities.
                // Talking to them is still worth doing, but it is a genuine
                // downgrade and the app says so — see the `wire` event below.
                //
                // What is deliberately *not* here: any failure that got as far
                // as a signature check never reaches this branch, so a hostile
                // network cannot force the weaker handshake by interfering.
                let mut retry = tokio::time::timeout(
                    Duration::from_secs(180),
                    socks5_connect(socks_port, &host, ONION_PORT),
                )
                .await
                .map_err(|_| anyhow!("kontakt neodpovídá"))??;
                let out = tokio::time::timeout(
                    Duration::from_secs(180),
                    initiate_at(&mut retry, &node, peer_ed, None, WireLevel::Classical),
                )
                .await
                .map_err(|_| anyhow!("protistrana neodpověděla na handshake"))??;
                stream = retry;
                out
            }
            Err(e) => return Err(e),
        };

        {
            let g = self.inner.lock().await;
            let _ = g.tx.send(Incoming {
                peer_hex: peer_hex.clone(),
                body: match level {
                    WireLevel::Hybrid => "hybrid".to_string(),
                    WireLevel::Classical => "classical".to_string(),
                },
                bytes: Vec::new(),
                kind: "wire".to_string(),
            });
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The cleanup must never touch a process that merely inherited the id we
    /// wrote down. This test *is* the proof: it feeds in its own pid, and the
    /// test process surviving to the assertion is the result.
    #[test]
    fn a_pid_that_is_not_tor_is_left_alone() {
        let dir = std::env::temp_dir().join(format!("nullchat-pid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(pid_file(&dir), std::process::id().to_string()).unwrap();

        assert!(!process_is_tor(std::process::id()), "the test runner is not tor");
        kill_orphan_tor(&dir, &|_: &str| {});

        // Still here, and the note about a daemon that no longer exists is gone
        // so the next start does not look at it again.
        assert!(!pid_file(&dir).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_damaged_pid_file_is_not_a_crash() {
        let dir = std::env::temp_dir().join(format!("nullchat-pidjunk-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(pid_file(&dir), "not a number").unwrap();
        kill_orphan_tor(&dir, &|_: &str| {});
        assert!(!pid_file(&dir).exists());

        // No file at all is the normal first run.
        kill_orphan_tor(&dir, &|_: &str| {});
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bridge_file_keeps_only_real_lines() {
        let dir = std::env::temp_dir().join(format!("nullchat-bridges-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bridges.txt");
        std::fs::write(&path, "# a comment\n\n  obfs4 1.2.3.4:9001 CERT\n\n").unwrap();
        assert_eq!(read_bridges(&path), vec!["obfs4 1.2.3.4:9001 CERT".to_string()]);

        // A file that is not there means "connect directly", not an error.
        assert!(read_bridges(&dir.join("nothing.txt")).is_empty());
        // So does a file with nothing but comments — the bug that forced every
        // start through bridges came from treating "present" as "use these".
        std::fs::write(&path, "# only comments\n").unwrap();
        assert!(read_bridges(&path).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
