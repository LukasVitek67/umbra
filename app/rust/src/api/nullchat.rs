// SPDX-License-Identifier: AGPL-3.0-or-later
//! The real flutter_rust_bridge API: bridges the Flutter UI to the NullChat core
//! (identity, user codes, invites, and the encrypted local store).
//!
//! Live peer-to-peer send/receive over the transport is a follow-up; this layer
//! already makes identity, codes, invites, contacts and message history *real*
//! and persisted (encrypted at rest).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::frb_generated::StreamSink;
use flutter_rust_bridge::frb;
use tokio::sync::mpsc;
use nullchat_core::crypto::keystore;
use nullchat_core::identity::{user_code, Keypair};
use nullchat_core::invite::Invite;
use nullchat_core::crypto::pq::HybridIdentity;
use nullchat_core::safety;
use nullchat_core::group::{Group, GroupMember};
use nullchat_core::store::{
    Contact, ContactStatus, Direction, MessageState, NewAttachment, NewGroupMessage, NewMessage,
    ProfileKind, Store,
};
use zeroize::Zeroizing;
use nullchat_transport::ctor::TorService;

use crate::accounts::{self, AccountEntry};
use crate::gifs;
use crate::updater;

use nullchat_core::envelope::{self, Payload};

/// An event from the network layer, pushed to the UI.
///
/// `kind` is one of:
/// `"status"` (bootstrapping / connecting…), `"onion"` (our address is ready),
/// `"connected"` / `"disconnected"` (peer session), `"message"` (incoming text),
/// `"error"`.
pub struct NetEvent {
    pub kind: String,
    pub data: String,
    pub peer_hex: String,
}

/// Dedicated multi-threaded runtime for Tor. Kept off Flutter's UI thread so a
/// slow or stalled bootstrap can never freeze the interface.
fn rt() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}

static SERVICE: Mutex<Option<TorService>> = Mutex::new(None);
static ONION: Mutex<Option<String>> = Mutex::new(None);
static EVENTS: Mutex<Option<mpsc::UnboundedSender<NetEvent>>> = Mutex::new(None);

/// Known contacts: identity hex → onion address. Used by the keep-alive loop.
static CONTACTS: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);
/// Identity hex → the post-quantum commitment from their invite, for the peers
/// that have one. The dialler checks the key it is offered against this.
static PQ_FINGERPRINTS: Mutex<Option<HashMap<String, [u8; 32]>>> = Mutex::new(None);

/// The commitment we hold for a peer, if any.
fn pq_fingerprint_of(peer_hex: &str) -> Option<[u8; 32]> {
    PQ_FINGERPRINTS.lock().unwrap().as_ref()?.get(peer_hex).copied()
}

/// Remember a peer's post-quantum commitment for the dialler.
fn remember_pq_fingerprint(peer_hex: &str, fp: Option<[u8; 32]>) {
    let Some(fp) = fp else { return };
    let mut g = PQ_FINGERPRINTS.lock().unwrap();
    g.get_or_insert_with(HashMap::new).insert(peer_hex.to_string(), fp);
}
/// The signed-in account, so payload handlers can persist without going
/// through Dart. Set when the network starts.
static APP: Mutex<Option<Arc<Mutex<Inner>>>> = Mutex::new(None);
/// One outgoing payload: the bytes to put on the wire, plus what the UI should
/// be told once it actually goes out.
#[derive(Clone)]
struct Pending {
    bytes: Vec<u8>,
    /// Text to echo back to the UI on delivery.
    ui: String,
    /// Group id (hex) when this is a group message, empty for 1:1.
    group_hex: String,
    /// The stored message this frame carries. `None` for frames that are not
    /// worth keeping if the peer is away (address, roster pushes).
    message_id: Option<i64>,
}
/// Contacts we are currently dialling, so we never dial one twice at once.
static DIALLING: Mutex<Option<HashSet<String>>> = Mutex::new(None);
/// One flush at a time per contact.
///
/// Two places deliver the outbox for the same person: the keep-alive loop every
/// twenty seconds, and the "connected" event. When they overlap they both read
/// the same rows and both put them on the wire, so the peer gets every waiting
/// message twice — and the second copy arrives against a ratchet that has
/// already moved past it, which is not a duplicate they can simply ignore.
static FLUSHING: Mutex<Option<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> = Mutex::new(None);

/// The flush lock for one contact, creating it on first use.
fn flush_lock(peer_hex: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut g = FLUSHING.lock().unwrap();
    let map = g.get_or_insert_with(HashMap::new);
    // Locks for contacts nobody is flushing are dead weight. Sweeping only when
    // the map has grown keeps this out of the common path, and doing it here —
    // rather than at the end of a flush — means there is no moment where a lock
    // is removed while its holder is still sending.
    if map.len() > 64 {
        map.retain(|_, v| Arc::strong_count(v) > 1);
    }
    map.entry(peer_hex.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}
/// The keep-alive loop is started once.
static KEEPALIVE: AtomicBool = AtomicBool::new(false);
/// The update loop is started once.
static UPDATER: AtomicBool = AtomicBool::new(false);
/// Tor's SOCKS port, so an update can be fetched on demand.
static SOCKS: Mutex<Option<u16>> = Mutex::new(None);
/// Where to append a plain-text diagnostic log (data dir / nullchat-app.log).
static LOGPATH: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Append one line to the diagnostic log. Best effort: never fails the caller.
/// A label that tells two peers apart *within one run* and means nothing
/// outside it.
///
/// Debugging needs to know that two events concern different people. Nobody
/// needs a file that names them. The salt is drawn once per process, so the
/// same contact gets a different label after a restart and two logs cannot be
/// lined up against each other.
fn peer_tag(peer_hex: &str) -> String {
    static SALT: Mutex<Option<[u8; 16]>> = Mutex::new(None);
    let salt = {
        let mut g = SALT.lock().unwrap();
        *g.get_or_insert_with(|| {
            let mut s = [0u8; 16];
            let _ = getrandom::getrandom(&mut s);
            s
        })
    };
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(salt);
    h.update(peer_hex.as_bytes());
    hex(&h.finalize()[..3])
}

fn log_line(text: &str) {
    let path = { LOGPATH.lock().unwrap().clone() };
    let Some(path) = path else { return };
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "[{secs}] {text}");
    }
}

/// Send a file as offer + chunks + end, or leave the whole thing in the outbox
/// when there is no session.
///
/// "They are offline, try later" was the behaviour for files and GIFs while
/// text messages had waited in the outbox since 1.1.0. Same promise now applies
/// to both: it goes out by itself once the peer appears.
///
/// Either everything is sent or nothing is. Sending half a file and queuing the
/// rest would leave the receiver holding chunks for a transfer that never ends.
async fn send_file_or_queue(peer_hex: &str, name: &str, data: Vec<u8>) {
    let mut id = [0u8; 16];
    if getrandom::getrandom(&mut id).is_err() {
        emit("error", "RNG selhal", peer_hex);
        return;
    }

    // Keep our own copy, sealed like a received one, so the conversation can
    // show the picture we sent rather than a line of text. Failing to store it
    // is not a reason to abandon the send — the bubble simply stays textual.
    let own_copy = APP.lock().unwrap().clone().and_then(|app| {
        let dir = FILES_DIR.lock().unwrap().clone()?;
        let mut path = dir.join(format!("sent-{}-{name}", hex(&id[..4])));
        let mut n = 1;
        while path.exists() {
            path = dir.join(format!("sent-{}-{n}-{name}", hex(&id[..4])));
            n += 1;
        }
        let g = app.lock().unwrap();
        g.store.encrypt_file(&path, &data).ok()?;
        Some(path.to_string_lossy().to_string())
    });
    let stored = own_copy.clone().unwrap_or_default();
    let total = data.len() as u64;

    // A row in `messages`, so the conversation shows what was sent instead of
    // nothing at all — and carries the attachment, so it is still a picture
    // after a restart rather than a filename.
    let ui_body = format!("📎 {name}");
    let message_id = APP
        .lock()
        .unwrap()
        .clone()
        .zip(unhex(peer_hex))
        .and_then(|(app, pk)| {
            let g = app.lock().unwrap();
            g.store
                .insert_message(&NewMessage {
                    contact_pubkey: pk,
                    direction: Direction::Outgoing,
                    sent_at: now_secs(),
                    body: ui_body.as_bytes(),
                    file: own_copy.as_deref().map(|path| NewAttachment {
                        path,
                        name,
                        size: total,
                    }),
                })
                .ok()
        })
        .unwrap_or(0);

    let mut frames = Vec::with_capacity(data.len() / envelope::CHUNK + 2);
    frames.push(envelope::encode_file_offer(&id, name, total));
    for (seq, chunk) in data.chunks(envelope::CHUNK).enumerate() {
        frames.push(envelope::encode_file_chunk(&id, seq as u32, chunk));
    }
    frames.push(envelope::encode_file_end(&id));

    let svc = SERVICE.lock().unwrap().clone();
    if let Some(svc) = svc {
        // A live session: send now, with progress, exactly as before.
        if svc.send_bytes(peer_hex, frames[0].clone()).await.is_ok() {
            emit("file_send_start", &format!("{name}|{total}"), peer_hex);
            for (i, frame) in frames.iter().enumerate().skip(1) {
                if svc.send_bytes(peer_hex, frame.clone()).await.is_err() {
                    emit("error", "přenos souboru se přerušil", peer_hex);
                    return;
                }
                if i < frames.len() - 1 {
                    let sent = (i * envelope::CHUNK).min(data.len()) as u64;
                    emit("file_send_progress", &format!("{sent}|{total}"), peer_hex);
                }
            }
            if message_id != 0 {
                if let Some(app) = APP.lock().unwrap().clone() {
                    let g = app.lock().unwrap();
                    let _ = g.store.set_message_state(message_id, MessageState::Sent);
                }
            }
            emit("file_sent", &format!("{ui_body}|{name}|{total}|{stored}"), peer_hex);
            return;
        }
    }

    // Nobody to send to. Park every frame in the encrypted outbox, in order.
    let Some(app) = APP.lock().unwrap().clone() else { return };
    let Some(pk) = unhex(peer_hex) else { return };
    {
        let g = app.lock().unwrap();
        for frame in &frames {
            // Every frame carries the same message id, so the bubble flips from
            // "waiting" to "sent" as the queue drains. An empty body marks the
            // frame as one the UI must not announce as a message — otherwise a
            // 3 MB GIF would report itself as 60-odd sent messages, and would
            // be counted as 60-odd waiting ones.
            if let Err(e) = g.store.queue_outgoing(&pk, message_id, None, frame, b"", now_secs()) {
                log_line(&format!("soubor nelze zařadit do fronty: {e}"));
                emit("error", "soubor nelze uložit do fronty", peer_hex);
                return;
            }
        }
    }
    emit("file_queued", &format!("{ui_body}|{name}|{total}|{stored}"), peer_hex);
    emit("queued", &format!("{}", pending_count()), peer_hex);

    let onion = {
        let g = CONTACTS.lock().unwrap();
        g.as_ref().and_then(|m| m.get(peer_hex).cloned())
    };
    if let Some(onion) = onion {
        if !onion.is_empty() {
            dial_once(peer_hex.to_string(), onion);
        }
    }
}

/// Deliver everything the database has waiting for `peer_hex`.
///
/// The queue lives in the encrypted store, not in memory: "it will be delivered
/// when they come back" has to survive closing the app, otherwise it is a lie.
async fn flush_pending(peer_hex: &str) {
    // Someone is already delivering this contact's queue. Waiting our turn would
    // only send the same rows again — and it would hold up the keep-alive loop,
    // which flushes every contact in sequence, behind one slow peer. Whatever
    // arrives while that flush runs goes out on the next tick.
    let lock = flush_lock(peer_hex);
    let Ok(_flushing) = lock.try_lock() else { return };

    let Some(app) = APP.lock().unwrap().clone() else { return };
    let Some(pk) = unhex(peer_hex) else { return };
    let queued = {
        let g = app.lock().unwrap();
        g.store.outbox_for(&pk).unwrap_or_default()
    };
    if queued.is_empty() {
        return;
    }
    let svc = SERVICE.lock().unwrap().clone();
    let Some(svc) = svc else { return };
    for item in queued {
        if let Err(e) = svc.send_bytes(peer_hex, item.payload.clone()).await {
            // Still not deliverable: it stays in the outbox for the next try.
            log_line(&format!("flush stopped: {e}"));
            return;
        }
        let ui = String::from_utf8_lossy(&item.body).to_string();
        {
            let g = app.lock().unwrap();
            let _ = g.store.dequeue(item.id);
            if item.group_id.is_none() {
                let _ = g.store.set_message_state(item.message_id, MessageState::Sent);
            }
        }
        // An empty body is a file frame (see `send_file_or_queue`): one file is
        // dozens of rows, and announcing each as a sent message would be wrong
        // and loud.
        if ui.is_empty() {
            continue;
        }
        match item.group_id {
            None => emit("sent", &ui, peer_hex),
            Some(gid) => emit("group_sent", &format!("{}|{}", hex(&gid), ui), peer_hex),
        }
    }
    emit("outbox", &format!("{}", pending_count()), peer_hex);
}

/// How many messages are still waiting, across all peers.
fn pending_count() -> u32 {
    let Some(app) = APP.lock().unwrap().clone() else { return 0 };
    let g = app.lock().unwrap();
    g.store
        .outbox_summary()
        .map(|v| v.iter().map(|(_, n)| n).sum())
        .unwrap_or(0)
}

/// Send a frame to one peer; if there is no session, leave it in the outbox and
/// start dialling. `message_id` ties it to the row the UI shows.
async fn send_or_queue(peer_hex: &str, item: Pending) {
    let svc = SERVICE.lock().unwrap().clone();
    if let Some(svc) = svc {
        if svc.send_bytes(peer_hex, item.bytes.clone()).await.is_ok() {
            if let (Some(app), Some(id)) = (APP.lock().unwrap().clone(), item.message_id) {
                let g = app.lock().unwrap();
                if item.group_hex.is_empty() {
                    let _ = g.store.set_message_state(id, MessageState::Sent);
                }
            }
            if item.group_hex.is_empty() {
                emit("sent", &item.ui, peer_hex);
            } else {
                emit("group_sent", &format!("{}|{}", item.group_hex, item.ui), peer_hex);
            }
            return;
        }
    }

    // Not deliverable now. Anything tied to a stored message waits in the
    // outbox; transient frames (a roster push, our address) are simply dropped.
    if let (Some(app), Some(id), Some(pk)) =
        (APP.lock().unwrap().clone(), item.message_id, unhex(peer_hex))
    {
        let gid = if item.group_hex.is_empty() {
            None
        } else {
            unhex16(&item.group_hex)
        };
        let g = app.lock().unwrap();
        let _ = g.store.queue_outgoing(
            &pk,
            id,
            gid,
            &item.bytes,
            item.ui.as_bytes(),
            now_secs(),
        );
    }
    emit("queued", &format!("{}", pending_count()), peer_hex);

    let onion = {
        let g = CONTACTS.lock().unwrap();
        g.as_ref().and_then(|m| m.get(peer_hex).cloned())
    };
    if let Some(onion) = onion {
        if !onion.is_empty() {
            dial_once(peer_hex.to_string(), onion);
        }
    }
}

/// Dial a contact unless a dial is already in flight for it.
fn dial_once(peer_hex: String, onion: String) {
    {
        let mut g = DIALLING.lock().unwrap();
        let set = g.get_or_insert_with(HashSet::new);
        if !set.insert(peer_hex.clone()) {
            return; // already dialling
        }
    }
    rt().spawn(async move {
        let svc = SERVICE.lock().unwrap().clone();
        if let (Some(svc), Some(pk)) = (svc, unhex(&peer_hex)) {
            log_line(&format!("dial start peer={}", peer_tag(&peer_hex)));
            match svc.connect(onion, pk, pq_fingerprint_of(&peer_hex)).await {
                Ok(()) => log_line("dial ok"),
                Err(e) => {
                    let text = format!("{e:#}");
                    log_line(&format!("dial FAILED: {text}"));
                    // A signature mismatch means the invite belongs to an
                    // identity the peer no longer has — say so, it is fixable.
                    if text.contains("signature invalid") || text.contains("man-in-the-middle") {
                        emit("error", "stale_invite", &peer_hex);
                    } else {
                        emit("status", &format!("unreachable|{text}"), &peer_hex);
                    }
                }
            }
        }
        if let Some(set) = DIALLING.lock().unwrap().as_mut() {
            set.remove(&peer_hex);
        }
    });
}

/// Background loop: keep a live session with every known contact, and flush
/// queued messages as soon as one comes up. This is what makes "write now,
/// they get it when they're online" work without the user clicking anything.
fn spawn_keepalive() {
    if KEEPALIVE.swap(true, Ordering::SeqCst) {
        return;
    }
    rt().spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(20)).await;
            let svc = SERVICE.lock().unwrap().clone();
            let Some(svc) = svc else { continue };

            let connected: HashSet<String> = svc.connected_peers().await.into_iter().collect();
            let contacts: Vec<(String, String)> = {
                let g = CONTACTS.lock().unwrap();
                g.as_ref()
                    .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                    .unwrap_or_default()
            };

            for (peer_hex, onion) in contacts {
                if connected.contains(&peer_hex) {
                    flush_pending(&peer_hex).await;
                } else if !onion.is_empty() {
                    dial_once(peer_hex, onion);
                }
            }
        }
    });
}

/// The folder the running build lives in — where an update is installed.
fn install_dir() -> Option<PathBuf> {
    std::env::current_exe().ok()?.parent().map(|p| p.to_path_buf())
}

/// Start the background update loop (once).
fn spawn_updater(socks_port: u16) {
    if UPDATER.swap(true, Ordering::SeqCst) {
        return;
    }
    let Some(dir) = install_dir() else { return };
    updater::clean_leftovers(&dir);
    *SOCKS.lock().unwrap() = Some(socks_port);
    rt().spawn(async move {
        updater::run_loop(socks_port, |kind, data| emit(kind, data, "")).await;
    });
}

/// Install the update the user was offered. Progress arrives as
/// `update_downloading` / `update_installed` / `update_error` events.
#[frb(sync)]
pub fn install_update() {
    let socks = *SOCKS.lock().unwrap();
    let (Some(socks), Some(dir)) = (socks, install_dir()) else {
        emit("update_error", "síť ještě neběží", "");
        return;
    };
    rt().spawn(async move {
        updater::install_offered(socks, dir, |kind, data| emit(kind, data, "")).await;
    });
}

/// The version waiting to be installed, empty when there is none.
#[frb(sync)]
pub fn offered_update() -> String {
    updater::offered_version().unwrap_or_default()
}

/// This build's version, for the UI.
#[frb(sync)]
pub fn app_version() -> String {
    updater::current_version().to_string()
}

/// Tell the transport where the shipped binaries live.
///
/// Android refuses to execute anything outside the APK's native library folder,
/// so `tor` travels as `libtor.so` there and only the Java side knows the path.
/// Desktop builds find their binaries next to the executable and never call this.
#[frb(sync)]
pub fn set_native_dir(path: String) {
    nullchat_transport::ctor::set_native_dir(PathBuf::from(path));
}

/// Push an event to the UI (no-op before the network is started).
fn emit(kind: &str, data: &str, peer_hex: &str) {
    // Only the shape of the event, never its content.
    //
    // This line used to be `{kind} peer={12 hex of identity} {data}`, which put
    // message text, contact names and onion addresses into a plain file sitting
    // next to the encrypted database — readable without the passphrase, which
    // undoes everything the database does to protect them.
    log_line(&format!("{kind} peer={} {} B", peer_tag(peer_hex), data.len()));
    if let Some(tx) = EVENTS.lock().unwrap().as_ref() {
        let _ = tx.send(NetEvent {
            kind: kind.to_string(),
            data: data.to_string(),
            peer_hex: peer_hex.to_string(),
        });
    }
}

/// One local account, as shown in the account picker.
pub struct AccountView {
    pub id: String,
    pub name: String,
    /// Signs in without asking for the passphrase.
    pub autologin: bool,
}

/// One GIF search result, flattened for the picker.
pub struct GifView {
    pub preview_url: String,
    pub gif_url: String,
    pub width: u32,
    pub height: u32,
    pub description: String,
}

impl From<gifs::GifResult> for GifView {
    fn from(g: gifs::GifResult) -> Self {
        Self {
            preview_url: g.preview_url,
            gif_url: g.gif_url,
            width: g.width,
            height: g.height,
            description: g.description,
        }
    }
}

/// The account's database, salt or KDF file — under whichever name it has.
///
/// The rename to NullChat changed these filenames in the source, and an account
/// created before it still has `umbra.db` and `umbra.salt` on disk. Looking
/// only for the new names told people their identity did not exist, with the
/// real one sitting right there unopened. So: the existing file wins, and
/// nothing on disk is renamed — a rename that fails halfway costs somebody
/// their account, and there is nothing here worth that.
fn account_file(dir: &Path, name: &str) -> PathBuf {
    let current = dir.join(name);
    if current.exists() {
        return current;
    }
    let legacy = match name {
        "nullchat.db" => "umbra.db",
        "nullchat.salt" => "umbra.salt",
        "nullchat.kdf" => "umbra.kdf",
        _ => return current,
    };
    let old = dir.join(legacy);
    if old.exists() {
        return old;
    }
    current
}

#[cfg(test)]
mod gif_name_tests {
    use super::safe_gif_name;

    #[test]
    fn a_description_becomes_the_name() {
        assert_eq!(safe_gif_name("happy cat", "abc12345"), "happy-cat.gif");
        // Path separators and anything else unpleasant are dropped, not escaped.
        assert_eq!(safe_gif_name("../../etc/passwd", "abc12345"), "etcpasswd.gif");
    }

    #[test]
    fn without_a_description_two_gifs_get_different_names() {
        // The service usually sends none, and every GIF being `gif.gif` is what
        // made the second one look like a repeat of the first.
        let a = safe_gif_name("", "XD4qHZpkyUFfq");
        let b = safe_gif_name("", "Ra1bmpxpsppNC");
        assert_ne!(a, b);
        assert!(a.ends_with(".gif") && b.ends_with(".gif"));
        // Nothing from the URL can turn into a path.
        assert_eq!(safe_gif_name("", "../../../evil"), "gif-evil.gif");
        assert_eq!(safe_gif_name("", ""), "gif.gif");
    }
}

#[cfg(test)]
mod account_file_tests {
    use super::account_file;

    /// An account created before the rename must still open. This is the bug
    /// that shipped in 2.0.0: the code looked only for `nullchat.db`, the disk
    /// had `umbra.db`, and the app reported no identity while the real one sat
    /// there untouched.
    #[test]
    fn a_pre_rename_account_is_found() {
        let dir = std::env::temp_dir().join(format!("nc-af-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Nothing there: the current name is what a new account would create.
        assert!(account_file(&dir, "nullchat.db").ends_with("nullchat.db"));

        // Only the old name exists — that is the file to open.
        std::fs::write(dir.join("umbra.db"), b"old").unwrap();
        std::fs::write(dir.join("umbra.salt"), b"salt").unwrap();
        assert!(account_file(&dir, "nullchat.db").ends_with("umbra.db"));
        assert!(account_file(&dir, "nullchat.salt").ends_with("umbra.salt"));

        // Both exist (an account created after the rename in the same folder):
        // the current name wins, so we never quietly reopen a stale database.
        std::fs::write(dir.join("nullchat.db"), b"new").unwrap();
        assert!(account_file(&dir, "nullchat.db").ends_with("nullchat.db"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Tor's SOCKS port, once the network is up.
fn socks_port_now() -> Option<u16> {
    *SOCKS.lock().unwrap()
}

/// The SOCKS circuit label GIF traffic uses.
///
/// Stable for the life of the process (so a picker session reuses one circuit
/// instead of building a new one per keystroke) and distinct from everything
/// else, so the exit that sees a search term never carries messaging.
fn gif_circuit() -> String {
    "nullchat-gifs".to_string()
}

/// A filename for a GIF that cannot do anything unpleasant.
///
/// `fallback` distinguishes GIFs the service gave no description for, which is
/// most of them. Calling every one of them `gif.gif` made a conversation full
/// of identical lines, and anything matching sends by name could not tell two
/// apart.
fn safe_gif_name(description: &str, fallback: &str) -> String {
    let cleaned: String = description
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
        .take(40)
        .collect();
    let trimmed = cleaned.trim();
    if !trimmed.is_empty() {
        return format!("{}.gif", trimmed.replace(' ', "-"));
    }
    let tag: String = fallback
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(8)
        .collect();
    if tag.is_empty() {
        "gif.gif".to_string()
    } else {
        format!("gif-{tag}.gif")
    }
}

/// A contact, flattened for the UI.
pub struct ContactView {
    pub identity_hex: String,
    pub user_code: String,
    pub display_name: String,
    pub onion: String,
    pub added_at: u64,
    /// 0 = waiting for a decision, 1 = accepted, 2 = blocked.
    pub status: u8,
    /// Kept in the address book.
    pub saved: bool,
    /// The user compared safety numbers with them and said it matched.
    pub verified: bool,
}

/// A stored message, flattened for the UI.
pub struct MessageView {
    /// Row id, so a single message can be acted on (deleted, for one).
    pub id: i64,
    pub outgoing: bool,
    pub sent_at: u64,
    pub body: String,
    /// 0 = still waiting for the peer, 1 = handed over, 2 = confirmed by them.
    pub state: u8,
    /// Where the sealed attachment is, empty when the message is only text.
    /// With this the thread can show a picture again after a restart.
    pub file_path: String,
    /// The attachment's name, empty when there is none.
    pub file_name: String,
    /// The attachment's size in bytes, 0 when there is none.
    pub file_size: u64,
}

/// A message found by search, or one a contact sent us.
pub struct SearchHitView {
    /// Who wrote it (or, in a 1:1 thread, the other party).
    pub peer_hex: String,
    /// Empty for a direct message, otherwise the group it was written in.
    pub group_hex: String,
    pub outgoing: bool,
    pub sent_at: u64,
    pub body: String,
}

fn hit_view(h: nullchat_core::store::SearchHit) -> SearchHitView {
    SearchHitView {
        peer_hex: hex(&h.peer_pubkey),
        group_hex: h.group_id.map(|g| hex(&g)).unwrap_or_default(),
        outgoing: h.outgoing,
        sent_at: h.sent_at,
        body: h.body,
    }
}

/// One member of a group, flattened for the UI.
pub struct GroupMemberView {
    pub identity_hex: String,
    pub display_name: String,
    pub onion: String,
}

/// A group conversation, flattened for the UI.
pub struct GroupView {
    pub id_hex: String,
    pub name: String,
    pub version: u32,
    pub created_at: u64,
    pub members: Vec<GroupMemberView>,
}

/// A message in a group, flattened for the UI.
pub struct GroupMessageView {
    pub sender_hex: String,
    /// Name from the roster, so the UI can label who wrote it.
    pub sender_name: String,
    pub outgoing: bool,
    pub sent_at: u64,
    pub body: String,
}

/// The running app: encrypted store + identity keypair, behind a mutex so the
/// opaque handle can be shared with Dart.
pub struct UmbraApp {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    store: Store,
    account: Keypair,
    username: String,
    /// The app's data directory (also where Tor keeps its state and our onion
    /// service keys, so the address stays stable across restarts).
    dir: PathBuf,
    /// Which local account this is, and where the account list lives.
    account_id: String,
    root: PathBuf,
}

impl UmbraApp {
    /// Whether an identity already exists at `dir`.
    #[frb(sync)]
    pub fn exists(dir: String) -> bool {
        account_file(&PathBuf::from(dir), "nullchat.db").exists()
    }

    /// Create a brand-new identity + encrypted store at `dir`, protected by
    /// `passphrase`.
    #[frb(sync)]
    pub fn create(dir: String, username: String, passphrase: String) -> Result<UmbraApp, String> {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt).map_err(|_| "RNG failed".to_string())?;
        std::fs::write(dir.join("nullchat.salt"), salt).map_err(|e| e.to_string())?;
        // The KDF settings live next to the salt, so raising them for new
        // accounts never locks anyone out of an existing one.
        std::fs::write(dir.join("nullchat.kdf"), kdf_line()).map_err(|e| e.to_string())?;

        let key = keystore::derive_store_key_with(
            passphrase.as_bytes(),
            &salt,
            keystore::STORE_M_COST,
            keystore::STORE_T_COST,
            keystore::STORE_P_COST,
        )
        .map_err(|e| e.to_string())?;
        let store = Store::open(&account_file(&dir, "nullchat.db"), &key).map_err(|e| e.to_string())?;

        let account = Keypair::generate().map_err(|e| e.to_string())?;
        store
            .put_secret("identity_seed", &*account.secret_seed())
            .map_err(|e| e.to_string())?;
        store
            .put_secret("username", username.trim().as_bytes())
            .map_err(|e| e.to_string())?;

        Ok(UmbraApp {
            inner: Arc::new(Mutex::new(Inner {
                store,
                account,
                username: username.trim().to_string(),
                dir,
                account_id: String::new(),
                root: PathBuf::new(),
            })),
        })
    }

    /// Open an existing identity at `dir` with `passphrase`.
    #[frb(sync)]
    pub fn open(dir: String, passphrase: String) -> Result<UmbraApp, String> {
        let dir = PathBuf::from(dir);
        // Opening a database that isn't there would CREATE an empty one, and the
        // app would then offer "unlock" forever for an identity that does not
        // exist. Refuse instead, so the UI can fall back to onboarding.
        if !account_file(&dir, "nullchat.db").exists() || !account_file(&dir, "nullchat.salt").exists() {
            return Err("Na tomto počítači není žádná identita.".to_string());
        }
        let salt = std::fs::read(account_file(&dir, "nullchat.salt")).map_err(|e| e.to_string())?;
        let (m, t, p) = read_kdf(&dir);
        let key = keystore::derive_store_key_with(passphrase.as_bytes(), &salt, m, t, p)
            .map_err(|e| e.to_string())?;
        let store = Store::open(&account_file(&dir, "nullchat.db"), &key).map_err(|e| e.to_string())?;

        // A duress passphrase destroys everything it cannot read and then
        // carries on as an ordinary sign-in. This happens here, before anything
        // is shown, so there is no separate code path a bystander could notice
        // and nothing for the UI to give away. See docs/DURESS.md.
        if store.profile_kind() == ProfileKind::Wipe {
            let _ = store.destroy_unreadable();
        }

        // A wrong passphrase derives a wrong key, so the stored secret fails to
        // decrypt. Say that plainly instead of leaking a storage-level error.
        let seed = store
            .get_secret("identity_seed")
            .map_err(|_| "Špatná přístupová fráze.".to_string())?
            .ok_or_else(|| "Špatná přístupová fráze.".to_string())?;
        let seed32: [u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| "corrupt identity seed".to_string())?;
        let account = Keypair::from_seed(&seed32);

        let username = store
            .get_secret("username")
            .map_err(|e| e.to_string())?
            .map(|v| String::from_utf8_lossy(&v).to_string())
            .unwrap_or_default();

        // Repair threads from before peers who wrote to us first were stored as
        // contacts: their messages were in the database, but with no contact
        // row the app showed nothing and never dialled them back. Done here, so
        // the UI already sees them on the first load after sign-in.
        // Before anything else looks for a contact by identity: put every row
        // on the index derived from it. Repairs that run on a database where
        // those disagree pick the wrong row — that is how a contact with forty
        // messages was deleted in 2.1.35.
        match store.normalise_contact_indexes() {
            Ok(n) if n > 0 => log_line(&format!("srovnáno {n} kontaktů na index podle identity")),
            Err(e) => log_line(&format!("srovnání indexů selhalo: {e}")),
            _ => {}
        }

        let _ = store.backfill_missing_contacts(now_secs());

        // Clear out rows an older build created from empty PROFILE/ADDRESS
        // frames: no name, no address, no history, so nothing to lose — but in
        // the chat list they looked like every conversation existing twice.
        if let Ok(n) = store.purge_empty_contacts() {
            if n > 0 {
                log_line(&format!("odstraněno {n} prázdných kontaktů bez historie"));
            }
        }

        // Two rows standing for one person: the chat list showed the same
        // conversation twice, one copy with the history and one without.
        if let Ok(n) = store.dedupe_contacts() {
            if n > 0 {
                log_line(&format!("sloučeno {n} duplicitních kontaktů (stejná identita)"));
            }
        }

        // What the chat list is built from, so a report of "the same
        // conversation twice" can be settled from the log instead of guessed
        // at. Identities are truncated and names are never written: this says
        // how many rows there are and whether two of them are the same key,
        // which is the whole question.
        if let Ok(contacts) = store.list_contacts() {
            log_line(&format!("kontaktů v databázi: {}", contacts.len()));
            for c in &contacts {
                let msgs = store.message_count(&c.identity_pubkey).unwrap_or(0);
                log_line(&format!(
                    "  kontakt {}… zpráv={} jméno={} adresa={} stav={:?}",
                    &hex(&c.identity_pubkey)[..12],
                    msgs,
                    if c.display_name.is_empty() { "prázdné" } else { "je" },
                    if c.onion_addr.is_empty() { "prázdná" } else { "je" },
                    c.status,
                ));
            }
        }

        Ok(UmbraApp {
            inner: Arc::new(Mutex::new(Inner {
                store,
                account,
                username,
                dir,
                account_id: String::new(),
                root: PathBuf::new(),
            })),
        })
    }


    // --- local accounts (several identities on one computer) ---------------

    /// Accounts stored on this computer. Also migrates a pre-accounts install.
    #[frb(sync)]
    pub fn list_accounts(root: String) -> Vec<AccountView> {
        let root = PathBuf::from(root);
        let _ = accounts::migrate_legacy(&root);
        accounts::load(&root)
            .into_iter()
            .map(|a| AccountView { id: a.id, name: a.name, autologin: a.autologin })
            .collect()
    }

    /// Create a new account with its own identity and data directory.
    #[frb(sync)]
    pub fn create_account(
        root: String,
        name: String,
        passphrase: String,
        autologin: bool,
    ) -> Result<UmbraApp, String> {
        let root = PathBuf::from(root);
        let id = accounts::new_id()?;
        let dir = accounts::account_dir(&root, &id);
        let app = UmbraApp::create(
            dir.to_string_lossy().to_string(),
            name.clone(),
            passphrase.clone(),
        )?;
        let secret = if autologin {
            accounts::protect_passphrase(&dir, &passphrase).unwrap_or_default()
        } else {
            String::new()
        };
        accounts::upsert(
            &root,
            AccountEntry {
                id: id.clone(),
                name: name.trim().to_string(),
                autologin: autologin && !secret.is_empty(),
                secret,
            },
        )?;
        {
            let mut g = app.inner.lock().unwrap();
            g.account_id = id;
            g.root = root;
        }
        Ok(app)
    }

    /// Unlock an account with its passphrase, optionally remembering it.
    #[frb(sync)]
    pub fn open_account(
        root: String,
        id: String,
        passphrase: String,
        remember: bool,
    ) -> Result<UmbraApp, String> {
        let root = PathBuf::from(root);
        let dir = accounts::account_dir(&root, &id);
        let app = UmbraApp::open(dir.to_string_lossy().to_string(), passphrase.clone())?;
        // Keep the stored name in step with the identity's own username.
        let username = app.username();
        let mut entry = accounts::load(&root)
            .into_iter()
            .find(|a| a.id == id)
            .unwrap_or(AccountEntry {
                id: id.clone(),
                name: username.clone(),
                autologin: false,
                secret: String::new(),
            });
        if !username.is_empty() {
            entry.name = username;
        }
        if remember {
            if let Some(secret) = accounts::protect_passphrase(&dir, &passphrase) {
                entry.secret = secret;
                entry.autologin = true;
            }
        }
        accounts::upsert(&root, entry)?;
        {
            let mut g = app.inner.lock().unwrap();
            g.account_id = id;
            g.root = root;
        }
        Ok(app)
    }

    /// Unlock an account whose passphrase this computer remembers.
    #[frb(sync)]
    pub fn open_account_auto(root: String, id: String) -> Result<UmbraApp, String> {
        let root_path = PathBuf::from(&root);
        let entry = accounts::load(&root_path)
            .into_iter()
            .find(|a| a.id == id)
            .ok_or_else(|| "account not found".to_string())?;
        let dir = accounts::account_dir(&root_path, &id);
        let passphrase = accounts::recover_passphrase(&dir, &entry.secret)
            .ok_or_else(|| "saved passphrase could not be read".to_string())?;
        // `remember` again, not because anything changed, but because it
        // rewrites the stored blob in the current format. That is how entries
        // written by an older build pick up the entropy binding.
        UmbraApp::open_account(root, id, passphrase, true)
    }

    /// Turn auto sign-in on (needs the passphrase) or off for this account.
    #[frb(sync)]
    pub fn set_autologin(&self, passphrase: String, enabled: bool) -> Result<(), String> {
        let (root, id, name, dir) = {
            let g = self.inner.lock().unwrap();
            (g.root.clone(), g.account_id.clone(), g.username.clone(), g.dir.clone())
        };
        if id.is_empty() {
            return Err("account context missing".to_string());
        }
        let mut entry = accounts::load(&root)
            .into_iter()
            .find(|a| a.id == id)
            .unwrap_or(AccountEntry { id: id.clone(), name, autologin: false, secret: String::new() });
        if enabled {
            entry.secret = accounts::protect_passphrase(&dir, &passphrase)
                .ok_or_else(|| "this system cannot store the passphrase safely".to_string())?;
            entry.autologin = true;
        } else {
            entry.secret = String::new();
            entry.autologin = false;
        }
        accounts::upsert(&root, entry)
    }

    /// Whether this account signs in automatically.
    #[frb(sync)]
    pub fn autologin_enabled(&self) -> bool {
        let (root, id) = {
            let g = self.inner.lock().unwrap();
            (g.root.clone(), g.account_id.clone())
        };
        accounts::load(&root).into_iter().any(|a| a.id == id && a.autologin)
    }

    /// Delete an account and everything it stored on this computer.
    #[frb(sync)]
    pub fn forget_account(root: String, id: String) -> Result<(), String> {
        accounts::remove(&PathBuf::from(root), &id)
    }

    /// Let go of the signed-in session: close the database, drop the identity
    /// key, and tear down the network.
    ///
    /// The store's keys zeroize on drop, so this really does take them out of
    /// their own memory — but it does not make the session unrecoverable. A key
    /// that has been live gets copied by the allocator, by a scheduler saving a
    /// stack, and by the page file, and none of those copies has a destructor.
    /// Leaving the process is what settles that, and the caller does exactly
    /// that next; see `AppState.signOut` on the Dart side. This function's job
    /// is to make that exit clean — no half-written database, no orphaned tor.
    #[frb(sync)]
    pub fn end_session() {
        // The network first: its tasks reach for APP, and TorProcess kills the
        // daemon when it drops, so nothing is left holding tor's data directory
        // against the next sign-in.
        *SERVICE.lock().unwrap() = None;
        *APP.lock().unwrap() = None;
        *ONION.lock().unwrap() = None;
        *CONTACTS.lock().unwrap() = None;
        *PQ_FINGERPRINTS.lock().unwrap() = None;
        *DIALLING.lock().unwrap() = None;
        *FLUSHING.lock().unwrap() = None;
        *MY_PROFILE.lock().unwrap() = None;
        // Last: the UI's event channel is how anything above would have
        // reported itself, and there is nobody left to report to.
        *EVENTS.lock().unwrap() = None;
    }

    #[frb(sync)]
    pub fn username(&self) -> String {
        self.inner.lock().unwrap().username.clone()
    }

    #[frb(sync)]
    pub fn user_code(&self) -> String {
        user_code(&self.inner.lock().unwrap().account.public())
    }

    #[frb(sync)]
    pub fn identity_hex(&self) -> String {
        hex(&self.inner.lock().unwrap().account.public())
    }

    /// A shareable `umbra1:` invite carrying our identity, username and live
    /// onion address. Empty until the onion service is up.
    #[frb(sync)]
    pub fn my_invite(&self) -> String {
        let onion = ONION.lock().unwrap().clone().unwrap_or_default();
        if onion.is_empty() {
            return String::new();
        }
        let g = self.inner.lock().unwrap();
        // Commit to the post-quantum half as well. 32 bytes, so the invite is
        // still something you can paste into a chat; the 1952-byte key itself
        // arrives during the handshake and is checked against this.
        let pq = HybridIdentity::from_seed(&g.account.secret_seed()).pq_fingerprint();
        Invite::with_pq(g.account.public(), g.username.clone(), onion, pq).encode()
    }

    /// Our onion address, or empty while the network is still starting.
    #[frb(sync)]
    pub fn my_onion(&self) -> String {
        ONION.lock().unwrap().clone().unwrap_or_default()
    }

    /// Start the Tor node: bootstrap (directly, falling back to bridges when
    /// the network blocks Tor), host our onion service, and accept incoming
    /// peers. Returns immediately — all progress arrives as [`NetEvent`]s.
    pub fn start_network(&self, sink: StreamSink<NetEvent>) {
        let (seed, dir) = {
            let g = self.inner.lock().unwrap();
            (*g.account.secret_seed(), g.dir.clone())
        };

        let (tx, mut rx) = mpsc::unbounded_channel::<NetEvent>();
        *EVENTS.lock().unwrap() = Some(tx);

        // Pump internal events out to Dart.
        rt().spawn(async move {
            while let Some(ev) = rx.recv().await {
                if sink.add(ev).is_err() {
                    break; // Dart side closed the stream
                }
            }
        });

        // Payload handlers persist group state themselves, so they need the
        // signed-in account.
        *APP.lock().unwrap() = Some(self.inner.clone());

        // Remember every contact we may need to reach, so the background
        // keep-alive loop can dial them without touching the store.
        {
            let g = self.inner.lock().unwrap();
            if let Ok(list) = g.store.list_contacts() {
                let mut c = CONTACTS.lock().unwrap();
                let c = c.get_or_insert_with(HashMap::new);
                c.clear();
                for contact in list {
                    let peer = hex(&contact.identity_pubkey);
                    remember_pq_fingerprint(&peer, contact.pq_fingerprint);
                    c.insert(peer, contact.onion_addr);
                }
            }
            // Group members are reachable peers too, even when they were never
            // added as contacts.
            if let Ok(groups) = g.store.list_groups() {
                let mut c = CONTACTS.lock().unwrap();
                let c = c.get_or_insert_with(HashMap::new);
                for group in groups {
                    for m in group.members {
                        if !m.onion.is_empty() {
                            c.entry(hex(&m.identity)).or_insert(m.onion);
                        }
                    }
                }
            }
        }

        // Start every run with an empty log. Builds up to 1.7.0 wrote message
        // text, contact names and onion addresses into this file in the clear,
        // so the old contents are a liability sitting next to the encrypted
        // database — and truncating also stops the file growing without end.
        let log_path = dir.join("nullchat-app.log");
        let _ = std::fs::write(&log_path, b"");
        *LOGPATH.lock().unwrap() = Some(log_path);
        *FILES_DIR.lock().unwrap() = Some(dir.join("files"));
        let _ = std::fs::create_dir_all(dir.join("files"));
        {
            // Files sent or received before attachments were kept with the
            // message are sitting in there unreferenced; put them back into
            // the conversation so old photos and GIFs show up too.
            let g = self.inner.lock().unwrap();
            if let Ok(n) = g.store.backfill_attachments(&dir.join("files")) {
                if n > 0 {
                    log_line(&format!("{n} starším zprávám se vrátila příloha"));
                }
            }
        }
        {
            let g = self.inner.lock().unwrap();
            let picture = g
                .store
                .get_secret("avatar")
                .ok()
                .flatten()
                .map(|v| v.to_vec())
                .unwrap_or_default();
            *MY_PROFILE.lock().unwrap() = Some((g.username.clone(), picture));
        }
        log_line("--- start_network ---");

        rt().spawn(async move {
            emit("status", "tor_starting", "");
            match TorService::start(seed, &dir, |msg| emit("status", msg, "")).await {
                Ok((svc, mut incoming)) => {
                    let onion = svc.onion.clone();
                    // The updater talks to GitHub through this very daemon, so
                    // the version check is onion-routed like everything else.
                    let socks_port = nullchat_transport::ctor::socks_port_of(&svc);
                    *ONION.lock().unwrap() = Some(onion.clone());
                    *SERVICE.lock().unwrap() = Some(svc);
                    emit("onion", &onion, "");
                    spawn_keepalive();
                    spawn_updater(socks_port);
                    while let Some(i) = incoming.recv().await {
                        match i.kind.as_str() {
                            "connected" => {
                                // Introduce ourselves, then deliver anything queued.
                                send_profile(&i.peer_hex).await;
                                flush_pending(&i.peer_hex).await;
                                emit("connected", "", &i.peer_hex);
                            }
                            "message" => handle_payload(&i.peer_hex, &i.bytes).await,
                            other => emit(other, &i.body, &i.peer_hex),
                        }
                    }
                }
                Err(e) => emit("error", &format!("Tor se nepodařilo spustit: {e}"), ""),
            }
        });
    }

    /// Dial a stored contact over Tor and run the verified handshake.
    #[frb(sync)]
    pub fn connect_peer(&self, contact_hex: String) {
        let Some(pk) = unhex(&contact_hex) else {
            emit("error", "neplatné ID kontaktu", &contact_hex);
            return;
        };
        let onion = {
            let g = self.inner.lock().unwrap();
            match g.store.get_contact(&pk) {
                Ok(Some(c)) => c.onion_addr,
                _ => {
                    emit("error", "kontakt nenalezen", &contact_hex);
                    return;
                }
            }
        };
        if onion.is_empty() || !onion.ends_with(".onion") {
            emit("error", "kontakt nemá platnou onion adresu", &contact_hex);
            return;
        }
        rt().spawn(async move {
            let svc = SERVICE.lock().unwrap().clone();
            let Some(svc) = svc else {
                emit("error", "síť ještě neběží", "");
                return;
            };
            // Reaching an onion service is slow and often fails on the first
            // try (descriptor lookup, rendezvous, censored networks), so keep
            // retrying instead of making the user click again and again.
            const ATTEMPTS: u32 = 12;
            for attempt in 1..=ATTEMPTS {
                emit("status", &format!("connecting|{attempt}|{ATTEMPTS}"), &contact_hex);
                match svc.connect(onion.clone(), pk, pq_fingerprint_of(&contact_hex)).await {
                    Ok(()) => return, // "connected" event follows from the session
                    Err(e) => {
                        if attempt == ATTEMPTS {
                            emit(
                                "error",
                                &format!(
                                    "Spojení se nepodařilo navázat: {e}. \
                                     Protějšek musí mít aplikaci spuštěnou a být online."
                                ),
                                &contact_hex,
                            );
                        } else {
                            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                        }
                    }
                }
            }
        });
    }


    /// Set our profile picture (raw image bytes, stored encrypted) and push it
    /// to everyone we are connected to.
    #[frb(sync)]
    pub fn set_my_picture(&self, bytes: Vec<u8>) -> Result<(), String> {
        {
            let g = self.inner.lock().unwrap();
            g.store.put_secret("avatar", &bytes).map_err(|e| e.to_string())?;
            *MY_PROFILE.lock().unwrap() = Some((g.username.clone(), bytes));
        }
        rt().spawn(async move {
            let svc = SERVICE.lock().unwrap().clone();
            if let Some(svc) = svc {
                for peer in svc.connected_peers().await {
                    send_profile(&peer).await;
                }
            }
        });
        Ok(())
    }

    /// Our profile picture bytes (empty when none is set).
    #[frb(sync)]
    pub fn my_picture(&self) -> Vec<u8> {
        let g = self.inner.lock().unwrap();
        g.store
            .get_secret("avatar")
            .ok()
            .flatten()
            .map(|v| v.to_vec())
            .unwrap_or_default()
    }

    /// Path to a contact's cached picture, or empty if we have none.
    #[frb(sync)]
    pub fn contact_picture_path(&self, contact_hex: String) -> String {
        let dir = FILES_DIR.lock().unwrap().clone();
        match dir {
            Some(d) => {
                let p = d.join(format!("avatar-{contact_hex}.img"));
                if p.exists() { p.to_string_lossy().to_string() } else { String::new() }
            }
            None => String::new(),
        }
    }

    /// Decrypt an attachment so the user can open or save it.
    ///
    /// Attachments are sealed on disk, so there is no path the operating system
    /// can open directly. Returning the bytes keeps the decision — show it,
    /// save it somewhere, discard it — with the caller.
    pub async fn read_attachment(&self, path: String) -> Result<Vec<u8>, String> {
        let g = self.inner.lock().unwrap();
        g.store
            .decrypt_file(&PathBuf::from(path))
            .map(|d| d.to_vec())
            .map_err(|e| e.to_string())
    }

    /// Send an attachment we already hold to somebody else.
    ///
    /// The bytes are read from our sealed copy, so forwarding never goes back
    /// to whoever originally served the file: the recipient learns nothing
    /// about where it came from, and no third party learns it was forwarded.
    #[frb(sync)]
    pub fn forward_attachment(&self, contact_hex: String, path: String, name: String) {
        let data = {
            let g = self.inner.lock().unwrap();
            g.store.decrypt_file(&PathBuf::from(&path)).map(|d| d.to_vec())
        };
        rt().spawn(async move {
            match data {
                Ok(bytes) => send_file_or_queue(&contact_hex, &name, bytes).await,
                Err(e) => emit("error", &format!("přílohu nelze přečíst: {e}"), &contact_hex),
            }
        });
    }

    /// Remove one message from this device, with the file it carried.
    #[frb(sync)]
    pub fn delete_message(&self, id: i64) -> Result<(), String> {
        let removed = {
            let g = self.inner.lock().unwrap();
            g.store.delete_message(id).map_err(|e| e.to_string())?
        };
        // The sealed file is useless once nothing points at it, and leaving it
        // would keep the picture on disk after the user deleted it.
        if let Some(path) = removed {
            let _ = std::fs::remove_file(path);
        }
        Ok(())
    }

    /// Write a decrypted copy where the user asked for it.
    ///
    /// This is the only way a plaintext attachment reaches the disk, and it
    /// happens because somebody chose a destination for it.
    pub async fn export_attachment(&self, path: String, to: String) -> Result<(), String> {
        let g = self.inner.lock().unwrap();
        let data = g
            .store
            .decrypt_file(&PathBuf::from(path))
            .map_err(|e| e.to_string())?;
        std::fs::write(&to, &*data).map_err(|e| e.to_string())
    }

    /// Seal attachments that older versions left in the clear.
    ///
    /// Runs on sign-in. Returns how many were converted, so the app can say so
    /// rather than changing the user's files silently.
    pub async fn encrypt_existing_attachments(&self) -> Result<u32, String> {
        let dir = FILES_DIR.lock().unwrap().clone();
        let Some(dir) = dir else { return Ok(0) };
        let Ok(entries) = std::fs::read_dir(&dir) else { return Ok(0) };

        let mut converted = 0u32;
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let g = self.inner.lock().unwrap();
            if g.store.file_is_encrypted(&path) {
                continue;
            }
            let Ok(plain) = std::fs::read(&path) else { continue };
            if g.store.encrypt_file(&path, &plain).is_ok() {
                converted += 1;
            }
        }
        if converted > 0 {
            log_line(&format!("sealed {converted} attachment(s) left unencrypted by an older version"));
        }
        Ok(converted)
    }

    /// Where finished incoming files are stored.
    #[frb(sync)]
    pub fn files_dir(&self) -> String {
        FILES_DIR
            .lock()
            .unwrap()
            .clone()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default()
    }

    /// Send a file: read it, split it into chunks and push each one through the
    /// encrypted session — or leave it in the outbox if the contact is offline,
    /// the same way a text message waits. Progress arrives as events.
    #[frb(sync)]
    pub fn send_file(&self, contact_hex: String, path: String) {
        rt().spawn(async move {
            let p = PathBuf::from(&path);
            let name = p
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "soubor".to_string());
            let data = match std::fs::read(&p) {
                Ok(d) => d,
                Err(e) => {
                    emit("error", &format!("soubor nelze přečíst: {e}"), &contact_hex);
                    return;
                }
            };
            send_file_or_queue(&contact_hex, &name, data).await;
        });
    }

    // --- GIFs (see docs/GIFS.md) -------------------------------------------

    /// The GIPHY API key this account uses, empty when none is set.
    ///
    /// It lives in the encrypted store like everything else. It is not much of
    /// a secret — it identifies an application, not a person — but it is the
    /// user's property, and *which* services an account is set up to talk to is
    /// itself worth not leaving in the clear.
    #[frb(sync)]
    pub fn gif_key(&self) -> String {
        let g = self.inner.lock().unwrap();
        g.store
            .get_secret("giphy_api_key")
            .ok()
            .flatten()
            .map(|v| String::from_utf8_lossy(&v).trim().to_string())
            .unwrap_or_default()
    }

    /// Whether searching can work at all: this build ships with a key, or the
    /// user supplied one. The picker asks before showing a setup panel nobody
    /// normally needs.
    #[frb(sync)]
    pub fn gif_key_available(&self) -> bool {
        gifs::key_for(&self.gif_key()).is_some()
    }

    /// Store (or clear, with an empty string) the GIPHY API key.
    #[frb(sync)]
    pub fn set_gif_key(&self, key: String) -> Result<(), String> {
        let g = self.inner.lock().unwrap();
        g.store
            .put_secret("giphy_api_key", key.trim().as_bytes())
            .map_err(|e| e.to_string())
    }

    /// Search GIPHY, over Tor, on a circuit of its own.
    ///
    /// The exit node that sees a search term is deliberately not the one
    /// carrying anything else this app does.
    pub async fn gif_search(&self, query: String, limit: u32) -> Result<Vec<GifView>, String> {
        let port = socks_port_now().ok_or_else(|| "síť ještě neběží".to_string())?;
        let key = self.gif_key();
        let found = if query.trim().is_empty() {
            gifs::featured(port, limit, &gif_circuit(), &key).await?
        } else {
            gifs::search(port, &query, limit, &gif_circuit(), &key).await?
        };
        Ok(found.into_iter().map(GifView::from).collect())
    }

    /// Fetch a preview thumbnail, through Tor.
    ///
    /// The picker calls this instead of handing the URL to Flutter's image
    /// loader, which would fetch it over the clearnet and undo the whole point.
    pub async fn gif_preview(&self, url: String) -> Result<Vec<u8>, String> {
        let port = socks_port_now().ok_or_else(|| "síť ještě neběží".to_string())?;
        gifs::fetch(port, &url, &gif_circuit()).await
    }

    /// Send a GIF to a contact.
    ///
    /// **We** download it and push the bytes through the encrypted file
    /// channel. The recipient's device never contacts GIPHY — sending a link
    /// instead would hand their IP address and the time to a third party, which
    /// is the one thing this whole design exists to prevent.
    ///
    /// The download needs Tor; delivery does not need the contact to be online.
    /// If they are away the GIF waits in the encrypted outbox and goes out by
    /// itself when they appear, exactly like a text message.
    #[frb(sync)]
    pub fn send_gif(&self, contact_hex: String, gif_url: String, description: String) {
        rt().spawn(async move {
            let Some(port) = socks_port_now() else {
                emit("error", "síť ještě neběží", &contact_hex);
                return;
            };

            emit("gif_fetching", "", &contact_hex);
            let data = match gifs::fetch(port, &gif_url, &gif_circuit()).await {
                Ok(d) => d,
                Err(e) => {
                    emit("error", &format!("GIF se nepodařilo stáhnout: {e}"), &contact_hex);
                    return;
                }
            };

            // A name from the description, not from the URL: a remote-supplied
            // filename has no business reaching a filesystem, and the receiving
            // side sanitises it anyway.
            // The fallback comes from the URL's own id segment, which is the
            // one part of it that identifies the GIF. It is filtered to
            // alphanumerics before it is used, so it cannot become a path.
            let url_tag = gif_url
                .rsplit('/')
                .find(|s| s.len() > 4 && s.chars().any(|c| c.is_ascii_alphanumeric()))
                .unwrap_or("");
            let name = safe_gif_name(&description, url_tag);
            send_file_or_queue(&contact_hex, &name, data).await;
        });
    }

    /// Store a message and send it. If the contact is not reachable it waits in
    /// the encrypted outbox and goes out by itself once they appear — closing
    /// the app does not lose it.
    #[frb(sync)]
    pub fn send_over_network(&self, contact_hex: String, text: String, now: u64) -> Result<(), String> {
        let pk = unhex(&contact_hex).ok_or_else(|| "bad contact id".to_string())?;
        let message_id = {
            let g = self.inner.lock().unwrap();
            g.store
                .insert_message(&NewMessage {
                    contact_pubkey: pk,
                    direction: Direction::Outgoing,
                    sent_at: now,
                    body: text.as_bytes(),
                    file: None,
                })
                .map_err(|e| e.to_string())?
        };
        rt().spawn(async move {
            let bytes = envelope::encode_text(&text);
            send_or_queue(
                &contact_hex,
                Pending {
                    bytes,
                    ui: text,
                    group_hex: String::new(),
                    message_id: Some(message_id),
                },
            )
            .await;
        });
        Ok(())
    }

    /// Throw away Tor's cached directory data and start the network again.
    ///
    /// The identity and the onion address are kept — only what Tor can fetch
    /// again is deleted. This is the manual version of the repair the app
    /// already tries by itself when a bootstrap stalls.
    #[frb(sync)]
    pub fn repair_tor(&self, sink: StreamSink<NetEvent>) -> Result<(), String> {
        {
            let g = self.inner.lock().unwrap();
            nullchat_transport::ctor::clear_tor_cache(&g.dir).map_err(|e| e.to_string())?;
        }
        // Drop the old service so its daemon exits and releases the lock.
        *SERVICE.lock().unwrap() = None;
        *ONION.lock().unwrap() = None;
        self.start_network(sink);
        Ok(())
    }

    /// Bridges the user pasted themselves, or empty when NullChat's own list is in
    /// use. Stored next to the account's Tor data, where the daemon reads it.
    #[frb(sync)]
    pub fn custom_bridges(&self) -> String {
        let g = self.inner.lock().unwrap();
        std::fs::read_to_string(g.dir.join("bridges.txt")).unwrap_or_default()
    }

    /// Replace (or, with empty text, drop) the user's own bridge lines. Takes
    /// effect the next time Tor starts.
    #[frb(sync)]
    pub fn set_custom_bridges(&self, text: String) -> Result<(), String> {
        let g = self.inner.lock().unwrap();
        let path = g.dir.join("bridges.txt");
        if text.trim().is_empty() {
            let _ = std::fs::remove_file(&path);
            return Ok(());
        }
        std::fs::write(&path, text.trim()).map_err(|e| e.to_string())
    }

    /// How many messages are still waiting for their peer.
    #[frb(sync)]
    pub fn pending_messages(&self) -> u32 {
        let g = self.inner.lock().unwrap();
        g.store
            .outbox_summary()
            .map(|v| v.iter().map(|(_, n)| n).sum())
            .unwrap_or(0)
    }

    /// Add a contact from a pasted `umbra1:` invite. Returns the parsed contact.
    #[frb(sync)]
    pub fn add_contact(&self, invite_code: String, now: u64) -> Result<ContactView, String> {
        let inv = Invite::decode(invite_code.trim()).map_err(|e| e.to_string())?;
        let g = self.inner.lock().unwrap();
        g.store
            .upsert_contact(&Contact {
                identity_pubkey: inv.identity,
                display_name: inv.username.clone(),
                onion_addr: inv.onion.clone(),
                added_at: now,
                // We pasted their invite ourselves, so there is nothing to
                // approve, and someone worth adding is worth keeping.
                status: ContactStatus::Accepted,
                saved: true,
                // Pasting an invite says where it came from, not that it was
                // not swapped on the way. Only comparing the safety number
                // does, and that has not happened yet.
                verified: false,
                pq_fingerprint: inv.pq_fingerprint,
            })
            .map_err(|e| e.to_string())?;
        remember_pq_fingerprint(&hex(&inv.identity), inv.pq_fingerprint);
        CONTACTS
            .lock()
            .unwrap()
            .get_or_insert_with(HashMap::new)
            .insert(hex(&inv.identity), inv.onion.clone());
        Ok(ContactView {
            identity_hex: hex(&inv.identity),
            user_code: user_code(&inv.identity),
            display_name: inv.username,
            onion: inv.onion,
            added_at: now,
            status: 1,
            saved: true,
            verified: false,
        })
    }

    #[frb(sync)]
    pub fn list_contacts(&self) -> Result<Vec<ContactView>, String> {
        let g = self.inner.lock().unwrap();
        Ok(g
            .store
            .list_contacts()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|c| ContactView {
                identity_hex: hex(&c.identity_pubkey),
                user_code: user_code(&c.identity_pubkey),
                display_name: c.display_name,
                onion: c.onion_addr,
                added_at: c.added_at,
                status: match c.status {
                    ContactStatus::Waiting => 0,
                    ContactStatus::Accepted => 1,
                    ContactStatus::Blocked => 2,
                },
                saved: c.saved,
                verified: c.verified,
            })
            .collect())
    }

    // --- duress passphrases (see docs/DURESS.md) ---------------------------

    /// Derive the key one more passphrase would produce for this account.
    fn duress_key(&self, passphrase: &str) -> Result<Zeroizing<[u8; 32]>, String> {
        let dir = { self.inner.lock().unwrap().dir.clone() };
        let salt = std::fs::read(account_file(&dir, "nullchat.salt")).map_err(|e| e.to_string())?;
        let (m, t, p) = read_kdf(&dir);
        keystore::derive_store_key_with(passphrase.as_bytes(), &salt, m, t, p)
            .map_err(|e| e.to_string())
    }

    /// Add a second passphrase to this account.
    ///
    /// `kind` is `"decoy"` (its own separate history) or `"wipe"` (destroys
    /// everything it cannot read, then behaves like a new account). Both are
    /// optional and independent.
    ///
    /// The new passphrase gets its own identity and its own rows in the same
    /// file. Nothing records that it exists except a note sealed under *this*
    /// passphrase, so the file itself never says how many it answers to.
    #[frb(sync)]
    pub fn set_duress_passphrase(&self, kind: String, passphrase: String) -> Result<(), String> {
        let profile = match kind.as_str() {
            "decoy" => ProfileKind::Decoy,
            "wipe" => ProfileKind::Wipe,
            _ => return Err("neznámý druh nouzové fráze".to_string()),
        };
        if passphrase.trim().len() < 12 {
            return Err("Nouzová fráze musí mít aspoň 12 znaků.".to_string());
        }
        let key = self.duress_key(&passphrase)?;
        let dir = { self.inner.lock().unwrap().dir.clone() };
        let store = Store::open(&account_file(&dir, "nullchat.db"), &key).map_err(|e| e.to_string())?;

        // Refuse a passphrase this account already answers to. Without this
        // check, reusing the real passphrase would mark the *real* profile as
        // "wipe" and destroy everything at the next sign-in.
        if store.get_secret("identity_seed").map_err(|e| e.to_string())?.is_some() {
            return Err("Tuto frázi už tento účet používá. Zvol jinou.".to_string());
        }

        // Its own identity, so the decoy behaves like a real, usable account.
        let account = Keypair::generate().map_err(|e| e.to_string())?;
        store
            .put_secret("identity_seed", &*account.secret_seed())
            .map_err(|e| e.to_string())?;
        store.put_secret("username", b"").map_err(|e| e.to_string())?;
        store.set_profile_kind(profile).map_err(|e| e.to_string())?;

        // Remembered only for us, so Settings can show what is configured.
        let g = self.inner.lock().unwrap();
        g.store
            .put_secret(&format!("duress.{kind}"), b"1")
            .map_err(|e| e.to_string())
    }

    /// Which duress passphrases this account has, as far as *we* can tell.
    ///
    /// Returns e.g. `["decoy"]`. This is a note we wrote for ourselves; a
    /// duress profile cannot see it, and neither can anyone without this
    /// passphrase.
    #[frb(sync)]
    pub fn duress_configured(&self) -> Vec<String> {
        let g = self.inner.lock().unwrap();
        ["decoy", "wipe"]
            .into_iter()
            .filter(|k| {
                g.store
                    .get_secret(&format!("duress.{k}"))
                    .ok()
                    .flatten()
                    .is_some()
            })
            .map(|k| k.to_string())
            .collect()
    }

    /// Turn a duress passphrase off again. Needs the passphrase itself, since
    /// that is the only thing that can reach its rows.
    #[frb(sync)]
    pub fn clear_duress_passphrase(&self, passphrase: String) -> Result<String, String> {
        let key = self.duress_key(&passphrase)?;
        let dir = { self.inner.lock().unwrap().dir.clone() };
        let store = Store::open(&account_file(&dir, "nullchat.db"), &key).map_err(|e| e.to_string())?;
        let kind = store.profile_kind();
        // Never let this be pointed at the real account.
        if kind == ProfileKind::Normal {
            return Err("Tato fráze není nouzová.".to_string());
        }
        // Removing the identity is what stops it opening; the rest of its rows
        // stay behind as unreadable noise, which is exactly what everything
        // else in the file looks like anyway.
        store.delete_secret("identity_seed").map_err(|e| e.to_string())?;
        store.delete_secret("profile.kind").map_err(|e| e.to_string())?;
        let name = if kind == ProfileKind::Decoy { "decoy" } else { "wipe" };
        let g = self.inner.lock().unwrap();
        g.store.delete_secret(&format!("duress.{name}")).map_err(|e| e.to_string())?;
        Ok(name.to_string())
    }

    /// Write a conversation into the decoy profile, so it is not suspiciously
    /// empty. Called from the real account, which is the only place that knows
    /// both passphrases.
    #[frb(sync)]
    pub fn fill_decoy(
        &self,
        passphrase: String,
        contact_name: String,
        lines: Vec<String>,
        start_at: u64,
    ) -> Result<(), String> {
        let key = self.duress_key(&passphrase)?;
        let dir = { self.inner.lock().unwrap().dir.clone() };
        let store = Store::open(&account_file(&dir, "nullchat.db"), &key).map_err(|e| e.to_string())?;
        if store.profile_kind() != ProfileKind::Decoy {
            return Err("Tato fráze nepatří nastrčenému účtu.".to_string());
        }
        let mut identity = [0u8; 32];
        getrandom::getrandom(&mut identity).map_err(|_| "RNG failed".to_string())?;
        store
            .upsert_contact(&Contact {
                identity_pubkey: identity,
                display_name: contact_name.trim().to_string(),
                onion_addr: String::new(),
                added_at: start_at,
                status: ContactStatus::Accepted,
                saved: true,
                verified: false,
                pq_fingerprint: None,
            })
            .map_err(|e| e.to_string())?;
        // Spread them over time: a history where every message shares one
        // timestamp is not a history anyone will believe.
        for (i, line) in lines.iter().enumerate() {
            store
                .insert_message(&NewMessage {
                    contact_pubkey: identity,
                    direction: if i % 2 == 0 { Direction::Incoming } else { Direction::Outgoing },
                    sent_at: start_at + (i as u64) * 900,
                    body: line.as_bytes(),
                    file: None,
                })
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Delete a contact together with its whole conversation.
    #[frb(sync)]
    pub fn delete_contact(&self, contact_hex: String) -> Result<(), String> {
        let pk = unhex(&contact_hex).ok_or_else(|| "neplatná identita".to_string())?;
        let g = self.inner.lock().unwrap();
        g.store.delete_contact(&pk).map_err(|e| e.to_string())?;
        drop(g);
        // Stop the keep-alive loop from dialling somebody we just removed.
        if let Some(map) = CONTACTS.lock().unwrap().as_mut() {
            map.remove(&contact_hex);
        }
        Ok(())
    }

    /// Fold one conversation into another: the same person with two identities,
    /// because they reinstalled or made a new account.
    ///
    /// The app cannot decide this by itself — two identities are two identities,
    /// and matching people by display name would merge strangers who share a
    /// name. So the user picks, and nothing is deleted: the older thread's
    /// messages (and anything still queued for it) move to the identity that
    /// stays. Returns how many messages moved.
    #[frb(sync)]
    pub fn merge_contact(&self, from_hex: String, into_hex: String) -> Result<u32, String> {
        let from = unhex(&from_hex).ok_or_else(|| "neplatná identita".to_string())?;
        let into = unhex(&into_hex).ok_or_else(|| "neplatná identita".to_string())?;
        if from == into {
            return Err("nelze sloučit kontakt sám se sebou".to_string());
        }
        let moved = {
            let g = self.inner.lock().unwrap();
            g.store.merge_contacts(&from, &into).map_err(|e| e.to_string())?
        };
        // The identity that no longer exists must not be dialled again.
        if let Some(map) = CONTACTS.lock().unwrap().as_mut() {
            map.remove(&from_hex);
        }
        Ok(moved as u32)
    }

    /// The 60 digits this contact and I must both see, in groups of five.
    ///
    /// Empty when we have no such contact. Both sides compute it from the same
    /// two identity keys, so reading it aloud over a channel an attacker would
    /// have to control *as well* is what rules out a swapped invite.
    #[frb(sync)]
    pub fn safety_number(&self, contact_hex: String) -> String {
        let Some(pk) = unhex(&contact_hex) else { return String::new() };
        let g = self.inner.lock().unwrap();
        // Covers the post-quantum halves too, so comparing the digits confirms
        // the whole identity and not just its classical part.
        let mine = HybridIdentity::from_seed(&g.account.secret_seed()).pq_fingerprint();
        let theirs = g
            .store
            .get_contact(&pk)
            .ok()
            .flatten()
            .and_then(|c| c.pq_fingerprint);
        safety::grouped(&safety::safety_number_full(
            &g.account.public(),
            Some(&mine),
            &pk,
            theirs.as_ref(),
        ))
    }

    /// Does this contact have a post-quantum identity? Used by the UI to say so
    /// rather than implying protection a pre-1.9 contact does not have.
    #[frb(sync)]
    pub fn contact_is_post_quantum(&self, contact_hex: String) -> bool {
        let Some(pk) = unhex(&contact_hex) else { return false };
        let g = self.inner.lock().unwrap();
        g.store
            .get_contact(&pk)
            .ok()
            .flatten()
            .and_then(|c| c.pq_fingerprint)
            .is_some()
    }

    /// Record that the user compared the number and it matched (or take it
    /// back). Nothing in the protocol may call this — only a person can.
    #[frb(sync)]
    pub fn set_verified(&self, contact_hex: String, verified: bool) -> Result<(), String> {
        let pk = unhex(&contact_hex).ok_or_else(|| "neplatná identita".to_string())?;
        let g = self.inner.lock().unwrap();
        g.store.set_contact_verified(&pk, verified).map_err(|e| e.to_string())
    }

    /// Search every conversation for text. Both kinds of message are covered;
    /// newest first.
    #[frb(sync)]
    pub fn search_messages(&self, query: String, limit: u32) -> Result<Vec<SearchHitView>, String> {
        let g = self.inner.lock().unwrap();
        Ok(g
            .store
            .search_messages(&query, limit)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(hit_view)
            .collect())
    }

    /// Everything one person has sent us, in the 1:1 thread and in groups.
    #[frb(sync)]
    pub fn messages_from_contact(
        &self,
        contact_hex: String,
        limit: u32,
    ) -> Result<Vec<SearchHitView>, String> {
        let pk = unhex(&contact_hex).ok_or_else(|| "bad contact id".to_string())?;
        let g = self.inner.lock().unwrap();
        Ok(g
            .store
            .messages_from(&pk, limit)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(hit_view)
            .collect())
    }

    /// Give a contact the name you know them by.
    #[frb(sync)]
    pub fn rename_contact(&self, contact_hex: String, name: String) -> Result<(), String> {
        let pk = unhex(&contact_hex).ok_or_else(|| "bad contact id".to_string())?;
        let g = self.inner.lock().unwrap();
        g.store.rename_contact(&pk, &name).map_err(|e| e.to_string())
    }

    /// Accept a waiting conversation (1), or block the contact (2). Blocking
    /// also drops whatever they still have queued with us.
    #[frb(sync)]
    pub fn set_contact_status(&self, contact_hex: String, status: u8) -> Result<(), String> {
        let pk = unhex(&contact_hex).ok_or_else(|| "bad contact id".to_string())?;
        let status = match status {
            0 => ContactStatus::Waiting,
            2 => ContactStatus::Blocked,
            _ => ContactStatus::Accepted,
        };
        let g = self.inner.lock().unwrap();
        g.store.set_contact_status(&pk, status).map_err(|e| e.to_string())?;
        if status == ContactStatus::Blocked {
            for item in g.store.outbox_for(&pk).unwrap_or_default() {
                let _ = g.store.dequeue(item.id);
            }
            CONTACTS.lock().unwrap().as_mut().map(|m| m.remove(&contact_hex));
        }
        Ok(())
    }

    /// Keep a contact in the address book (or drop them from it).
    #[frb(sync)]
    pub fn set_contact_saved(&self, contact_hex: String, saved: bool) -> Result<(), String> {
        let pk = unhex(&contact_hex).ok_or_else(|| "bad contact id".to_string())?;
        let g = self.inner.lock().unwrap();
        g.store.set_contact_saved(&pk, saved).map_err(|e| e.to_string())
    }

    #[frb(sync)]
    pub fn add_message(
        &self,
        contact_hex: String,
        outgoing: bool,
        sent_at: u64,
        body: String,
    ) -> Result<(), String> {
        let pk = unhex(&contact_hex).ok_or_else(|| "bad contact id".to_string())?;
        let g = self.inner.lock().unwrap();
        g.store
            .insert_message(&NewMessage {
                contact_pubkey: pk,
                direction: if outgoing { Direction::Outgoing } else { Direction::Incoming },
                sent_at,
                body: body.as_bytes(),
                file: None,
            })
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    #[frb(sync)]
    pub fn list_messages(&self, contact_hex: String, limit: u32) -> Result<Vec<MessageView>, String> {
        let pk = unhex(&contact_hex).ok_or_else(|| "bad contact id".to_string())?;
        let g = self.inner.lock().unwrap();
        Ok(g
            .store
            .messages_for(&pk, limit)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|m| MessageView {
                id: m.id,
                outgoing: matches!(m.direction, Direction::Outgoing),
                sent_at: m.sent_at,
                body: String::from_utf8_lossy(&m.body).to_string(),
                state: match m.state {
                    MessageState::Waiting => 0,
                    MessageState::Sent => 1,
                    MessageState::Delivered => 2,
                },
                // An attachment whose file is gone is not offered: the preview
                // would fail and the "Save file" button would lie.
                file_path: m
                    .file_path
                    .filter(|p| std::path::Path::new(p).exists())
                    .unwrap_or_default(),
                file_name: m.file_name.unwrap_or_default(),
                file_size: m.file_size.unwrap_or(0),
            })
            .collect())
    }

    // --- groups -----------------------------------------------------------

    /// Create a group from existing contacts. We are always a member, and the
    /// roster is pushed to everyone right away (it doubles as the invitation).
    #[frb(sync)]
    pub fn create_group(
        &self,
        name: String,
        member_hexes: Vec<String>,
        now: u64,
    ) -> Result<GroupView, String> {
        let group = {
            let g = self.inner.lock().unwrap();
            let mut members = vec![GroupMember {
                identity: g.account.public(),
                display_name: g.username.clone(),
                onion: ONION.lock().unwrap().clone().unwrap_or_default(),
            }];
            for hex_id in &member_hexes {
                let pk = unhex(hex_id).ok_or_else(|| "bad contact id".to_string())?;
                let c = g
                    .store
                    .get_contact(&pk)
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| "kontakt nenalezen".to_string())?;
                members.push(GroupMember {
                    identity: c.identity_pubkey,
                    display_name: c.display_name,
                    onion: c.onion_addr,
                });
            }
            let group = Group::create(&name, members, now).map_err(|e| e.to_string())?;
            g.store.upsert_group(&group).map_err(|e| e.to_string())?;
            group
        };
        remember_group_routes(&group);
        broadcast_group_info(&group, &self.identity_pubkey());
        Ok(view_of(&group))
    }

    #[frb(sync)]
    pub fn list_groups(&self) -> Result<Vec<GroupView>, String> {
        let g = self.inner.lock().unwrap();
        Ok(g
            .store
            .list_groups()
            .map_err(|e| e.to_string())?
            .iter()
            .map(view_of)
            .collect())
    }

    /// Add a contact to a group and push the new roster to everyone.
    #[frb(sync)]
    pub fn add_group_member(
        &self,
        group_id_hex: String,
        contact_hex: String,
    ) -> Result<GroupView, String> {
        let gid = unhex16(&group_id_hex).ok_or_else(|| "bad group id".to_string())?;
        let pk = unhex(&contact_hex).ok_or_else(|| "bad contact id".to_string())?;
        let group = {
            let g = self.inner.lock().unwrap();
            let mut group = g
                .store
                .get_group(&gid)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "skupina nenalezena".to_string())?;
            let c = g
                .store
                .get_contact(&pk)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "kontakt nenalezen".to_string())?;
            if !group.add_member(GroupMember {
                identity: c.identity_pubkey,
                display_name: c.display_name,
                onion: c.onion_addr,
            }) {
                return Ok(view_of(&group)); // already in the group
            }
            g.store.upsert_group(&group).map_err(|e| e.to_string())?;
            group
        };
        remember_group_routes(&group);
        broadcast_group_info(&group, &self.identity_pubkey());
        Ok(view_of(&group))
    }

    /// Rename a group. The new name travels with the roster, so everyone sees
    /// it (a group has no owner — see `docs/THREAT_MODEL.md`).
    #[frb(sync)]
    pub fn rename_group(&self, group_id_hex: String, name: String) -> Result<GroupView, String> {
        let gid = unhex16(&group_id_hex).ok_or_else(|| "bad group id".to_string())?;
        let group = {
            let g = self.inner.lock().unwrap();
            let mut group = g
                .store
                .get_group(&gid)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "skupina nenalezena".to_string())?;
            group.rename(&name);
            g.store.upsert_group(&group).map_err(|e| e.to_string())?;
            group
        };
        broadcast_group_info(&group, &self.identity_pubkey());
        Ok(view_of(&group))
    }

    /// Leave a group: tell the others we are gone, then drop it locally with
    /// its whole history.
    #[frb(sync)]
    pub fn leave_group(&self, group_id_hex: String) -> Result<(), String> {
        let gid = unhex16(&group_id_hex).ok_or_else(|| "bad group id".to_string())?;
        let me = self.identity_pubkey();
        let group = {
            let g = self.inner.lock().unwrap();
            let mut group = g
                .store
                .get_group(&gid)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "skupina nenalezena".to_string())?;
            group.remove_member(&me);
            g.store.delete_group(&gid).map_err(|e| e.to_string())?;
            group
        };
        // The roster we send no longer contains us; everyone else keeps talking.
        broadcast_group_info(&group, &me);
        Ok(())
    }

    /// Send a group message: stored locally once, then fanned out over each
    /// member's own 1:1 session.
    #[frb(sync)]
    pub fn send_group_message(
        &self,
        group_id_hex: String,
        text: String,
        now: u64,
    ) -> Result<(), String> {
        let gid = unhex16(&group_id_hex).ok_or_else(|| "bad group id".to_string())?;
        let me = self.identity_pubkey();
        let (group, message_id) = {
            let g = self.inner.lock().unwrap();
            let group = g
                .store
                .get_group(&gid)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "skupina nenalezena".to_string())?;
            let id = g
                .store
                .insert_group_message(&NewGroupMessage {
                    group_id: gid,
                    sender_pubkey: me,
                    direction: Direction::Outgoing,
                    sent_at: now,
                    body: text.as_bytes(),
                })
                .map_err(|e| e.to_string())?;
            (group, id)
        };

        let bytes = envelope::encode_group_text(&gid, &text);
        for m in group.members.iter().filter(|m| m.identity != me) {
            let peer_hex = hex(&m.identity);
            let item = Pending {
                bytes: bytes.clone(),
                ui: text.clone(),
                group_hex: group_id_hex.clone(),
                message_id: Some(message_id),
            };
            rt().spawn(async move { send_or_queue(&peer_hex, item).await });
        }
        Ok(())
    }

    #[frb(sync)]
    pub fn list_group_messages(
        &self,
        group_id_hex: String,
        limit: u32,
    ) -> Result<Vec<GroupMessageView>, String> {
        let gid = unhex16(&group_id_hex).ok_or_else(|| "bad group id".to_string())?;
        let g = self.inner.lock().unwrap();
        let names: HashMap<[u8; 32], String> = g
            .store
            .group_members(&gid)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|m| (m.identity, m.display_name))
            .collect();
        Ok(g
            .store
            .group_messages_for(&gid, limit)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|m| GroupMessageView {
                sender_hex: hex(&m.sender_pubkey),
                sender_name: names.get(&m.sender_pubkey).cloned().unwrap_or_default(),
                outgoing: matches!(m.direction, Direction::Outgoing),
                sent_at: m.sent_at,
                body: String::from_utf8_lossy(&m.body).to_string(),
            })
            .collect())
    }

    fn identity_pubkey(&self) -> [u8; 32] {
        self.inner.lock().unwrap().account.public()
    }
}

/// Flatten a group for the UI.
fn view_of(g: &Group) -> GroupView {
    GroupView {
        id_hex: hex(&g.id),
        name: g.name.clone(),
        version: g.version,
        created_at: g.created_at,
        members: g
            .members
            .iter()
            .map(|m| GroupMemberView {
                identity_hex: hex(&m.identity),
                display_name: m.display_name.clone(),
                onion: m.onion.clone(),
            })
            .collect(),
    }
}

/// Make sure the keep-alive loop can reach every member — group members are
/// not necessarily contacts of ours.
fn remember_group_routes(group: &Group) {
    let mut g = CONTACTS.lock().unwrap();
    let map = g.get_or_insert_with(HashMap::new);
    for m in &group.members {
        if m.onion.is_empty() {
            continue;
        }
        map.entry(hex(&m.identity)).or_insert_with(|| m.onion.clone());
    }
}

/// Push a roster to every member except `me`.
fn broadcast_group_info(group: &Group, me: &[u8; 32]) {
    let bytes = envelope::encode_group_info(group);
    let group_hex = hex(&group.id);
    for m in group.members.iter().filter(|m| &m.identity != me) {
        let peer_hex = hex(&m.identity);
        let item = Pending {
            bytes: bytes.clone(),
            ui: String::new(),
            group_hex: group_hex.clone(),
            // A roster is a snapshot: if they are away, the next connection
            // carries a fresher one anyway.
            message_id: None,
        };
        rt().spawn(async move { send_or_queue(&peer_hex, item).await });
    }
}


/// Our own profile picture (raw image bytes) and name, sent to peers on connect.
static MY_PROFILE: Mutex<Option<(String, Vec<u8>)>> = Mutex::new(None);
/// Where finished incoming files are written.
static FILES_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);
/// Largest file we will accept from a peer. Anything bigger is refused at the
/// offer, before a single byte is written.
const MAX_INCOMING_FILE: u64 = 4 * 1024 * 1024 * 1024;
/// Largest profile picture we will store. A peer used to be able to hand us an
/// image of any size and have it written straight to disk.
const MAX_PICTURE: usize = 8 * 1024 * 1024;
/// How many transfers may be in flight at once, across all peers.
const MAX_TRANSFERS: usize = 16;

/// A transfer in progress.
struct Incoming {
    /// Who is sending it. A chunk from anyone else is refused — without this,
    /// knowing a transfer id was enough to write into someone else's file.
    peer_hex: String,
    name: String,
    size: u64,
    part: PathBuf,
    received: u64,
}

/// Partially received files, keyed by transfer id.
static INCOMING_FILES: Mutex<Option<HashMap<[u8; 16], Incoming>>> = Mutex::new(None);

/// Send our name and picture so the peer can show them.
async fn send_profile(peer_hex: &str) {
    let profile = { MY_PROFILE.lock().unwrap().clone() };
    let Some((name, picture)) = profile else { return };
    let svc = SERVICE.lock().unwrap().clone();
    if let Some(svc) = svc {
        let _ = svc
            .send_bytes(peer_hex, envelope::encode_profile(&name, &picture))
            .await;
        // Tell them where we live, so a conversation we started can be picked
        // up from their side later. Without this the party who was contacted
        // can answer only while the session happens to be up.
        let onion = ONION.lock().unwrap().clone().unwrap_or_default();
        let _ = svc
            .send_bytes(peer_hex, envelope::encode_address(&onion, &name))
            .await;
    }
}

/// Make sure a peer we are talking to has a contact row.
///
/// Everything the UI shows after a restart comes from `contacts`; a peer who
/// wrote to us first used to have messages in the database and nothing else,
/// so the whole thread disappeared on the next start and we never dialled them
/// again. `onion` may be empty — an entry with no address is still a visible
/// conversation, and the address arrives with their next [`Payload::Address`].
fn remember_peer(peer_hex: &str, name: Option<&str>, onion: Option<&str>) {
    remember_peer_inner(peer_hex, name, onion, true)
}

/// The same, but it will not invent a contact out of nothing.
///
/// A `PROFILE` or `ADDRESS` frame whose fields are empty says nothing about
/// anybody: acting on it created a row with no name, no address and no
/// history, which the chat list then showed as a second "unknown contact"
/// beside the real one — the duplicate-conversation bug. Frames that carry
/// actual content (a message, a file) still create the contact, because
/// otherwise the thread would not survive a restart.
fn update_peer_details(peer_hex: &str, name: Option<&str>, onion: Option<&str>) {
    let has_something = name.is_some_and(|n| !n.trim().is_empty())
        || onion.is_some_and(|o| !o.trim().is_empty());
    remember_peer_inner(peer_hex, name, onion, has_something)
}

fn remember_peer_inner(
    peer_hex: &str,
    name: Option<&str>,
    onion: Option<&str>,
    create_if_missing: bool,
) {
    let Some(app) = APP.lock().unwrap().clone() else { return };
    let Some(pk) = unhex(peer_hex) else { return };
    let mut changed = false;
    {
        let g = app.lock().unwrap();
        let existing = g.store.get_contact(&pk).ok().flatten();
        if existing.is_none() && !create_if_missing {
            return;
        }
        let is_new = existing.is_none();
        let mut contact = existing.clone().unwrap_or(Contact {
            identity_pubkey: pk,
            display_name: String::new(),
            onion_addr: String::new(),
            added_at: now_secs(),
            // Someone we never added writes to us: their thread waits for the
            // user's decision instead of appearing among real conversations.
            status: ContactStatus::Waiting,
            saved: false,
            verified: false,
            pq_fingerprint: None,
        });
        let _ = is_new;
        if let Some(name) = name {
            if !name.is_empty() && contact.display_name != name {
                contact.display_name = name.to_string();
                changed = true;
            }
        }
        if let Some(onion) = onion {
            if !onion.is_empty() && contact.onion_addr != onion {
                contact.onion_addr = onion.to_string();
                changed = true;
            }
        }
        if existing.is_none() || changed {
            let _ = g.store.upsert_contact(&contact);
            changed = true;
        }
        if !contact.onion_addr.is_empty() {
            CONTACTS
                .lock()
                .unwrap()
                .get_or_insert_with(HashMap::new)
                .insert(peer_hex.to_string(), contact.onion_addr.clone());
        }
        if changed {
            let display = contact.display_name.clone();
            let addr = contact.onion_addr.clone();
            let status = match contact.status {
                ContactStatus::Waiting => 0,
                ContactStatus::Accepted => 1,
                ContactStatus::Blocked => 2,
            };
            drop(g);
            emit("contact_updated", &format!("{display}|{addr}|{status}"), peer_hex);
        }
    }
}

/// Interpret a decrypted payload from a peer.
async fn handle_payload(peer_hex: &str, bytes: &[u8]) {
    // A blocked identity gets nothing: not stored, not shown, not notified.
    if let (Some(app), Some(pk)) = (APP.lock().unwrap().clone(), unhex(peer_hex)) {
        let blocked = {
            let g = app.lock().unwrap();
            g.store.is_blocked(&pk).unwrap_or(false)
        };
        if blocked {
            log_line("zpráva od blokovaného kontaktu — zahozena");
            return;
        }
    }
    let Some(payload) = envelope::decode(bytes) else {
        // A newer peer speaking a frame we do not know yet is not an error the
        // user can act on; ignoring it keeps the protocol extensible.
        log_line("payload: neznámý typ rámce — ignoruji (novější verze aplikace?)");
        return;
    };
    match payload {
        Payload::Text(text) => {
            // Whoever writes to us becomes a contact, or the thread would not
            // survive a restart.
            remember_peer(peer_hex, None, None);
            emit("message", &text, peer_hex);
            // Confirm it arrived, so their app can stop saying "waiting".
            let svc = SERVICE.lock().unwrap().clone();
            if let Some(svc) = svc {
                let _ = svc.send_bytes(peer_hex, envelope::encode_receipt(&text)).await;
            }
        }
        Payload::Receipt { body } => {
            if let (Some(app), Some(pk)) = (APP.lock().unwrap().clone(), unhex(peer_hex)) {
                let marked = {
                    let g = app.lock().unwrap();
                    g.store.mark_delivered(&pk, body.as_bytes()).ok().flatten()
                };
                if marked.is_some() {
                    emit("delivered", &body, peer_hex);
                }
            }
        }
        Payload::Address { onion, name } => {
            update_peer_details(peer_hex, Some(&name), Some(&onion));
        }
        Payload::Profile { name, picture } => {
            // Cache the picture next to the app data; the UI reads it by path.
            // Bounded: a peer chooses this size, and it lands straight on disk.
            if !picture.is_empty() && picture.len() <= MAX_PICTURE {
                if let Some(dir) = FILES_DIR.lock().unwrap().clone() {
                    let p = dir.join(format!("avatar-{peer_hex}.img"));
                    let _ = std::fs::write(&p, &picture);
                }
            }
            update_peer_details(peer_hex, Some(&name), None);
            emit("profile", &name, peer_hex);
        }
        Payload::FileOffer { id, name, size } => {
            if size > MAX_INCOMING_FILE {
                log_line("file offer refused: too large");
                return;
            }
            let Some(dir) = FILES_DIR.lock().unwrap().clone() else { return };
            let _ = std::fs::create_dir_all(&dir);
            let safe = safe_file_name(&name);
            let part = dir.join(format!("{}.part", hex(&id)));
            {
                let mut g = INCOMING_FILES.lock().unwrap();
                let map = g.get_or_insert_with(HashMap::new);
                // A peer that keeps offering files must not be able to open an
                // unbounded number of part-files on our disk.
                if map.len() >= MAX_TRANSFERS && !map.contains_key(&id) {
                    log_line("file offer refused: too many transfers in flight");
                    return;
                }
                let _ = std::fs::write(&part, b"");
                map.insert(
                    id,
                    Incoming {
                        peer_hex: peer_hex.to_string(),
                        name: safe.clone(),
                        size,
                        part,
                        received: 0,
                    },
                );
            }
            emit("file_start", &format!("{safe}|{size}"), peer_hex);
        }
        Payload::FileChunk { id, seq: _, data } => {
            let entry = {
                let mut g = INCOMING_FILES.lock().unwrap();
                match g.as_mut().and_then(|m| m.get_mut(&id)) {
                    // Only the peer who offered this transfer may add to it.
                    Some(e) if e.peer_hex == peer_hex => {
                        // Never write more than was offered: without this a
                        // sender could keep streaming until the disk was full.
                        if e.received + data.len() as u64 > e.size {
                            log_line("file chunk refused: more data than the offer promised");
                            None
                        } else {
                            e.received += data.len() as u64;
                            Some((e.part.clone(), e.received, e.size))
                        }
                    }
                    Some(_) => {
                        log_line("file chunk refused: not the peer that offered it");
                        None
                    }
                    None => None,
                }
            };
            if let Some((part, received, total)) = entry {
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(&part) {
                    let _ = f.write_all(&data);
                }
                emit("file_progress", &format!("{received}|{total}"), peer_hex);
            }
        }
        Payload::GroupText { group_id, text } => {
            let Some(app) = APP.lock().unwrap().clone() else { return };
            let Some(sender) = unhex(peer_hex) else { return };
            let g = app.lock().unwrap();
            match g.store.get_group(&group_id) {
                // A message for a group we do not know, or from someone who is
                // not in its roster, is dropped: membership is the only thing
                // that makes a group message ours to store.
                Ok(Some(group)) if group.has_member(&sender) => {
                    let _ = g.store.insert_group_message(&NewGroupMessage {
                        group_id,
                        sender_pubkey: sender,
                        direction: Direction::Incoming,
                        sent_at: now_secs(),
                        body: text.as_bytes(),
                    });
                    drop(g);
                    emit("group_message", &format!("{}|{}", hex(&group_id), text), peer_hex);
                }
                _ => log_line("group message for an unknown group or from a non-member — dropped"),
            }
        }
        Payload::GroupInfo { group: incoming } => {
            let Some(app) = APP.lock().unwrap().clone() else { return };
            let Some(sender) = unhex(peer_hex) else { return };
            // Only someone inside the group may hand us its roster.
            if !incoming.has_member(&sender) {
                log_line("group roster from a non-member — ignored");
                return;
            }
            let g = app.lock().unwrap();
            let me = g.account.public();
            let known = g.store.get_group(&incoming.id).ok().flatten();
            let (stored, is_new) = match known {
                Some(mut mine) => {
                    if !mine.merge(&incoming) {
                        return; // same or older roster: nothing to do
                    }
                    (mine, false)
                }
                None => {
                    let mut fresh = incoming.clone();
                    // Our own arrival time, not the sender's claim.
                    fresh.created_at = now_secs();
                    (fresh, true)
                }
            };
            // Being dropped from the roster means we were removed: forget it.
            if !stored.has_member(&me) {
                let _ = g.store.delete_group(&stored.id);
                drop(g);
                emit("group_removed", &hex(&stored.id), peer_hex);
                return;
            }
            let _ = g.store.upsert_group(&stored);
            drop(g);
            remember_group_routes(&stored);
            emit(
                if is_new { "group_invite" } else { "group_info" },
                &format!("{}|{}", hex(&stored.id), stored.name),
                peer_hex,
            );
        }
        Payload::FileEnd { id } => {
            let entry = {
                let mut g = INCOMING_FILES.lock().unwrap();
                match g.as_mut().and_then(|m| m.get(&id)) {
                    Some(e) if e.peer_hex == peer_hex => {
                        g.as_mut().and_then(|m| m.remove(&id))
                    }
                    _ => None,
                }
            };
            if let Some(Incoming { name, part, .. }) = entry {
                let dir = part.parent().map(|p| p.to_path_buf()).unwrap_or_default();
                let mut final_path = dir.join(&name);
                let mut n = 1;
                while final_path.exists() {
                    final_path = dir.join(format!("{n}-{name}"));
                    n += 1;
                }
                // Seal it before it lands. Until now a received photo sat in
                // `files/` as a readable photo, next to a database that took
                // great care to encrypt the sentence describing it — anyone
                // with the disk had the content without the passphrase.
                let sealed = APP.lock().unwrap().clone().and_then(|app| {
                    let plain = std::fs::read(&part).ok()?;
                    let g = app.lock().unwrap();
                    g.store.encrypt_file(&final_path, &plain).ok()
                });
                if sealed.is_some() {
                    let _ = std::fs::remove_file(&part);
                } else {
                    // No account open (should not happen mid-transfer): keep
                    // the file rather than lose it, and say so in the log.
                    log_line("received file stored WITHOUT encryption: no account open");
                    let _ = std::fs::rename(&part, &final_path);
                }
                // Give the received file a row in the thread. Until now it was
                // an event and nothing else: the file survived a restart, the
                // conversation did not remember it had arrived.
                let stored = final_path.to_string_lossy().to_string();
                let size = std::fs::metadata(&final_path).map(|m| m.len()).unwrap_or(0);
                if let (Some(app), Some(pk)) = (APP.lock().unwrap().clone(), unhex(peer_hex)) {
                    let g = app.lock().unwrap();
                    let _ = g.store.insert_message(&NewMessage {
                        contact_pubkey: pk,
                        direction: Direction::Incoming,
                        sent_at: now_secs(),
                        body: format!("📎 {name}").as_bytes(),
                        file: Some(NewAttachment {
                            path: &stored,
                            name: &name,
                            size,
                        }),
                    });
                }
                emit("file_done", &format!("{stored}|{name}|{size}"), peer_hex);
            }
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Turn a name chosen by someone else into one that is safe to create inside
/// our own downloads folder.
///
/// The sender picks this string, so it is treated as hostile: separators and
/// control characters go, `..` cannot escape the folder, Windows' reserved
/// device names are pushed aside, and trailing dots and spaces — which Windows
/// silently strips, and which can therefore make two names collide — are cut.
fn safe_file_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if r#"\/:*?"<>|"#.contains(c) || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect();
    let cleaned = cleaned.trim().trim_end_matches(['.', ' ']).trim();
    // Keep it well inside every filesystem's limit, counting bytes not chars.
    let mut cleaned: String = cleaned.chars().take(120).collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        cleaned = "soubor".to_string();
    }
    const RESERVED: [&str; 22] = [
        "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7",
        "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    ];
    let stem = cleaned.split('.').next().unwrap_or("").to_ascii_lowercase();
    if RESERVED.contains(&stem.as_str()) {
        cleaned = format!("_{cleaned}");
    }
    cleaned
}

/// How a new account records the KDF settings it was created with.
fn kdf_line() -> String {
    format!(
        "argon2id {} {} {}",
        keystore::STORE_M_COST,
        keystore::STORE_T_COST,
        keystore::STORE_P_COST
    )
}

/// The settings an account's database was built with. Accounts made before this
/// file existed used the old, weaker defaults — and must keep using them, or
/// their key would come out different and nothing would decrypt.
fn read_kdf(dir: &Path) -> (u32, u32, u32) {
    let legacy = (
        keystore::LEGACY_M_COST,
        keystore::LEGACY_T_COST,
        keystore::LEGACY_P_COST,
    );
    let Ok(text) = std::fs::read_to_string(account_file(dir, "nullchat.kdf")) else { return legacy };
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.len() != 4 || parts[0] != "argon2id" {
        return legacy;
    }
    match (parts[1].parse(), parts[2].parse(), parts[3].parse()) {
        (Ok(m), Ok(t), Ok(p)) => (m, t, p),
        _ => legacy,
    }
}

/// Wall-clock seconds; only used for stamping what we store ourselves.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn unhex16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The sender picks the file name, so it is attacker-controlled input.
    #[test]
    fn a_hostile_file_name_cannot_escape_the_download_folder() {
        for evil in [
            "../../../../Windows/System32/evil.dll",
            r"..\..\autorun.inf",
            "/etc/passwd",
            "..",
            ".",
            "",
            "   ",
        ] {
            let safe = safe_file_name(evil);
            assert!(!safe.contains('/'), "{evil} kept a forward slash: {safe}");
            assert!(!safe.contains('\\'), "{evil} kept a backslash: {safe}");
            assert_ne!(safe, "..");
            assert_ne!(safe, ".");
            assert!(!safe.is_empty());
            // The decisive property: joining it onto the folder stays inside it.
            let base = std::path::Path::new("C:/nullchat/files");
            let joined = base.join(&safe);
            assert_eq!(joined.parent(), Some(base), "{evil} escaped to {joined:?}");
        }
    }

    #[test]
    fn windows_device_names_and_trailing_dots_are_defused() {
        // "CON" and friends are devices, not files, on Windows.
        assert_eq!(safe_file_name("CON"), "_CON");
        assert_eq!(safe_file_name("nul.txt"), "_nul.txt");
        // Windows silently strips these, so two names could collide.
        assert_eq!(safe_file_name("report.pdf..."), "report.pdf");
        assert_eq!(safe_file_name("spaced.txt  "), "spaced.txt");
        // Ordinary names are left alone, accents and all.
        assert_eq!(safe_file_name("Zpráva 2026.pdf"), "Zpráva 2026.pdf");
        // Control characters cannot sneak through either.
        assert_eq!(safe_file_name("a\u{7}b.txt"), "a_b.txt");
    }

    /// The log must be able to tell two peers apart without naming either.
    #[test]
    fn a_peer_tag_hides_the_identity_it_stands_for() {
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        assert_eq!(peer_tag(&a), peer_tag(&a), "stable within a run");
        assert_ne!(peer_tag(&a), peer_tag(&b), "different peers stay distinct");
        // Nothing of the identity itself survives into the label.
        assert!(!a.contains(&peer_tag(&a)));
        assert_eq!(peer_tag(&a).len(), 6);
    }
}
