// SPDX-License-Identifier: AGPL-3.0-or-later
//! The real flutter_rust_bridge API: bridges the Flutter UI to the Umbra core
//! (identity, user codes, invites, and the encrypted local store).
//!
//! Live peer-to-peer send/receive over the transport is a follow-up; this layer
//! already makes identity, codes, invites, contacts and message history *real*
//! and persisted (encrypted at rest).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::frb_generated::StreamSink;
use flutter_rust_bridge::frb;
use tokio::sync::mpsc;
use umbra_core::crypto::keystore;
use umbra_core::identity::{user_code, Keypair};
use umbra_core::invite::Invite;
use umbra_core::group::{Group, GroupMember};
use umbra_core::store::{
    Contact, ContactStatus, Direction, MessageState, NewGroupMessage, NewMessage, Store,
};
use umbra_transport::ctor::TorService;

use crate::accounts::{self, AccountEntry};
use crate::updater;

use umbra_core::envelope::{self, Payload};

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
/// The keep-alive loop is started once.
static KEEPALIVE: AtomicBool = AtomicBool::new(false);
/// The update loop is started once.
static UPDATER: AtomicBool = AtomicBool::new(false);
/// Tor's SOCKS port, so an update can be fetched on demand.
static SOCKS: Mutex<Option<u16>> = Mutex::new(None);
/// Where to append a plain-text diagnostic log (data dir / umbra-app.log).
static LOGPATH: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Append one line to the diagnostic log. Best effort: never fails the caller.
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

/// Deliver everything the database has waiting for `peer_hex`.
///
/// The queue lives in the encrypted store, not in memory: "it will be delivered
/// when they come back" has to survive closing the app, otherwise it is a lie.
async fn flush_pending(peer_hex: &str) {
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
            log_line(&format!("dial start peer={} onion={onion}", &peer_hex[..12.min(peer_hex.len())]));
            match svc.connect(onion, pk).await {
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
        updater::run_loop(socks_port, dir, |kind, data| emit(kind, data, "")).await;
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
    umbra_transport::ctor::set_native_dir(PathBuf::from(path));
}

/// Push an event to the UI (no-op before the network is started).
fn emit(kind: &str, data: &str, peer_hex: &str) {
    log_line(&format!("{kind} peer={} {data}", &peer_hex.chars().take(12).collect::<String>()));
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
}

/// A stored message, flattened for the UI.
pub struct MessageView {
    pub outgoing: bool,
    pub sent_at: u64,
    pub body: String,
    /// 0 = still waiting for the peer, 1 = handed over, 2 = confirmed by them.
    pub state: u8,
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
        PathBuf::from(dir).join("umbra.db").exists()
    }

    /// Create a brand-new identity + encrypted store at `dir`, protected by
    /// `passphrase`.
    #[frb(sync)]
    pub fn create(dir: String, username: String, passphrase: String) -> Result<UmbraApp, String> {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt).map_err(|_| "RNG failed".to_string())?;
        std::fs::write(dir.join("umbra.salt"), salt).map_err(|e| e.to_string())?;

        let key = keystore::derive_store_key(passphrase.as_bytes(), &salt).map_err(|e| e.to_string())?;
        let store = Store::open(&dir.join("umbra.db"), &key).map_err(|e| e.to_string())?;

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
        if !dir.join("umbra.db").exists() || !dir.join("umbra.salt").exists() {
            return Err("Na tomto počítači není žádná identita.".to_string());
        }
        let salt = std::fs::read(dir.join("umbra.salt")).map_err(|e| e.to_string())?;
        let key = keystore::derive_store_key(passphrase.as_bytes(), &salt).map_err(|e| e.to_string())?;
        let store = Store::open(&dir.join("umbra.db"), &key).map_err(|e| e.to_string())?;

        // A wrong passphrase derives a wrong key, so the stored secret fails to
        // decrypt. Say that plainly instead of leaking a storage-level error.
        let seed = store
            .get_secret("identity_seed")
            .map_err(|_| "Špatná přístupová fráze.".to_string())?
            .ok_or_else(|| "V databázi není žádná identita.".to_string())?;
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
        let _ = store.backfill_missing_contacts(now_secs());

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
            accounts::protect_passphrase(&passphrase).unwrap_or_default()
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
            if let Some(secret) = accounts::protect_passphrase(&passphrase) {
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
        let passphrase = accounts::recover_passphrase(&entry.secret)
            .ok_or_else(|| "saved passphrase could not be read".to_string())?;
        UmbraApp::open_account(root, id, passphrase, false)
    }

    /// Turn auto sign-in on (needs the passphrase) or off for this account.
    #[frb(sync)]
    pub fn set_autologin(&self, passphrase: String, enabled: bool) -> Result<(), String> {
        let (root, id, name) = {
            let g = self.inner.lock().unwrap();
            (g.root.clone(), g.account_id.clone(), g.username.clone())
        };
        if id.is_empty() {
            return Err("account context missing".to_string());
        }
        let mut entry = accounts::load(&root)
            .into_iter()
            .find(|a| a.id == id)
            .unwrap_or(AccountEntry { id: id.clone(), name, autologin: false, secret: String::new() });
        if enabled {
            entry.secret = accounts::protect_passphrase(&passphrase)
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
        Invite::new(g.account.public(), g.username.clone(), onion).encode()
    }

    /// Our onion address, or empty while the network is still starting.
    #[frb(sync)]
    pub fn my_onion(&self) -> String {
        ONION.lock().unwrap().clone().unwrap_or_default()
    }

    /// Start the Tor node: bootstrap (through bundled obfs4 bridges when
    /// present), host our onion service, and accept incoming peers. Returns
    /// immediately — all progress arrives as [`NetEvent`]s on the stream.
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
                    c.insert(hex(&contact.identity_pubkey), contact.onion_addr);
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

        *LOGPATH.lock().unwrap() = Some(dir.join("umbra-app.log"));
        *FILES_DIR.lock().unwrap() = Some(dir.join("files"));
        let _ = std::fs::create_dir_all(dir.join("files"));
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
                    let socks_port = umbra_transport::ctor::socks_port_of(&svc);
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
                match svc.connect(onion.clone(), pk).await {
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

    /// Send a file to a connected contact: read it, split it into chunks and
    /// push each one through the encrypted session. Progress arrives as events.
    #[frb(sync)]
    pub fn send_file(&self, contact_hex: String, path: String) {
        rt().spawn(async move {
            let svc = SERVICE.lock().unwrap().clone();
            let Some(svc) = svc else {
                emit("error", "síť ještě neběží", &contact_hex);
                return;
            };
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

            let mut id = [0u8; 16];
            if getrandom::getrandom(&mut id).is_err() {
                emit("error", "RNG selhal", &contact_hex);
                return;
            }
            let total = data.len() as u64;
            if svc
                .send_bytes(&contact_hex, envelope::encode_file_offer(&id, &name, total))
                .await
                .is_err()
            {
                emit("error", "soubor nelze odeslat: nejsi spojen", &contact_hex);
                return;
            }
            emit("file_send_start", &format!("{name}|{total}"), &contact_hex);

            for (seq, chunk) in data.chunks(envelope::CHUNK).enumerate() {
                if svc
                    .send_bytes(&contact_hex, envelope::encode_file_chunk(&id, seq as u32, chunk))
                    .await
                    .is_err()
                {
                    emit("error", "přenos souboru se přerušil", &contact_hex);
                    return;
                }
                let sent = ((seq + 1) * envelope::CHUNK).min(data.len()) as u64;
                emit("file_send_progress", &format!("{sent}|{total}"), &contact_hex);
            }
            let _ = svc.send_bytes(&contact_hex, envelope::encode_file_end(&id)).await;
            emit("file_sent", &name, &contact_hex);
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
            })
            .map_err(|e| e.to_string())?;
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
            })
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
                outgoing: matches!(m.direction, Direction::Outgoing),
                sent_at: m.sent_at,
                body: String::from_utf8_lossy(&m.body).to_string(),
                state: match m.state {
                    MessageState::Waiting => 0,
                    MessageState::Sent => 1,
                    MessageState::Delivered => 2,
                },
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
/// Partially received files: id → (name, size, handle, received bytes).
static INCOMING_FILES: Mutex<Option<HashMap<[u8; 16], (String, u64, PathBuf, u64)>>> =
    Mutex::new(None);

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
    let Some(app) = APP.lock().unwrap().clone() else { return };
    let Some(pk) = unhex(peer_hex) else { return };
    let mut changed = false;
    {
        let g = app.lock().unwrap();
        let existing = g.store.get_contact(&pk).ok().flatten();
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
            remember_peer(peer_hex, Some(&name), Some(&onion));
        }
        Payload::Profile { name, picture } => {
            // Cache the picture next to the app data; the UI reads it by path.
            if !picture.is_empty() {
                if let Some(dir) = FILES_DIR.lock().unwrap().clone() {
                    let p = dir.join(format!("avatar-{peer_hex}.img"));
                    let _ = std::fs::write(&p, &picture);
                }
            }
            remember_peer(peer_hex, Some(&name), None);
            emit("profile", &name, peer_hex);
        }
        Payload::FileOffer { id, name, size } => {
            let Some(dir) = FILES_DIR.lock().unwrap().clone() else { return };
            let _ = std::fs::create_dir_all(&dir);
            let safe: String = name
                .chars()
                .map(|c| if r#"\/:*?"<>|"#.contains(c) { '_' } else { c })
                .collect();
            let part = dir.join(format!("{}.part", hex(&id)));
            let _ = std::fs::write(&part, b"");
            INCOMING_FILES
                .lock()
                .unwrap()
                .get_or_insert_with(HashMap::new)
                .insert(id, (safe.clone(), size, part, 0));
            emit("file_start", &format!("{safe}|{size}"), peer_hex);
        }
        Payload::FileChunk { id, seq: _, data } => {
            let entry = {
                let mut g = INCOMING_FILES.lock().unwrap();
                g.as_mut().and_then(|m| m.get_mut(&id).map(|e| {
                    e.3 += data.len() as u64;
                    (e.2.clone(), e.3, e.1)
                }))
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
            let entry = { INCOMING_FILES.lock().unwrap().as_mut().and_then(|m| m.remove(&id)) };
            if let Some((name, _size, part, _got)) = entry {
                let dir = part.parent().map(|p| p.to_path_buf()).unwrap_or_default();
                let mut final_path = dir.join(&name);
                let mut n = 1;
                while final_path.exists() {
                    final_path = dir.join(format!("{n}-{name}"));
                    n += 1;
                }
                let _ = std::fs::rename(&part, &final_path);
                emit("file_done", &final_path.to_string_lossy(), peer_hex);
            }
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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
