// SPDX-License-Identifier: AGPL-3.0-or-later
//! Local encrypted persistence.
//!
//! # Design (and its documented tradeoff)
//!
//! Ideally the *whole* database file is opaque at rest (SQLCipher). SQLCipher's
//! only build path here needs a vendored OpenSSL toolchain (Perl + NASM) that
//! isn't available, so instead we use a plain bundled SQLite and encrypt the
//! **values** ourselves with XChaCha20-Poly1305 under a 32-byte data key.
//!
//! Message *bodies*, contact names, onion addresses and all secrets are
//! ciphertext at rest.
//!
//! # Routing columns: blind index
//!
//! Columns SQL has to match and sort on cannot be sealed — a query cannot look
//! inside ciphertext. They used to hold the raw values, which meant a stolen
//! file handed over the whole social graph without the passphrase: every
//! contact's identity key, who is in which group, who wrote what.
//!
//! They now hold a **blind index**: `HMAC-SHA256(key derived from the data key,
//! value)`. Lookups still work, because a lookup is always *by a value we
//! already hold* — we compute the same index and match on it. The real value
//! lives once, sealed, in [`blind_index`](SCHEMA), and is only recovered when
//! something needs to be shown.
//!
//! What this does and does not buy, stated plainly:
//!
//! * Without the passphrase, the identity keys are unrecoverable — the index is
//!   a MAC, not an encoding, and the key is per-account. Two seized devices
//!   cannot be shown to share a contact or a group either, because their index
//!   keys differ.
//! * Inside one file, rows for the same person still carry the same index, so a
//!   thief learns *how many* distinct parties there are and how often each was
//!   active. Timestamps, direction and delivery state stay plaintext because
//!   ordering needs them. Whole-file encryption (SQLCipher) is still the better
//!   answer where its build toolchain is available.
//!
//! The data key itself is expected to be a random key sealed under the user
//! passphrase via [`crate::crypto::keystore`]; this module just consumes the
//! raw key.

use crate::error::StoreError;
use crate::group::{Group, GroupMember};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use sha2::Sha256;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const NONCE_LEN: usize = 24;

/// Marks a database whose routing columns have been converted to blind indexes.
/// Both a raw key and its index are 32 bytes, so nothing in the data itself
/// tells the two apart — this note is what makes the migration run exactly once.
const BLIND_INDEX_MARK: &str = "schema.blind_index.v1";

/// Marks a database whose secret *names* have been indexed too.
///
/// Separate from the mark above on purpose. Sharing it meant every database
/// that had already converted its routing columns skipped the name conversion
/// permanently — and then failed to find `identity_seed`, which the app reports
/// as a wrong passphrase.
const SECRET_NAMES_MARK: &str = "schema.secret_names.v1";

/// Marks a profile whose accepted contacts have been put in the address book.
///
/// Unlike the two above this is *per profile*, not per file, so it goes through
/// the ordinary sealed-and-indexed secrets. It also has to be a mark rather
/// than a repair that runs every time: dropping someone from the address book
/// is a decision, and a repair with no memory would undo it at the next
/// sign-in.
const SAVED_CONTACTS_MARK: &str = "repair.saved_contacts.v1";

/// Domain separator, so the index key cannot coincide with any other use of
/// the data key.
const INDEX_KEY_INFO: &[u8] = b"nullchat blind index v1";

const SCHEMA: &str = "
PRAGMA secure_delete = ON;
CREATE TABLE IF NOT EXISTS secrets (
    name  TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
-- Resolves a blind index back to the value it stands for. This is the only
-- place a contact key or a group id exists in readable form, and it is sealed.
CREATE TABLE IF NOT EXISTS blind_index (
    bi     BLOB PRIMARY KEY,            -- HMAC-SHA256(index key, value)
    sealed BLOB NOT NULL                -- sealed: the value itself
);
CREATE TABLE IF NOT EXISTS contacts (
    identity_pubkey BLOB PRIMARY KEY,   -- blind index of the identity key
    display_name    BLOB NOT NULL,      -- sealed
    onion_addr      BLOB NOT NULL,      -- sealed
    added_at        INTEGER NOT NULL,
    status          INTEGER NOT NULL DEFAULT 1, -- 0 waiting, 1 accepted, 2 blocked
    saved           INTEGER NOT NULL DEFAULT 0, -- kept in the address book
    verified        INTEGER NOT NULL DEFAULT 0, -- safety number compared in person
    pq_fingerprint  BLOB                        -- sealed; NULL for pre-1.9 contacts
);
CREATE TABLE IF NOT EXISTS messages (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    contact_pubkey BLOB NOT NULL,       -- blind index (query/order)
    direction      INTEGER NOT NULL,    -- 0 = incoming, 1 = outgoing
    sent_at        INTEGER NOT NULL,    -- plaintext (ordering)
    body           BLOB NOT NULL,       -- sealed
    state          INTEGER NOT NULL DEFAULT 0  -- 0 waiting, 1 sent, 2 delivered
);
-- Messages that have not reached the peer yet. Without this table a queued
-- message lived only in memory: closing the app threw it away, which is the
-- opposite of the promise that it goes out once they are back.
CREATE TABLE IF NOT EXISTS outbox (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_pubkey BLOB NOT NULL,          -- blind index (routing)
    message_id INTEGER NOT NULL,        -- row in messages / group_messages
    group_id   BLOB,                    -- blind index of a group id, else NULL
    payload    BLOB NOT NULL,           -- sealed: the exact frame to send
    body       BLOB NOT NULL,           -- sealed: the text, for matching receipts
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_outbox_peer ON outbox(peer_pubkey, id);
CREATE INDEX IF NOT EXISTS idx_messages_contact
    ON messages(contact_pubkey, sent_at);
CREATE TABLE IF NOT EXISTS groups (
    group_id   BLOB PRIMARY KEY,        -- blind index of the group id
    name       BLOB NOT NULL,           -- sealed
    version    INTEGER NOT NULL,        -- roster version (plaintext, ordering)
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS group_members (
    group_id      BLOB NOT NULL,        -- blind index
    member_pubkey BLOB NOT NULL,        -- blind index (who is in the group)
    display_name  BLOB NOT NULL,        -- sealed
    onion_addr    BLOB NOT NULL,        -- sealed
    PRIMARY KEY (group_id, member_pubkey)
);
CREATE TABLE IF NOT EXISTS group_messages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id      BLOB NOT NULL,        -- blind index (query/order)
    sender_pubkey BLOB NOT NULL,        -- blind index (who wrote it)
    direction     INTEGER NOT NULL,     -- 0 = incoming, 1 = outgoing
    sent_at       INTEGER NOT NULL,     -- plaintext (ordering)
    body          BLOB NOT NULL         -- sealed
);
CREATE INDEX IF NOT EXISTS idx_group_messages
    ON group_messages(group_id, sent_at);
-- Who put which emoji on what. Keyed by the message *reference* rather than a
-- row id, because a reaction arrives from the other side, where our row ids
-- mean nothing (see `envelope::message_ref`). One emoji per person per message:
-- reacting again replaces, which is what the primary key says.
CREATE TABLE IF NOT EXISTS reactions (
    msg_ref BLOB NOT NULL,              -- blind index of the message reference
    who     BLOB NOT NULL,              -- blind index of the reactor's identity
    emoji   BLOB NOT NULL,              -- sealed
    at      INTEGER NOT NULL,
    PRIMARY KEY (msg_ref, who)
);
";

/// Secret holding [`ProfileKind`] for whichever passphrase opened the store.
const PROFILE_KIND: &str = "profile.kind";

/// What a passphrase opens.
///
/// One database can answer to several passphrases. Each derives its own key,
/// each sees only the rows sealed under that key, and **nothing in the file
/// says how many there are** — a row nobody can read looks the same whether it
/// belongs to another profile, was overwritten, or never meant anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileKind {
    /// The real account.
    Normal,
    /// A separate, self-contained history to show instead of the real one.
    Decoy,
    /// Destroys everything it cannot read, then behaves like a fresh account.
    Wipe,
}

impl ProfileKind {
    fn as_bytes(self) -> &'static [u8] {
        match self {
            ProfileKind::Normal => b"normal",
            ProfileKind::Decoy => b"decoy",
            ProfileKind::Wipe => b"wipe",
        }
    }
    fn from_bytes(v: &[u8]) -> Self {
        match v {
            b"decoy" => ProfileKind::Decoy,
            b"wipe" => ProfileKind::Wipe,
            _ => ProfileKind::Normal,
        }
    }
}

/// Direction of a stored message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Received from the peer.
    Incoming,
    /// Sent by us.
    Outgoing,
}

impl Direction {
    fn to_i64(self) -> i64 {
        match self {
            Direction::Incoming => 0,
            Direction::Outgoing => 1,
        }
    }
    fn from_i64(v: i64) -> Result<Self, StoreError> {
        match v {
            0 => Ok(Direction::Incoming),
            1 => Ok(Direction::Outgoing),
            _ => Err(StoreError::Corrupt),
        }
    }
}

/// Where a contact stands with us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactStatus {
    /// They wrote to us and we have not decided yet: their messages are kept
    /// aside instead of landing in the chat list.
    Waiting,
    /// A normal conversation.
    Accepted,
    /// Everything from them is dropped on arrival.
    Blocked,
}

impl ContactStatus {
    fn to_i64(self) -> i64 {
        match self {
            ContactStatus::Waiting => 0,
            ContactStatus::Accepted => 1,
            ContactStatus::Blocked => 2,
        }
    }
    fn from_i64(v: i64) -> Self {
        match v {
            0 => ContactStatus::Waiting,
            2 => ContactStatus::Blocked,
            _ => ContactStatus::Accepted,
        }
    }
}

/// A contact record (decrypted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    /// The contact's 32-byte Ed25519 identity public key.
    pub identity_pubkey: [u8; 32],
    /// Human-readable display name.
    pub display_name: String,
    /// The contact's Tor onion service address.
    pub onion_addr: String,
    /// When added (unix seconds).
    pub added_at: u64,
    /// Accepted, waiting for a decision, or blocked.
    pub status: ContactStatus,
    /// Kept in the address book, so they can be picked later (e.g. added to a
    /// group) without digging through old conversations.
    pub saved: bool,
    /// The user compared the safety number with this person out of band and
    /// said it matched. Only ever set by an explicit human decision.
    pub verified: bool,
    /// Commitment to their post-quantum identity key, from their invite.
    /// `None` for contacts added before those existed — such a conversation is
    /// protected by Ed25519 alone, and the app says so rather than implying
    /// protection it does not have.
    pub pq_fingerprint: Option<[u8; 32]>,
}

/// How far an outgoing message got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageState {
    /// Still in the outbox: the peer has not been reachable yet.
    Waiting,
    /// Handed to the peer's live session.
    Sent,
    /// The peer's app confirmed it arrived.
    Delivered,
}

impl MessageState {
    fn to_i64(self) -> i64 {
        match self {
            MessageState::Waiting => 0,
            MessageState::Sent => 1,
            MessageState::Delivered => 2,
        }
    }
    fn from_i64(v: i64) -> Self {
        match v {
            1 => MessageState::Sent,
            2 => MessageState::Delivered,
            _ => MessageState::Waiting,
        }
    }
}

/// One queued message waiting for its peer to come online.
#[derive(Debug, Clone)]
pub struct OutboxItem {
    /// Row id in `outbox`.
    pub id: i64,
    /// Who it is for.
    pub peer_pubkey: [u8; 32],
    /// The row it belongs to in `messages` (or `group_messages`).
    pub message_id: i64,
    /// Set when this is a group message.
    pub group_id: Option<[u8; 16]>,
    /// The exact frame to put on the wire.
    pub payload: Vec<u8>,
    /// The text, so a delivery receipt can be matched to it.
    pub body: Vec<u8>,
    /// When it was queued (unix seconds).
    pub created_at: u64,
}

/// A message to insert.
#[derive(Debug, Clone)]
pub struct NewMessage<'a> {
    /// The other party's identity public key.
    pub contact_pubkey: [u8; 32],
    /// Direction.
    pub direction: Direction,
    /// Timestamp (unix seconds).
    pub sent_at: u64,
    /// Plaintext body; stored encrypted.
    pub body: &'a [u8],
    /// The attachment this message carries, if any.
    pub file: Option<NewAttachment<'a>>,
    /// How the other side refers to this message; see
    /// [`crate::envelope::message_ref`]. Computed by the caller, which is the
    /// only layer that knows whose message it is.
    pub msg_ref: Option<[u8; 16]>,
    /// The message this one answers, if it answers one.
    pub reply_to: Option<[u8; 16]>,
}

/// The file part of a message.
///
/// Kept with the message so a photo or GIF is still a photo after a restart.
/// Path and name are sealed like a body: together they say what was exchanged
/// and with whom.
#[derive(Debug, Clone, Copy)]
pub struct NewAttachment<'a> {
    /// Where the sealed file lives on disk.
    pub path: &'a str,
    /// The name to show.
    pub name: &'a str,
    /// Size in bytes.
    pub size: u64,
}

/// A group message to insert.
#[derive(Debug, Clone)]
pub struct NewGroupMessage<'a> {
    /// Which group it belongs to.
    pub group_id: [u8; 16],
    /// Who wrote it (our own key for outgoing messages).
    pub sender_pubkey: [u8; 32],
    /// Direction.
    pub direction: Direction,
    /// Timestamp (unix seconds).
    pub sent_at: u64,
    /// Plaintext body; stored encrypted.
    pub body: &'a [u8],
    /// How the other members refer to this message.
    pub msg_ref: Option<[u8; 16]>,
    /// The message this one answers, if it answers one.
    pub reply_to: Option<[u8; 16]>,
}

/// A message matched by a search or a contact lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    /// Row id in its own table.
    pub id: i64,
    /// The other party (or, in a group, the sender).
    pub peer_pubkey: [u8; 32],
    /// Set when the message came from a group.
    pub group_id: Option<[u8; 16]>,
    /// True when we wrote it.
    pub outgoing: bool,
    /// Timestamp (unix seconds).
    pub sent_at: u64,
    /// Decrypted text.
    pub body: String,
}

/// One attachment, wherever in the history it sits.
///
/// Carries the message it belongs to, so the overview can hand back to the
/// conversation rather than being a dead end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaItem {
    /// The message row this attachment came in on.
    pub message_id: i64,
    /// The other party in that conversation.
    pub peer_pubkey: [u8; 32],
    /// True when we sent it.
    pub outgoing: bool,
    /// Timestamp (unix seconds).
    pub sent_at: u64,
    /// Where the sealed copy lives.
    pub file_path: String,
    /// The name it was sent under.
    pub file_name: String,
    /// Size in bytes.
    pub file_size: u64,
}

/// A stored group message (decrypted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMessage {
    /// Row id.
    pub id: i64,
    /// Which group it belongs to.
    pub group_id: [u8; 16],
    /// Who wrote it.
    pub sender_pubkey: [u8; 32],
    /// Direction.
    pub direction: Direction,
    /// Timestamp (unix seconds).
    pub sent_at: u64,
    /// Decrypted body.
    pub body: Vec<u8>,
}

/// A stored message (decrypted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Row id.
    pub id: i64,
    /// The other party's identity public key.
    pub contact_pubkey: [u8; 32],
    /// Direction.
    pub direction: Direction,
    /// Timestamp (unix seconds).
    pub sent_at: u64,
    /// Decrypted body.
    pub body: Vec<u8>,
    /// Delivery progress (outgoing messages only).
    pub state: MessageState,
    /// Where the sealed attachment lives, when the message carries one.
    pub file_path: Option<String>,
    /// The attachment's name.
    pub file_name: Option<String>,
    /// The attachment's size in bytes.
    pub file_size: Option<u64>,
    /// The message this one answers, if it answers one. What it refers to may
    /// not be in our history at all — a reply to something from before we had
    /// it, or from a thread that was cleared.
    pub reply_to: Option<[u8; 16]>,
}

/// How long a sealed empty value is: a 24-byte nonce and a 16-byte tag with no
/// ciphertext between them. Anything longer carries at least one byte.
const SEALED_EMPTY_LEN: usize = 24 + 16;

/// A `contacts` row exactly as SQLite hands it back: display name, onion,
/// added_at, status, saved, verified, PQ fingerprint — all still sealed or
/// blind-indexed. Named only so the query below does not carry a seven-element
/// tuple in its signature.
type ContactRow = (Vec<u8>, Vec<u8>, i64, i64, i64, i64, Option<Vec<u8>>);

/// A `group_messages` row as it comes out of SQLite: id, sender, direction,
/// timestamp, sealed body.
type GroupMessageRow = (i64, Vec<u8>, i64, i64, Vec<u8>);

/// A `messages` row as SQLite hands it back: id, contact, direction, timestamp,
/// sealed body, state, sealed path/name, size, and the reply index.
type MessageRow = (
    i64,
    Vec<u8>,
    i64,
    i64,
    Vec<u8>,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
);

/// One step of a re-key: the index a value sits on now, the index it moves to,
/// and the value itself.
type IndexMove = (Vec<u8>, Vec<u8>, Zeroizing<Vec<u8>>);

/// A stored secret exactly as it sits on disk: its name and its value, both
/// still opaque.
pub type StoredSecret = (Vec<u8>, Vec<u8>);

/// The encrypted local store.
pub struct Store {
    conn: Connection,
    key: Zeroizing<[u8; 32]>,
    /// Derived from `key`; keys the blind index over the routing columns.
    index_key: Zeroizing<[u8; 32]>,
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Db(e.to_string())
    }
}

impl Store {
    /// Open (creating if needed) an encrypted store at `path` with `data_key`.
    pub fn open(path: &Path, data_key: &[u8; 32]) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        Self::init(conn, data_key)
    }

    /// An in-memory store (for tests / ephemeral use).
    pub fn open_in_memory(data_key: &[u8; 32]) -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn, data_key)
    }

    fn init(conn: Connection, data_key: &[u8; 32]) -> Result<Self, StoreError> {
        conn.execute_batch(SCHEMA)?;
        Self::migrate(&conn)?;
        let store = Self {
            conn,
            key: Zeroizing::new(*data_key),
            index_key: Zeroizing::new(derive_index_key(data_key)),
        };
        // Needs the key, so it cannot live in `migrate` with the schema changes.
        store.migrate_blind_index()?;
        // Deliberately a *separate* step with its own marker. Folding it into
        // the one above meant databases that had already converted their
        // routing columns — everything written by 1.7.x — skipped it forever,
        // and then could not find their own identity seed.
        store.migrate_secret_names()?;
        Ok(store)
    }

    // --- blind index over the routing columns ---

    /// The index a value is stored under. Deterministic, so lookups match.
    fn bi(&self, value: &[u8]) -> Vec<u8> {
        bi_with(&self.index_key, value)
    }

    /// The index, *and* a note of what it stands for so it can be read back.
    ///
    /// Called on every write path. Writing the mapping is idempotent: the same
    /// value always lands on the same index.
    fn indexed(&self, value: &[u8]) -> Result<Vec<u8>, StoreError> {
        let bi = self.bi(value);
        let exists: Option<i64> = self
            .conn
            .query_row("SELECT 1 FROM blind_index WHERE bi = ?1", params![bi], |r| r.get(0))
            .optional()?;
        if exists.is_none() {
            let sealed = self.seal(value)?;
            self.conn.execute(
                "INSERT INTO blind_index(bi, sealed) VALUES(?1, ?2)
                 ON CONFLICT(bi) DO NOTHING",
                params![bi, sealed],
            )?;
        }
        Ok(bi)
    }

    /// Recover what an index stands for.
    fn value_of(&self, bi: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let blob: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT sealed FROM blind_index WHERE bi = ?1", params![bi], |r| r.get(0))
            .optional()?;
        // A routing column pointing at nothing means the file was edited or
        // truncated outside NullChat; refusing to guess is the only safe answer.
        self.unseal(&blob.ok_or(StoreError::Corrupt)?)
    }

    fn key32_of(&self, bi: &[u8]) -> Result<[u8; 32], StoreError> {
        to_key32(&self.value_of(bi)?)
    }

    fn id16_of(&self, bi: &[u8]) -> Result<[u8; 16], StoreError> {
        self.value_of(bi)?.as_slice().try_into().map_err(|_| StoreError::Corrupt)
    }

    /// The same, but "I cannot read this" answers `None` instead of failing.
    ///
    /// One file can hold rows written under more than one passphrase — that is
    /// what makes a second, separate history possible without the file showing
    /// that it has one. A row this key cannot open is not damage and not an
    /// error: it is simply not ours, and listing must walk straight past it.
    fn try_key32_of(&self, bi: &[u8]) -> Option<[u8; 32]> {
        self.value_of(bi).ok().and_then(|v| to_key32(&v).ok())
    }

    fn try_id16_of(&self, bi: &[u8]) -> Option<[u8; 16]> {
        self.value_of(bi).ok().and_then(|v| v.as_slice().try_into().ok())
    }

    /// Open a sealed 32-byte commitment, or `None` if there is none (or it
    /// belongs to another passphrase).
    fn unseal_fingerprint(&self, blob: Option<&[u8]>) -> Option<[u8; 32]> {
        let bytes = self.unseal(blob?).ok()?;
        bytes.as_slice().try_into().ok()
    }

    fn try_decrypt_string(&self, blob: &[u8]) -> Option<String> {
        let bytes = self.unseal(blob).ok()?;
        String::from_utf8(bytes.to_vec()).ok()
    }

    /// Convert a database written before the blind index existed.
    ///
    /// Runs once, inside a transaction: either every routing column is an index
    /// afterwards or the file is untouched. Nothing is lost — the raw values
    /// move into `blind_index`, sealed.
    fn migrate_blind_index(&self) -> Result<(), StoreError> {
        // Checked *without* decrypting: opening with the wrong key must fail the
        // way it always did — when something is read — not here.
        let marked: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM secrets WHERE name = ?1",
                params![BLIND_INDEX_MARK],
                |r| r.get(0),
            )
            .optional()?;
        if marked.is_some() {
            return Ok(());
        }
        // Converting with the wrong key would compute indexes nobody can ever
        // match again — the data would still be there and permanently
        // unreachable. So before touching anything, prove the key is right.
        if !self.key_opens_existing_data()? {
            return Err(StoreError::Corrupt);
        }
        // A copy of the file as it was, kept beside it. The conversion is a
        // transaction and should never leave a half-changed database — but this
        // rewrites every routing column in someone's whole history, and a
        // one-off backup is a cheap answer to "what if I am wrong".
        self.backup_before_conversion();
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let converted = (|| -> Result<(), StoreError> {
            for (table, column, len) in [
                ("contacts", "identity_pubkey", 32usize),
                ("messages", "contact_pubkey", 32),
                ("outbox", "peer_pubkey", 32),
                ("outbox", "group_id", 16),
                ("groups", "group_id", 16),
                ("group_members", "group_id", 16),
                ("group_members", "member_pubkey", 32),
                ("group_messages", "group_id", 16),
                ("group_messages", "sender_pubkey", 32),
            ] {
                self.reindex_column(table, column, len)?;
            }
            self.reindex_secret_names()?;
            Ok(())
        })();
        match converted {
            Ok(()) => {
                self.conn.execute_batch("COMMIT")?;
                // Written under its plain name on purpose — it is a fact about
                // the *file*, not about any one passphrase, and it must be
                // findable without deriving a key. It says nothing about how
                // many passphrases the file answers to.
                self.conn.execute(
                    "INSERT INTO secrets(name, value) VALUES(?1, ?2)
                     ON CONFLICT(name) DO UPDATE SET value = excluded.value",
                    params![BLIND_INDEX_MARK, self.seal(b"1")?],
                )?;
                Ok(())
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// Copy the database next to itself before converting it.
    ///
    /// Best effort on purpose: an in-memory store has no path, and a full disk
    /// is not a reason to refuse an upgrade that is transactional anyway. The
    /// copy keeps the same protection as the original — it *is* the original,
    /// with its sealed columns.
    fn backup_before_conversion(&self) {
        let Some(path) = self.conn.path().map(std::path::PathBuf::from) else { return };
        if !path.exists() {
            return; // in-memory
        }
        let backup = path.with_extension("db.pre-blind-index.bak");
        if backup.exists() {
            return; // a previous attempt already made one; do not overwrite it
        }
        let _ = std::fs::copy(&path, &backup);
    }

    /// Re-encrypt everything this key opens under `new_key`, and record the way
    /// back in as the secret `wrap_name` -> `wrap_value`.
    ///
    /// This is what lets the cost of guessing a passphrase rise on a database
    /// that already exists. The old scheme derived the data key from the
    /// passphrase, so raising the Argon2id parameters changed the key and left
    /// every row unreadable; the only accounts that could benefit were ones
    /// created afterwards. With the data key random and wrapped, the parameters
    /// are free to move.
    ///
    /// **Rows this key cannot open are left byte-identical.** One file answers
    /// to several passphrases, and a profile has no business rewriting — or
    /// being able to notice — another one's rows. Each converts itself, the
    /// first time it signs in.
    ///
    /// One transaction, over a file copied beside itself first, and a check at
    /// the end that nothing we could read before is still sealed under the old
    /// key. So the outcomes are "converted" or "exactly as it was".
    ///
    /// # Errors
    /// Any storage or crypto failure, in which case nothing changed.
    pub fn rekey(
        &mut self,
        new_key: &[u8; 32],
        wrap_name: &[u8],
        wrap_value: &[u8],
        files_dir: Option<&Path>,
    ) -> Result<(), StoreError> {
        let new_index_key = derive_index_key(new_key);
        // Attachments are sealed with this same key, on disk, outside anything
        // SQLite can roll back. They are prepared first and put in place last,
        // so a failure anywhere in between leaves the originals alone.
        if let Some(dir) = files_dir {
            self.reseal_files_to_temp(dir, new_key)?;
        }
        let backup = self.backup_before_rekey();
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let done = (|| -> Result<(), StoreError> {
            // Only values this key opens. Everything below is driven off this
            // list, so another passphrase's rows are never considered again.
            let mut mapping: Vec<IndexMove> = Vec::new();
            {
                let mut stmt = self.conn.prepare("SELECT bi, sealed FROM blind_index")?;
                let rows = stmt
                    .query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
                for row in rows {
                    let (old_bi, sealed) = row?;
                    let Ok(value) = self.unseal(&sealed) else { continue };
                    let new_bi = bi_with(&new_index_key, &value);
                    mapping.push((old_bi, new_bi, value));
                }
            }

            // Move the routing columns first. They are matched on, never read,
            // so this is a rename from one index to another.
            for (old_bi, new_bi, _) in &mapping {
                for (table, column) in INDEX_COLUMNS {
                    self.conn.execute(
                        &format!("UPDATE {table} SET {column} = ?2 WHERE {column} = ?1"),
                        params![old_bi, new_bi],
                    )?;
                }
            }

            // Then the table that says what an index stands for.
            for (old_bi, new_bi, value) in &mapping {
                self.conn
                    .execute("DELETE FROM blind_index WHERE bi = ?1", params![old_bi])?;
                self.conn.execute(
                    "INSERT INTO blind_index(bi, sealed) VALUES(?1, ?2)
                     ON CONFLICT(bi) DO UPDATE SET sealed = excluded.sealed",
                    params![new_bi, seal_with(new_key, value)?],
                )?;
            }

            for (table, column) in SEALED_COLUMNS {
                self.reseal_column(table, column, new_key)?;
            }

            // A column left out of SEALED_COLUMNS would still open under the old
            // key and never under the new one — data silently lost at the next
            // sign-in. Nothing readable may survive this point.
            for (table, column) in SEALED_COLUMNS {
                if self.column_still_opens(table, column)? {
                    return Err(StoreError::Corrupt);
                }
            }

            // Last, so the re-sealing pass above never sees it: this one is
            // sealed under the passphrase, not under the data key.
            self.conn.execute(
                "INSERT INTO secrets(name, value) VALUES(?1, ?2)
                 ON CONFLICT(name) DO UPDATE SET value = excluded.value",
                params![wrap_name, wrap_value],
            )?;
            Ok(())
        })();
        match done {
            Ok(()) => {
                self.conn.execute_batch("COMMIT")?;
                self.key = Zeroizing::new(*new_key);
                self.index_key = Zeroizing::new(new_index_key);
                // Now that the new key is the key, the prepared attachments are
                // the readable ones.
                if let Some(dir) = files_dir {
                    self.finish_file_rekey(dir);
                }
                // The copy is protected by the key we just retired, which is the
                // weak one this whole exercise is about. It exists only for the
                // moment the conversion is in flight.
                if let Some(backup) = backup {
                    let _ = std::fs::remove_file(backup);
                }
                Ok(())
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                // The prepared copies describe a key nobody adopted.
                if let Some(dir) = files_dir {
                    self.finish_file_rekey(dir);
                }
                Err(e)
            }
        }
    }

    /// The suffix a re-sealed attachment waits under until the new key is real.
    const REKEY_TMP: &'static str = ".rekey-tmp";

    /// Write a copy of every attachment this key opens, sealed under `new_key`.
    ///
    /// Files this key cannot open are another profile's — or were never sealed
    /// at all, which is how attachments from before 2.2.2 sit — and are left
    /// alone in both cases.
    fn reseal_files_to_temp(&self, files_dir: &Path, new_key: &[u8; 32]) -> Result<(), StoreError> {
        let Ok(entries) = std::fs::read_dir(files_dir) else { return Ok(()) };
        for path in entries.flatten().map(|e| e.path()).filter(|p| p.is_file()) {
            if path.to_string_lossy().ends_with(Self::REKEY_TMP) {
                continue;
            }
            let Ok(raw) = std::fs::read(&path) else { continue };
            let Ok(plain) = self.unseal(&raw) else { continue };
            let tmp = PathBuf::from(format!("{}{}", path.to_string_lossy(), Self::REKEY_TMP));
            std::fs::write(&tmp, seal_with(new_key, &plain)?)
                .map_err(|e| StoreError::Db(e.to_string()))?;
        }
        Ok(())
    }

    /// Settle any half-finished attachment re-sealing.
    ///
    /// A prepared copy is put in place when it opens under the key this store
    /// currently holds, and thrown away when it does not — which is exactly the
    /// difference between "the conversion committed" and "it did not". Safe to
    /// call at any time, and called on every sign-in, so a crash in the moment
    /// between the database committing and the files being swapped in does not
    /// cost anyone their pictures.
    pub fn finish_file_rekey(&self, files_dir: &Path) {
        let Ok(entries) = std::fs::read_dir(files_dir) else { return };
        for tmp in entries.flatten().map(|e| e.path()).filter(|p| p.is_file()) {
            let name = tmp.to_string_lossy().to_string();
            let Some(target) = name.strip_suffix(Self::REKEY_TMP) else { continue };
            match std::fs::read(&tmp).ok().map(|raw| self.unseal(&raw).is_ok()) {
                Some(true) => {
                    let _ = std::fs::rename(&tmp, target);
                }
                _ => {
                    let _ = std::fs::remove_file(&tmp);
                }
            }
        }
    }

    /// Copy the database beside itself for the duration of a re-key.
    ///
    /// Best effort: an in-memory store has no path, and a full disk is not a
    /// reason to refuse a conversion that is transactional anyway.
    fn backup_before_rekey(&self) -> Option<PathBuf> {
        let path = self.conn.path().map(PathBuf::from)?;
        if !path.exists() {
            return None; // in-memory
        }
        let backup = path.with_extension("db.pre-rekey.bak");
        // A leftover from an attempt that died mid-flight. The database itself
        // rolled back, so the copy describes the same content and is no safer
        // to keep than to replace.
        let _ = std::fs::remove_file(&backup);
        std::fs::copy(&path, &backup).ok().map(|_| backup)
    }

    /// Re-seal one column under `new_key`, leaving alone every value the
    /// current key cannot open.
    fn reseal_column(
        &self,
        table: &str,
        column: &str,
        new_key: &[u8; 32],
    ) -> Result<(), StoreError> {
        let rows: Vec<(i64, Vec<u8>)> = {
            let mut stmt = self.conn.prepare(&format!(
                "SELECT rowid, {column} FROM {table} WHERE {column} IS NOT NULL"
            ))?;
            let rows =
                stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
            rows.collect::<Result<_, _>>()?
        };
        for (id, sealed) in rows {
            let Ok(plain) = self.unseal(&sealed) else { continue };
            self.conn.execute(
                &format!("UPDATE {table} SET {column} = ?2 WHERE rowid = ?1"),
                params![id, seal_with(new_key, &plain)?],
            )?;
        }
        Ok(())
    }

    /// Is anything in this column still readable with the current key?
    fn column_still_opens(&self, table: &str, column: &str) -> Result<bool, StoreError> {
        let mut stmt = self
            .conn
            .prepare(&format!("SELECT {column} FROM {table} WHERE {column} IS NOT NULL"))?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        for row in rows {
            if self.unseal(&row?).is_ok() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Convert plaintext secret names to blind indexes, once, on its own mark.
    ///
    /// Skipped silently when the key does not open the file — a decoy or duress
    /// passphrase has no business rewriting another profile's rows, and failing
    /// here would turn "not my data" into an error.
    fn migrate_secret_names(&self) -> Result<(), StoreError> {
        let marked: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM secrets WHERE name = ?1",
                params![SECRET_NAMES_MARK],
                |r| r.get(0),
            )
            .optional()?;
        if marked.is_some() {
            return Ok(());
        }
        if !self.key_opens_existing_data()? {
            return Ok(());
        }
        self.reindex_secret_names()?;
        self.conn.execute(
            "INSERT INTO secrets(name, value) VALUES(?1, ?2)
             ON CONFLICT(name) DO UPDATE SET value = excluded.value",
            params![SECRET_NAMES_MARK, self.seal(b"1")?],
        )?;
        Ok(())
    }

    /// Move the secrets of an older database onto blind-indexed names.
    ///
    /// Their names were written in the clear (`identity_seed`, `avatar`), which
    /// both describes the contents and would collide the moment a second
    /// passphrase wanted a row of its own.
    fn reindex_secret_names(&self) -> Result<(), StoreError> {
        let names: Vec<String> = {
            let mut stmt = self.conn.prepare("SELECT name FROM secrets")?;
            let rows = stmt.query_map([], |r| r.get::<_, Option<String>>(0))?;
            rows.filter_map(|r| r.transpose()).collect::<Result<_, _>>()?
        };
        for name in names {
            if name == BLIND_INDEX_MARK || name == SECRET_NAMES_MARK {
                continue; // stays readable by design, see above
            }
            let bi = self.indexed(name.as_bytes())?;
            self.conn.execute(
                "UPDATE secrets SET name = ?2 WHERE name = ?1",
                params![name, bi],
            )?;
        }
        Ok(())
    }

    /// Does our key actually open what is already in this file?
    ///
    /// `true` also when there is nothing sealed yet — a database with no data
    /// cannot be damaged by converting it.
    fn key_opens_existing_data(&self) -> Result<bool, StoreError> {
        let mut saw_something = false;
        for (table, column) in [
            ("secrets", "value"),
            ("contacts", "display_name"),
            ("messages", "body"),
            ("groups", "name"),
        ] {
            // Several rows, not the first one. A file can hold rows this key is
            // not meant to read — another profile's, or the wrapped data key,
            // which is sealed under the passphrase rather than under the key it
            // protects — and judging by whichever row happens to come back
            // first would call a perfectly good key wrong.
            let mut stmt = self
                .conn
                .prepare(&format!("SELECT {column} FROM {table} WHERE {column} IS NOT NULL LIMIT 32"))?;
            let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
            for row in rows {
                saw_something = true;
                if self.unseal(&row?).is_ok() {
                    return Ok(true);
                }
            }
        }
        // Nothing sealed anywhere: an empty database cannot be damaged by
        // converting it.
        Ok(!saw_something)
    }

    /// Replace every raw value in one column with its blind index.
    fn reindex_column(&self, table: &str, column: &str, len: usize) -> Result<(), StoreError> {
        let values: Vec<Vec<u8>> = {
            let mut stmt = self.conn.prepare(&format!(
                "SELECT DISTINCT {column} FROM {table} WHERE {column} IS NOT NULL"
            ))?;
            let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
            rows.collect::<Result<_, _>>()?
        };
        for value in values {
            // A 16-byte group id becomes a 32-byte index, so a second run finds
            // nothing left to do. Identity keys are 32 bytes either way, which
            // is what BLIND_INDEX_MARK is for.
            if value.len() != len {
                continue;
            }
            let bi = self.indexed(&value)?;
            self.conn.execute(
                &format!("UPDATE {table} SET {column} = ?2 WHERE {column} = ?1"),
                params![value, bi],
            )?;
        }
        Ok(())
    }

    /// Bring an older database up to the current shape. `CREATE TABLE IF NOT
    /// EXISTS` only covers new tables, so columns added later need this.
    fn migrate(conn: &Connection) -> Result<(), StoreError> {
        if !Self::has_column(conn, "messages", "state")? {
            conn.execute_batch(
                "ALTER TABLE messages ADD COLUMN state INTEGER NOT NULL DEFAULT 0",
            )?;
        }
        // Contacts from before this existed were all added by us on purpose,
        // so they count as accepted.
        if !Self::has_column(conn, "contacts", "status")? {
            conn.execute_batch(
                "ALTER TABLE contacts ADD COLUMN status INTEGER NOT NULL DEFAULT 1",
            )?;
        }
        if !Self::has_column(conn, "contacts", "saved")? {
            conn.execute_batch(
                "ALTER TABLE contacts ADD COLUMN saved INTEGER NOT NULL DEFAULT 0",
            )?;
        }
        // Nobody has compared a safety number before this column existed, so
        // every existing contact starts unverified. Defaulting the other way
        // would be a lie the user never told.
        if !Self::has_column(conn, "contacts", "verified")? {
            conn.execute_batch(
                "ALTER TABLE contacts ADD COLUMN verified INTEGER NOT NULL DEFAULT 0",
            )?;
        }
        // Contacts added before post-quantum identities have none. They keep
        // working with the classical half alone, which is what they had.
        if !Self::has_column(conn, "contacts", "pq_fingerprint")? {
            conn.execute_batch("ALTER TABLE contacts ADD COLUMN pq_fingerprint BLOB")?;
        }
        // Which file a message carries. Without these the thread kept only the
        // line of text describing an attachment, so a photo or GIF was a
        // filename again after a restart — and nothing showed it at all if the
        // app had been closed since it arrived.
        //
        // The path and name are sealed like a body; the size is not, because it
        // is the one thing already visible to anyone watching the transfer.
        if !Self::has_column(conn, "messages", "file_path")? {
            conn.execute_batch("ALTER TABLE messages ADD COLUMN file_path BLOB")?;
        }
        if !Self::has_column(conn, "messages", "file_name")? {
            conn.execute_batch("ALTER TABLE messages ADD COLUMN file_name BLOB")?;
        }
        // How the other side refers to a message, and what a reply answers.
        // Both are blind indexes, so an older database simply has none and its
        // messages cannot be replied to — which is true: the other side never
        // learned a reference for them either.
        for table in ["messages", "group_messages"] {
            if !Self::has_column(conn, table, "msg_ref")? {
                conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN msg_ref BLOB"))?;
                conn.execute_batch(&format!(
                    "CREATE INDEX IF NOT EXISTS idx_{table}_ref ON {table}(msg_ref)"
                ))?;
            }
            if !Self::has_column(conn, table, "reply_to")? {
                conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN reply_to BLOB"))?;
            }
        }
        if !Self::has_column(conn, "messages", "file_size")? {
            conn.execute_batch("ALTER TABLE messages ADD COLUMN file_size INTEGER")?;
        }
        Ok(())
    }

    fn has_column(conn: &Connection, table: &str, column: &str) -> Result<bool, StoreError> {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let columns: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<Result<_, _>>()?;
        Ok(columns.iter().any(|c| c == column))
    }

    // --- value encryption (XChaCha20-Poly1305, nonce || ciphertext) ---

    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, StoreError> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|_| StoreError::Rng)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&*self.key).map_err(|_| StoreError::Crypto)?;
        let ct = cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext)
            .map_err(|_| StoreError::Crypto)?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn unseal(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        if blob.len() < NONCE_LEN {
            return Err(StoreError::Corrupt);
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        let cipher = XChaCha20Poly1305::new_from_slice(&*self.key).map_err(|_| StoreError::Crypto)?;
        let pt = cipher
            .decrypt(XNonce::from_slice(nonce), ct)
            .map_err(|_| StoreError::Corrupt)?; // wrong key or tampering
        Ok(Zeroizing::new(pt))
    }

    // --- secrets (identity seed, roster, session pickles, …) ---

    /// Store `value` under `name` exactly as given, sealing neither.
    ///
    /// For the one thing that cannot be sealed under the data key, because it
    /// *is* the data key. The caller has already wrapped it under the
    /// passphrase; see [`Store::rekey`].
    ///
    /// # Errors
    /// A storage error if the row cannot be written.
    pub fn put_raw_secret(&self, name: &[u8], value: &[u8]) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO secrets(name, value) VALUES(?1, ?2)
             ON CONFLICT(name) DO UPDATE SET value = excluded.value",
            params![name, value],
        )?;
        Ok(())
    }

    /// Remove a row by its exact stored name.
    ///
    /// The counterpart of [`Store::put_raw_secret`]: turning a passphrase off
    /// has to take its wrapped key with it, or the passphrase still opens the
    /// file.
    ///
    /// # Errors
    /// A storage error if the row cannot be removed.
    pub fn delete_raw_secret(&self, name: &[u8]) -> Result<(), StoreError> {
        self.conn
            .execute("DELETE FROM secrets WHERE name = ?1", params![name])?;
        Ok(())
    }

    /// Store a named secret (overwrites any existing value).
    ///
    /// The *name* is blind-indexed like every other lookup key, which is what
    /// lets two passphrases share one file without either being able to see
    /// that the other exists: the same name under a different key lands on a
    /// different row, and neither row says what it is for.
    ///
    /// # Errors
    /// A storage or crypto error if the value cannot be sealed or written.
    pub fn put_secret(&self, name: &str, plaintext: &[u8]) -> Result<(), StoreError> {
        let value = self.seal(plaintext)?;
        let key = self.indexed(name.as_bytes())?;
        self.conn.execute(
            "INSERT INTO secrets(name, value) VALUES(?1, ?2)
             ON CONFLICT(name) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Fetch a named secret, or `None` if absent.
    ///
    /// A row written under a different passphrase is simply *not there* as far
    /// as this key is concerned — not an error, because "the file holds
    /// something I cannot read" is exactly what must never be observable.
    pub fn get_secret(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        let blob: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT value FROM secrets WHERE name = ?1",
                params![self.bi(name.as_bytes())],
                |r| r.get(0),
            )
            .optional()?;
        // A value that will not open is treated as absent, exactly like a row
        // belonging to another passphrase. That consistency is the point: after
        // a duress wipe the app must look like a fresh, empty account, not like
        // a damaged one — a "database corrupt" message would announce that
        // something used to be there.
        if let Some(value) = blob.and_then(|b| self.unseal(&b).ok()) {
            return Ok(Some(value));
        }

        // Databases written before secret *names* were indexed still store them
        // in the clear. Shipping without this fallback is what made 2.0.0 tell
        // people their passphrase was wrong: the identity seed was right there
        // under `identity_seed`, and we were only ever looking for its index.
        let legacy: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT value FROM secrets WHERE name = ?1",
                params![name],
                |r| r.get(0),
            )
            .optional()?;
        Ok(legacy.and_then(|b| self.unseal(&b).ok()))
    }

    // --- profiles: what a passphrase opens ---

    /// What this passphrase is for. Absent means an ordinary account, which is
    /// what every database written before profiles existed contains.
    pub fn profile_kind(&self) -> ProfileKind {
        match self.get_secret(PROFILE_KIND) {
            Ok(Some(v)) => ProfileKind::from_bytes(&v),
            _ => ProfileKind::Normal,
        }
    }

    /// Mark what this passphrase opens. Stored like any other secret, so from
    /// outside it is one more unreadable row among the rest.
    pub fn set_profile_kind(&self, kind: ProfileKind) -> Result<(), StoreError> {
        self.put_secret(PROFILE_KIND, kind.as_bytes())
    }

    /// Destroy every row this key cannot read, in place.
    ///
    /// Used by a duress passphrase: it does not know the real key, so it cannot
    /// tell a real row from a decoy one — it destroys everything that is not
    /// its own. Sealed values are overwritten with random bytes **of the same
    /// length**, and rows are not deleted, so the file keeps its size, its row
    /// counts and its shape. What is gone is the content, and it is gone for
    /// good: there is no key that opens random bytes.
    ///
    /// Returns how many values were overwritten.
    ///
    /// This cannot defeat someone who copied the disk *before* it ran. Nothing
    /// running on the machine afterwards can — see `docs/DURESS.md`.
    pub fn destroy_unreadable(&self) -> Result<usize, StoreError> {
        // Every column that holds a sealed value, with its table.
        const SEALED: [(&str, &str); 11] = [
            ("secrets", "value"),
            ("blind_index", "sealed"),
            ("contacts", "display_name"),
            ("contacts", "onion_addr"),
            ("messages", "body"),
            ("outbox", "payload"),
            ("outbox", "body"),
            ("groups", "name"),
            ("group_members", "display_name"),
            ("group_members", "onion_addr"),
            ("group_messages", "body"),
        ];
        let mut destroyed = 0usize;
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| -> Result<(), StoreError> {
            for (table, column) in SEALED {
                let rows: Vec<(i64, Vec<u8>)> = {
                    let mut stmt = self
                        .conn
                        .prepare(&format!("SELECT rowid, {column} FROM {table}"))?;
                    let rows = stmt.query_map([], |r| {
                        Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
                    })?;
                    rows.collect::<Result<_, _>>()?
                };
                for (rowid, blob) in rows {
                    if self.unseal(&blob).is_ok() {
                        continue; // ours, and this passphrase is allowed to keep it
                    }
                    let mut noise = vec![0u8; blob.len()];
                    getrandom::getrandom(&mut noise).map_err(|_| StoreError::Rng)?;
                    self.conn.execute(
                        &format!("UPDATE {table} SET {column} = ?2 WHERE rowid = ?1"),
                        params![rowid, noise],
                    )?;
                    destroyed += 1;
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(destroyed)
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// Remove a named secret.
    pub fn delete_secret(&self, name: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM secrets WHERE name = ?1",
            params![self.bi(name.as_bytes())],
        )?;
        Ok(())
    }

    // --- contacts ---

    /// Insert or update a contact.
    ///
    /// An update keeps the decisions the user already made: a rename or a new
    /// onion address must never quietly un-block someone or turn a waiting
    /// request into an accepted chat.
    pub fn upsert_contact(&self, c: &Contact) -> Result<(), StoreError> {
        let name = self.seal(c.display_name.as_bytes())?;
        let onion = self.seal(c.onion_addr.as_bytes())?;
        let bi = self.indexed(&c.identity_pubkey)?;
        let pq = match &c.pq_fingerprint {
            Some(fp) => Some(self.seal(fp)?),
            None => None,
        };
        self.conn.execute(
            "INSERT INTO contacts(identity_pubkey, display_name, onion_addr, added_at, status, saved, verified, pq_fingerprint)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(identity_pubkey) DO UPDATE SET
                 display_name = excluded.display_name,
                 onion_addr   = excluded.onion_addr,
                 -- Never *unset* a commitment we already hold: an update that
                 -- happens to carry no fingerprint must not silently downgrade
                 -- the contact to classical-only.
                 pq_fingerprint = COALESCE(excluded.pq_fingerprint, contacts.pq_fingerprint)",
            params![
                bi,
                name,
                onion,
                c.added_at as i64,
                c.status.to_i64(),
                c.saved as i64,
                c.verified as i64,
                pq
            ],
        )?;
        Ok(())
    }

    /// Fetch a contact by identity key.
    pub fn get_contact(&self, identity_pubkey: &[u8; 32]) -> Result<Option<Contact>, StoreError> {
        let row: Option<ContactRow> = self
            .conn
            .query_row(
                "SELECT display_name, onion_addr, added_at, status, saved, verified, pq_fingerprint
                 FROM contacts WHERE identity_pubkey = ?1",
                params![self.bi(identity_pubkey)],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((name_ct, onion_ct, added, status, saved, verified, pq_ct)) => Ok(Some(Contact {
                identity_pubkey: *identity_pubkey,
                display_name: self.decrypt_string(&name_ct)?,
                onion_addr: self.decrypt_string(&onion_ct)?,
                added_at: added as u64,
                status: ContactStatus::from_i64(status),
                saved: saved != 0,
                verified: verified != 0,
                pq_fingerprint: self.unseal_fingerprint(pq_ct.as_deref()),
            })),
        }
    }

    /// Make every contact row use the index derived from its own identity.
    ///
    /// This is the fault under the "same conversation twice", the "no messages
    /// yet" beside a full thread, and contacts vanishing: a row can be stored
    /// under one routing index while everything else — its messages, its queue,
    /// every lookup by identity — uses the index derived from the identity. The
    /// two only have to disagree once for the row and its history to stop
    /// finding each other, and then any repair that assumes one of them picks
    /// the wrong row.
    ///
    /// So instead of working around it: move the row, its messages and its
    /// queue onto the derived index. When a row is already there, the two are
    /// the same person and are merged — keeping anything the user decided
    /// (saved, verified, blocked) from whichever row carries it.
    ///
    /// Returns how many rows were moved or merged.
    pub fn normalise_contact_indexes(&self) -> Result<usize, StoreError> {
        let mut stmt = self.conn.prepare("SELECT identity_pubkey FROM contacts")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let stored: Vec<Vec<u8>> = rows.collect::<Result<_, _>>()?;
        drop(stmt);

        let mut fixed = 0;
        for old in stored {
            let Some(identity) = self.try_key32_of(&old) else { continue };
            let canonical = self.indexed(&identity)?;
            if old == canonical {
                continue;
            }

            let existing: Option<i64> = self
                .conn
                .query_row(
                    "SELECT 1 FROM contacts WHERE identity_pubkey = ?1",
                    params![canonical],
                    |r| r.get(0),
                )
                .optional()?;

            if existing.is_some() {
                // Two rows, one person: keep the decisions from both.
                let (Some(a), Some(b)) = (
                    self.contact_at_index(&old)?,
                    self.contact_at_index(&canonical)?,
                ) else {
                    continue;
                };
                let merged = Contact {
                    identity_pubkey: identity,
                    display_name: if b.display_name.is_empty() {
                        a.display_name
                    } else {
                        b.display_name
                    },
                    onion_addr: if b.onion_addr.is_empty() { a.onion_addr } else { b.onion_addr },
                    added_at: a.added_at.min(b.added_at),
                    // Blocking must survive; otherwise it would quietly undo.
                    status: if a.status == ContactStatus::Blocked
                        || b.status == ContactStatus::Blocked
                    {
                        ContactStatus::Blocked
                    } else if a.status == ContactStatus::Accepted
                        || b.status == ContactStatus::Accepted
                    {
                        ContactStatus::Accepted
                    } else {
                        ContactStatus::Waiting
                    },
                    saved: a.saved || b.saved,
                    verified: a.verified || b.verified,
                    pq_fingerprint: b.pq_fingerprint.or(a.pq_fingerprint),
                };
                self.upsert_contact(&merged)?;
                self.conn
                    .execute("DELETE FROM contacts WHERE identity_pubkey = ?1", params![old])?;
            } else {
                self.conn.execute(
                    "UPDATE contacts SET identity_pubkey = ?2 WHERE identity_pubkey = ?1",
                    params![old, canonical],
                )?;
            }

            // The history has to come with it, or the row keeps its name and
            // loses the conversation.
            self.conn.execute(
                "UPDATE messages SET contact_pubkey = ?2 WHERE contact_pubkey = ?1",
                params![old, canonical],
            )?;
            self.conn.execute(
                "UPDATE outbox SET peer_pubkey = ?2 WHERE peer_pubkey = ?1",
                params![old, canonical],
            )?;
            fixed += 1;
        }
        Ok(fixed)
    }

    /// Read a contact row by the exact index it is stored under.
    fn contact_at_index(&self, bi: &[u8]) -> Result<Option<Contact>, StoreError> {
        let row: Option<ContactRow> = self
            .conn
            .query_row(
                "SELECT display_name, onion_addr, added_at, status, saved, verified, pq_fingerprint
                 FROM contacts WHERE identity_pubkey = ?1",
                params![bi],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((name_ct, onion_ct, added, status, saved, verified, pq_ct)) = row else {
            return Ok(None);
        };
        let Some(identity) = self.try_key32_of(bi) else { return Ok(None) };
        Ok(Some(Contact {
            identity_pubkey: identity,
            display_name: self.try_decrypt_string(&name_ct).unwrap_or_default(),
            onion_addr: self.try_decrypt_string(&onion_ct).unwrap_or_default(),
            added_at: added as u64,
            status: ContactStatus::from_i64(status),
            saved: saved != 0,
            verified: verified != 0,
            pq_fingerprint: self.unseal_fingerprint(pq_ct.as_deref()),
        }))
    }

    /// Remove contact rows that stand for a person another row already covers.
    ///
    /// Two rows can carry different routing indexes and still resolve to the
    /// same identity key. When that happens the chat list shows the same person
    /// twice: one tile with the history and one without, because messages are
    /// found under the index derived from the identity, which only one of the
    /// rows matches.
    ///
    /// The row whose index matches the identity is the one everything else in
    /// the database is keyed by, so that is the one kept. Nothing is merged and
    /// no message is touched — the duplicates hold no history of their own.
    ///
    /// Returns how many rows were removed.
    pub fn dedupe_contacts(&self) -> Result<usize, StoreError> {
        let mut stmt = self.conn.prepare("SELECT identity_pubkey FROM contacts")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let stored: Vec<Vec<u8>> = rows.collect::<Result<_, _>>()?;

        // identity -> the rows that resolve to it
        let mut groups: Vec<([u8; 32], Vec<Vec<u8>>)> = Vec::new();
        for bi in stored {
            let Some(identity) = self.try_key32_of(&bi) else { continue };
            match groups.iter_mut().find(|(id, _)| *id == identity) {
                Some((_, list)) => list.push(bi),
                None => groups.push((identity, vec![bi])),
            }
        }

        let mut removed = 0;
        for (_identity, rows) in groups {
            if rows.len() < 2 {
                continue;
            }
            // Keep the row the conversation is attached to. Preferring the
            // "canonical" index instead is what deleted a contact with forty
            // messages and left the thread with nobody attached to it.
            let mut keep = rows[0].clone();
            let mut best = -1i64;
            for bi in &rows {
                let n: i64 = self.conn.query_row(
                    "SELECT COUNT(*) FROM messages WHERE contact_pubkey = ?1",
                    params![bi],
                    |r| r.get(0),
                )?;
                if n > best {
                    best = n;
                    keep = bi.clone();
                }
            }

            // Whatever the user decided lives on, wherever it was recorded.
            let mut merged = match self.contact_at_index(&keep)? {
                Some(c) => c,
                None => continue,
            };
            for bi in &rows {
                if *bi == keep {
                    continue;
                }
                if let Some(other) = self.contact_at_index(bi)? {
                    if merged.display_name.is_empty() {
                        merged.display_name = other.display_name;
                    }
                    if merged.onion_addr.is_empty() {
                        merged.onion_addr = other.onion_addr;
                    }
                    merged.saved |= other.saved;
                    merged.verified |= other.verified;
                    if other.status == ContactStatus::Blocked {
                        merged.status = ContactStatus::Blocked;
                    }
                    merged.pq_fingerprint = merged.pq_fingerprint.or(other.pq_fingerprint);
                    merged.added_at = merged.added_at.min(other.added_at);
                }
            }

            for bi in &rows {
                if *bi == keep {
                    continue;
                }
                // Any history on the row being dropped moves to the survivor.
                self.conn.execute(
                    "UPDATE messages SET contact_pubkey = ?2 WHERE contact_pubkey = ?1",
                    params![bi, keep],
                )?;
                self.conn.execute(
                    "UPDATE outbox SET peer_pubkey = ?2 WHERE peer_pubkey = ?1",
                    params![bi, keep],
                )?;
                self.conn
                    .execute("DELETE FROM contacts WHERE identity_pubkey = ?1", params![bi])?;
                removed += 1;
            }

            // Write the merged decisions back onto the row that survived.
            self.conn.execute(
                "UPDATE contacts SET display_name = ?2, onion_addr = ?3, status = ?4,
                                     saved = ?5, verified = ?6, added_at = ?7
                 WHERE identity_pubkey = ?1",
                params![
                    keep,
                    self.seal(merged.display_name.as_bytes())?,
                    self.seal(merged.onion_addr.as_bytes())?,
                    merged.status.to_i64(),
                    merged.saved as i64,
                    merged.verified as i64,
                    merged.added_at as i64,
                ],
            )?;
        }
        Ok(removed)
    }

    /// List all contacts, newest first.
    ///
    /// One person appears once: rows that resolve to an identity already seen
    /// are skipped, so a database that still holds duplicates cannot put the
    /// same conversation in the list twice.
    pub fn list_contacts(&self) -> Result<Vec<Contact>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT identity_pubkey, display_name, onion_addr, added_at, status, saved, verified,
                    pq_fingerprint
             FROM contacts ORDER BY added_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, Option<Vec<u8>>>(7)?,
            ))
        })?;
        #[allow(clippy::type_complexity)]
        let found: Vec<(Vec<u8>, Vec<u8>, Vec<u8>, i64, i64, i64, i64, Option<Vec<u8>>)> =
            rows.collect::<Result<_, _>>()?;
        let mut out: Vec<Contact> = Vec::new();
        for (pk, name_ct, onion_ct, added, status, saved, verified, pq_ct) in found {
            // Rows belonging to another passphrase are skipped, not reported.
            let (Some(identity_pubkey), Some(display_name), Some(onion_addr)) = (
                self.try_key32_of(&pk),
                self.try_decrypt_string(&name_ct),
                self.try_decrypt_string(&onion_ct),
            ) else {
                continue;
            };
            // One person, one entry: a second row resolving to the same identity
            // is a duplicate, and showing it would be the chat-list bug again.
            if out.iter().any(|c| c.identity_pubkey == identity_pubkey) {
                continue;
            }
            out.push(Contact {
                identity_pubkey,
                display_name,
                onion_addr,
                added_at: added as u64,
                status: ContactStatus::from_i64(status),
                saved: saved != 0,
                verified: verified != 0,
                pq_fingerprint: self.unseal_fingerprint(pq_ct.as_deref()),
            });
        }
        Ok(out)
    }

    /// Change a contact's name (the user's own label for them).
    pub fn rename_contact(&self, identity_pubkey: &[u8; 32], name: &str) -> Result<(), StoreError> {
        let sealed = self.seal(name.trim().as_bytes())?;
        self.conn.execute(
            "UPDATE contacts SET display_name = ?2 WHERE identity_pubkey = ?1",
            params![self.bi(identity_pubkey), sealed],
        )?;
        Ok(())
    }

    // --- attachments on disk ---
    //
    // Received files used to land in `files/` as themselves: a photo somebody
    // sent was a readable photo on disk, next to a database that went to great
    // lengths to encrypt the sentence describing it. Anyone with the file — a
    // backup, a stolen laptop, another program running as the user — had the
    // content without ever needing the passphrase.
    //
    // They are now sealed with the same key as everything else. The cost is
    // that opening one means decrypting it first (see `decrypt_file_to`),
    // rather than handing the path to the operating system.

    /// Seal `plaintext` into `path`, replacing whatever is there.
    pub fn encrypt_file(&self, path: &Path, plaintext: &[u8]) -> Result<(), StoreError> {
        let sealed = self.seal(plaintext)?;
        std::fs::write(path, sealed).map_err(|e| StoreError::Db(e.to_string()))
    }

    /// Read a sealed file back.
    ///
    /// A file that is not sealed at all is returned as-is: attachments received
    /// before this existed are still readable, and pretending otherwise would
    /// mean losing them.
    pub fn decrypt_file(&self, path: &Path) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let raw = std::fs::read(path).map_err(|e| StoreError::Db(e.to_string()))?;
        match self.unseal(&raw) {
            Ok(plain) => Ok(plain),
            Err(_) => Ok(Zeroizing::new(raw)),
        }
    }

    /// Attach files that are on disk to the messages that describe them.
    ///
    /// Attachments were only recorded with the message from 2.2.1 onwards, so
    /// anything sent or received before that is a line of text with a sealed
    /// file sitting beside it, unreferenced. The file is still there, and the
    /// message still says which name it had, so the two can be put back
    /// together.
    ///
    /// Matching is deliberately timid: a candidate must end with exactly the
    /// name the message names, and a file already claimed by another message is
    /// never reused. Where several files could fit, the oldest message takes
    /// the oldest file — and if anything is ambiguous beyond that, the message
    /// is left as text rather than shown the wrong picture.
    ///
    /// Returns how many messages gained their file back.
    pub fn backfill_attachments(&self, files_dir: &Path) -> Result<usize, StoreError> {
        let Ok(entries) = std::fs::read_dir(files_dir) else { return Ok(0) };
        let mut on_disk: Vec<(std::time::SystemTime, PathBuf)> = entries
            .flatten()
            .filter(|e| e.path().is_file())
            .map(|e| {
                let t = e
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::UNIX_EPOCH);
                (t, e.path())
            })
            .collect();
        on_disk.sort_by_key(|(t, _)| *t);

        // Files already spoken for must not be handed to a second message.
        let mut claimed: Vec<String> = Vec::new();
        {
            let mut stmt = self
                .conn
                .prepare("SELECT file_path FROM messages WHERE file_path IS NOT NULL")?;
            let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
            for row in rows {
                if let Some(p) = self.try_decrypt_string(&row?) {
                    claimed.push(p);
                }
            }
        }

        let mut stmt = self.conn.prepare(
            "SELECT id, body FROM messages WHERE file_path IS NULL ORDER BY sent_at ASC, id ASC",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        let pending: Vec<(i64, Vec<u8>)> = rows.collect::<Result<_, _>>()?;

        let mut fixed = 0;
        for (id, body_ct) in pending {
            let Some(body) = self.try_decrypt_string(&body_ct) else { continue };
            // The marker the app writes in front of an attachment's name.
            let Some(name) = body.strip_prefix("📎 ") else { continue };
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            let found = on_disk.iter().find(|(_, p)| {
                let Some(file) = p.file_name().and_then(|n| n.to_str()) else { return false };
                if !file.ends_with(name) {
                    return false;
                }
                let full = p.to_string_lossy().to_string();
                !claimed.contains(&full)
            });
            let Some((_, path)) = found else { continue };
            let full = path.to_string_lossy().to_string();
            let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            self.conn.execute(
                "UPDATE messages SET file_path = ?2, file_name = ?3, file_size = ?4 WHERE id = ?1",
                params![
                    id,
                    self.seal(full.as_bytes())?,
                    self.seal(name.as_bytes())?,
                    size as i64
                ],
            )?;
            claimed.push(full);
            fixed += 1;
        }
        Ok(fixed)
    }

    /// Is this file sealed, or still a plain attachment from an older version?
    pub fn file_is_encrypted(&self, path: &Path) -> bool {
        std::fs::read(path)
            .ok()
            .map(|raw| self.unseal(&raw).is_ok())
            .unwrap_or(false)
    }

    /// Remove a contact and everything belonging to that conversation.
    ///
    /// Deliberately thorough: the contact row, the messages, and anything of
    /// theirs still queued in the outbox. A "delete" that leaves the history
    /// behind is not a delete, and in this app that history is the point.
    ///
    /// The `blind_index` entry stays — other rows may still reference it, and
    /// it is sealed, so it reveals nothing on its own.
    pub fn delete_contact(&self, identity_pubkey: &[u8; 32]) -> Result<usize, StoreError> {
        let bi = self.bi(identity_pubkey);
        let messages = self
            .conn
            .execute("DELETE FROM messages WHERE contact_pubkey = ?1", params![bi])?;
        self.conn
            .execute("DELETE FROM outbox WHERE peer_pubkey = ?1", params![bi])?;
        self.conn
            .execute("DELETE FROM contacts WHERE identity_pubkey = ?1", params![bi])?;
        Ok(messages)
    }

    /// Remove one message, and the sealed file it carried.
    ///
    /// Local only: the copy on the other side is theirs and nothing here can
    /// reach it. The attachment goes with the row — leaving the file behind
    /// would keep the picture on disk after the user asked for it to be gone,
    /// which is the opposite of what "delete" means.
    ///
    /// Returns the path that was removed, so the caller can delete the file.
    pub fn delete_message(&self, id: i64) -> Result<Option<String>, StoreError> {
        let path: Option<Option<Vec<u8>>> = self
            .conn
            .query_row("SELECT file_path FROM messages WHERE id = ?1", params![id], |r| {
                r.get(0)
            })
            .optional()?;
        let path = path
            .flatten()
            .and_then(|ct| self.try_decrypt_string(&ct));
        self.conn
            .execute("DELETE FROM messages WHERE id = ?1", params![id])?;
        // Anything still queued for it would be sent to a peer for a message
        // that no longer exists here.
        self.conn
            .execute("DELETE FROM outbox WHERE message_id = ?1", params![id])?;
        Ok(path)
    }

    /// Accept, park or block a contact.
    pub fn set_contact_status(
        &self,
        identity_pubkey: &[u8; 32],
        status: ContactStatus,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE contacts SET status = ?2 WHERE identity_pubkey = ?1",
            params![self.bi(identity_pubkey), status.to_i64()],
        )?;
        Ok(())
    }

    /// Put everyone this profile has accepted into the address book, once.
    ///
    /// Accepting a conversation and keeping the person are the same decision,
    /// but only one of them was ever recorded: a contact who wrote to us first
    /// arrives unsaved, and accepting them left it that way. So the Contacts
    /// screen showed only the people whose invite the user had pasted in
    /// themselves, while the conversations with everyone else sat one tab away.
    ///
    /// Runs once per profile. Dropping someone from the address book afterwards
    /// is a decision, and this must not keep overruling it.
    ///
    /// # Errors
    /// A storage error if the rows cannot be read or written.
    pub fn save_accepted_contacts(&self) -> Result<usize, StoreError> {
        if self.get_secret(SAVED_CONTACTS_MARK)?.is_some() {
            return Ok(0);
        }
        let changed = self.conn.execute(
            "UPDATE contacts SET saved = 1 WHERE saved = 0 AND status = ?1",
            params![ContactStatus::Accepted.to_i64()],
        )?;
        self.put_secret(SAVED_CONTACTS_MARK, b"1")?;
        Ok(changed)
    }

    /// Keep (or drop) a contact in the address book.
    pub fn set_contact_saved(
        &self,
        identity_pubkey: &[u8; 32],
        saved: bool,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE contacts SET saved = ?2 WHERE identity_pubkey = ?1",
            params![self.bi(identity_pubkey), saved as i64],
        )?;
        Ok(())
    }

    /// Record that the user compared safety numbers with this contact.
    ///
    /// Only ever called from an explicit human decision — nothing in the
    /// protocol may set this, or the badge would stop meaning anything.
    pub fn set_contact_verified(
        &self,
        identity_pubkey: &[u8; 32],
        verified: bool,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE contacts SET verified = ?2 WHERE identity_pubkey = ?1",
            params![self.bi(identity_pubkey), verified as i64],
        )?;
        Ok(())
    }

    /// Is this identity blocked? Asked on every incoming frame, so it is a
    /// single indexed lookup rather than a full contact read.
    pub fn is_blocked(&self, identity_pubkey: &[u8; 32]) -> Result<bool, StoreError> {
        let status: Option<i64> = self
            .conn
            .query_row(
                "SELECT status FROM contacts WHERE identity_pubkey = ?1",
                params![self.bi(identity_pubkey)],
                |r| r.get(0),
            )
            .optional()?;
        Ok(status.map(ContactStatus::from_i64) == Some(ContactStatus::Blocked))
    }

    // --- messages ---

    /// Append a message, returning its row id.
    pub fn insert_message(&self, m: &NewMessage) -> Result<i64, StoreError> {
        let body = self.seal(m.body)?;
        let bi = self.indexed(&m.contact_pubkey)?;
        let (path, name, size) = match m.file {
            Some(f) => (
                Some(self.seal(f.path.as_bytes())?),
                Some(self.seal(f.name.as_bytes())?),
                Some(f.size as i64),
            ),
            None => (None, None, None),
        };
        self.conn.execute(
            "INSERT INTO messages(contact_pubkey, direction, sent_at, body,
                                  file_path, file_name, file_size, msg_ref, reply_to)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                bi,
                m.direction.to_i64(),
                m.sent_at as i64,
                body,
                path,
                name,
                size,
                self.indexed_opt(m.msg_ref.as_ref())?,
                self.indexed_opt(m.reply_to.as_ref())?,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// The blind index of an optional reference, mapping absent to absent.
    ///
    /// References are digests of a message's plaintext, so storing one raw
    /// would let anyone holding the file confirm a guess at what was said.
    /// Indexed like every other lookup key instead.
    fn indexed_opt(&self, value: Option<&[u8; 16]>) -> Result<Option<Vec<u8>>, StoreError> {
        match value {
            Some(v) => Ok(Some(self.indexed(v)?)),
            None => Ok(None),
        }
    }

    /// The message a reference stands for, if it is one of ours.
    ///
    /// # Errors
    /// A storage error if the row cannot be read.
    pub fn message_by_ref(&self, msg_ref: &[u8; 16]) -> Result<Option<Message>, StoreError> {
        let row: Option<MessageRow> = self
            .conn
            .query_row(
                "SELECT id, contact_pubkey, direction, sent_at, body, state,
                        file_path, file_name, file_size, reply_to
                 FROM messages WHERE msg_ref = ?1 ORDER BY id DESC LIMIT 1",
                params![self.bi(msg_ref)],
                |r| {
                    Ok((
                        r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?,
                        r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?,
                    ))
                },
            )
            .optional()?;
        let Some((id, peer, dir, sent_at, body_ct, state, path, name, size, reply)) = row else {
            return Ok(None);
        };
        let (Some(body), Some(contact_pubkey)) =
            (self.unseal(&body_ct).ok(), self.try_key32_of(&peer))
        else {
            return Ok(None); // another passphrase's row: absent, as always
        };
        Ok(Some(Message {
            id,
            contact_pubkey,
            direction: Direction::from_i64(dir)?,
            sent_at: sent_at as u64,
            body: body.to_vec(),
            state: MessageState::from_i64(state),
            file_path: path
                .and_then(|p| self.unseal(&p).ok())
                .map(|p| String::from_utf8_lossy(&p).to_string()),
            file_name: name
                .and_then(|n| self.unseal(&n).ok())
                .map(|n| String::from_utf8_lossy(&n).to_string()),
            file_size: size.map(|s| s.max(0) as u64),
            reply_to: self.ref_of(reply.as_deref())?,
        }))
    }

    /// Turn a stored reply index back into the reference it stands for.
    fn ref_of(&self, stored: Option<&[u8]>) -> Result<Option<[u8; 16]>, StoreError> {
        let Some(bi) = stored else { return Ok(None) };
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT sealed FROM blind_index WHERE bi = ?1", params![bi], |r| r.get(0))
            .optional()?;
        Ok(sealed
            .and_then(|s| self.unseal(&s).ok())
            .and_then(|v| <[u8; 16]>::try_from(v.as_slice()).ok()))
    }

    /// Every attachment in the history, newest first.
    ///
    /// One list across all conversations, which is the only way to answer "where
    /// is that picture" without remembering who sent it. Rows another passphrase
    /// wrote are skipped exactly as everywhere else — not an error, just absent.
    ///
    /// # Errors
    /// A storage error if the rows cannot be read.
    pub fn list_media(&self, limit: u32) -> Result<Vec<MediaItem>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, contact_pubkey, direction, sent_at, file_path, file_name, file_size
             FROM messages
             WHERE file_path IS NOT NULL
             ORDER BY sent_at DESC, id DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, Vec<u8>>(4)?,
                r.get::<_, Option<Vec<u8>>>(5)?,
                r.get::<_, Option<i64>>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            if out.len() as u32 >= limit {
                break;
            }
            let (id, peer, dir, sent_at, path_ct, name_ct, size) = row?;
            let (Some(path), Some(peer_pubkey)) =
                (self.unseal(&path_ct).ok(), self.try_key32_of(&peer))
            else {
                continue;
            };
            let name = name_ct
                .and_then(|n| self.unseal(&n).ok())
                .map(|n| String::from_utf8_lossy(&n).to_string())
                .unwrap_or_default();
            out.push(MediaItem {
                message_id: id,
                peer_pubkey,
                outgoing: Direction::from_i64(dir)? == Direction::Outgoing,
                sent_at: sent_at as u64,
                file_path: String::from_utf8_lossy(&path).to_string(),
                file_name: name,
                file_size: size.unwrap_or(0).max(0) as u64,
            });
        }
        Ok(out)
    }

    /// The most recent `limit` messages with a contact, oldest first.
    pub fn messages_for(
        &self,
        contact_pubkey: &[u8; 32],
        limit: u32,
    ) -> Result<Vec<Message>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, direction, sent_at, body, state, file_path, file_name, file_size, reply_to
             FROM messages
             WHERE contact_pubkey = ?1 ORDER BY sent_at ASC, id ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![self.bi(contact_pubkey), limit], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Option<Vec<u8>>>(5)?,
                r.get::<_, Option<Vec<u8>>>(6)?,
                r.get::<_, Option<i64>>(7)?,
                r.get::<_, Option<Vec<u8>>>(8)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, dir, sent_at, body_ct, state, path_ct, name_ct, size, reply) = row?;
            out.push(Message {
                id,
                contact_pubkey: *contact_pubkey,
                direction: Direction::from_i64(dir)?,
                sent_at: sent_at as u64,
                body: self.unseal(&body_ct)?.to_vec(),
                state: MessageState::from_i64(state),
                // An attachment nobody can decrypt is simply not shown; the
                // message itself still reads, which is what matters.
                file_path: path_ct.as_deref().and_then(|b| self.try_decrypt_string(b)),
                file_name: name_ct.as_deref().and_then(|b| self.try_decrypt_string(b)),
                file_size: size.map(|s| s as u64),
                reply_to: self.ref_of(reply.as_deref())?,
            });
        }
        Ok(out)
    }

    // --- reactions ---

    /// Record that `who` put `emoji` on the message `msg_ref` stands for.
    ///
    /// An empty `emoji` takes theirs off again. One per person per message: a
    /// second reaction replaces the first, which is what people expect and what
    /// keeps this from being a place to store unbounded text.
    ///
    /// # Errors
    /// A storage or crypto error if the row cannot be written.
    pub fn set_reaction(
        &self,
        msg_ref: &[u8; 16],
        who: &[u8; 32],
        emoji: &str,
        at: u64,
    ) -> Result<(), StoreError> {
        let key = self.indexed(msg_ref)?;
        let who_bi = self.indexed(who)?;
        if emoji.is_empty() {
            self.conn.execute(
                "DELETE FROM reactions WHERE msg_ref = ?1 AND who = ?2",
                params![key, who_bi],
            )?;
            return Ok(());
        }
        // Long enough for the emoji people actually use, including the ones
        // built from several code points. Anything past that is not a reaction.
        let emoji: String = emoji.chars().take(8).collect();
        self.conn.execute(
            "INSERT INTO reactions(msg_ref, who, emoji, at) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(msg_ref, who) DO UPDATE SET emoji = excluded.emoji, at = excluded.at",
            params![key, who_bi, self.seal(emoji.as_bytes())?, at as i64],
        )?;
        Ok(())
    }

    /// Every reaction on one message, as `(emoji, who)`.
    ///
    /// # Errors
    /// A storage error if the rows cannot be read.
    pub fn reactions_for(&self, msg_ref: &[u8; 16]) -> Result<Vec<(String, [u8; 32])>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT emoji, who FROM reactions WHERE msg_ref = ?1 ORDER BY at ASC")?;
        let rows = stmt.query_map(params![self.bi(msg_ref)], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (emoji_ct, who) = row?;
            let (Some(emoji), Some(who)) =
                (self.unseal(&emoji_ct).ok(), self.try_key32_of(&who))
            else {
                continue; // another passphrase's row
            };
            out.push((String::from_utf8_lossy(&emoji).to_string(), who));
        }
        Ok(out)
    }

    /// Move an outgoing message along (waiting → sent → delivered).
    pub fn set_message_state(&self, id: i64, state: MessageState) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE messages SET state = ?2 WHERE id = ?1",
            params![id, state.to_i64()],
        )?;
        Ok(())
    }

    // --- outbox ---

    /// Queue a frame for a peer. Returns the outbox row id.
    pub fn queue_outgoing(
        &self,
        peer_pubkey: &[u8; 32],
        message_id: i64,
        group_id: Option<[u8; 16]>,
        payload: &[u8],
        body: &[u8],
        created_at: u64,
    ) -> Result<i64, StoreError> {
        let payload_ct = self.seal(payload)?;
        let body_ct = self.seal(body)?;
        let peer_bi = self.indexed(peer_pubkey)?;
        let group_bi = match group_id {
            Some(g) => Some(self.indexed(&g)?),
            None => None,
        };
        self.conn.execute(
            "INSERT INTO outbox(peer_pubkey, message_id, group_id, payload, body, created_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                peer_bi,
                message_id,
                group_bi,
                payload_ct,
                body_ct,
                created_at as i64
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Everything still waiting for `peer`, oldest first.
    pub fn outbox_for(&self, peer_pubkey: &[u8; 32]) -> Result<Vec<OutboxItem>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, message_id, group_id, payload, body, created_at FROM outbox
             WHERE peer_pubkey = ?1 ORDER BY id ASC",
        )?;
        let rows = stmt.query_map(params![self.bi(peer_pubkey)], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Option<Vec<u8>>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, Vec<u8>>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, message_id, group, payload_ct, body_ct, created_at) = row?;
            out.push(OutboxItem {
                id,
                peer_pubkey: *peer_pubkey,
                message_id,
                group_id: match group {
                    Some(g) => Some(self.id16_of(&g)?),
                    None => None,
                },
                payload: self.unseal(&payload_ct)?.to_vec(),
                body: self.unseal(&body_ct)?.to_vec(),
                created_at: created_at as u64,
            });
        }
        Ok(out)
    }

    /// Every peer with something waiting, and how much.
    /// One waiting *item* per row would be wrong for attachments: a file is
    /// queued as an offer, dozens of chunks and an end marker, and counting
    /// those as messages turned one GIF into "84 waiting". Frames belonging to
    /// a file are stored with an empty body, so counting the rest gives the
    /// number a person would recognise.
    pub fn outbox_summary(&self) -> Result<Vec<([u8; 32], u32)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT peer_pubkey, COUNT(*) FROM outbox
             WHERE length(body) > ?1 GROUP BY peer_pubkey",
        )?;
        let rows = stmt.query_map(params![SEALED_EMPTY_LEN as i64], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (pk, n) = row?;
            if let Some(peer) = self.try_key32_of(&pk) {
                out.push((peer, n as u32));
            }
        }
        Ok(out)
    }

    /// Drop a queued item once it is on its way.
    pub fn dequeue(&self, outbox_id: i64) -> Result<(), StoreError> {
        self.conn
            .execute("DELETE FROM outbox WHERE id = ?1", params![outbox_id])?;
        Ok(())
    }

    /// A peer confirmed a text arrived: mark the oldest matching outgoing
    /// message delivered. Bodies are sealed with a fresh nonce each time, so
    /// the match is done on the decrypted text, not on the stored bytes.
    ///
    /// Returns the message row that was marked, if any.
    pub fn mark_delivered(
        &self,
        contact_pubkey: &[u8; 32],
        body: &[u8],
    ) -> Result<Option<i64>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, body FROM messages
             WHERE contact_pubkey = ?1 AND direction = 1 AND state < 2
             ORDER BY id ASC LIMIT 500",
        )?;
        let rows = stmt.query_map(params![self.bi(contact_pubkey)], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (id, body_ct) = row?;
            if self.unseal(&body_ct)?.as_slice() == body {
                self.set_message_state(id, MessageState::Delivered)?;
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    /// One message found by a search, from either kind of conversation.
    ///
    /// Bodies are encrypted at rest, so there is nothing for SQL to match on:
    /// searching means decrypting and comparing here. That is fine for a
    /// personal history and keeps the promise that the database says nothing
    /// about content — a searchable plaintext index would quietly break it.
    pub fn search_messages(&self, query: &str, limit: u32) -> Result<Vec<SearchHit>, StoreError> {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() {
            return Ok(Vec::new());
        }
        let mut hits = Vec::new();

        let mut stmt = self.conn.prepare(
            "SELECT id, contact_pubkey, direction, sent_at, body FROM messages
             ORDER BY sent_at DESC, id DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, Vec<u8>>(4)?,
            ))
        })?;
        for row in rows {
            if hits.len() as u32 >= limit {
                break;
            }
            let (id, peer, dir, sent_at, body_ct) = row?;
            // Not ours to read: another passphrase wrote it.
            let (Some(body), Some(peer_pubkey)) =
                (self.unseal(&body_ct).ok(), self.try_key32_of(&peer))
            else {
                continue;
            };
            let text = String::from_utf8_lossy(&body).to_string();
            if text.to_lowercase().contains(&needle) {
                hits.push(SearchHit {
                    id,
                    peer_pubkey,
                    group_id: None,
                    outgoing: Direction::from_i64(dir)? == Direction::Outgoing,
                    sent_at: sent_at as u64,
                    body: text,
                });
            }
        }

        let mut stmt = self.conn.prepare(
            "SELECT id, group_id, sender_pubkey, direction, sent_at, body FROM group_messages
             ORDER BY sent_at DESC, id DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Vec<u8>>(5)?,
            ))
        })?;
        for row in rows {
            if hits.len() as u32 >= limit * 2 {
                break;
            }
            let (id, gid, sender, dir, sent_at, body_ct) = row?;
            let (Some(body), Some(peer_pubkey), Some(group)) = (
                self.unseal(&body_ct).ok(),
                self.try_key32_of(&sender),
                self.try_id16_of(&gid),
            ) else {
                continue;
            };
            let text = String::from_utf8_lossy(&body).to_string();
            if text.to_lowercase().contains(&needle) {
                hits.push(SearchHit {
                    id,
                    peer_pubkey,
                    group_id: Some(group),
                    outgoing: Direction::from_i64(dir)? == Direction::Outgoing,
                    sent_at: sent_at as u64,
                    body: text,
                });
            }
        }

        hits.sort_by_key(|h| std::cmp::Reverse(h.sent_at));
        hits.truncate(limit as usize);
        Ok(hits)
    }

    /// Everything a given person ever sent us — in the 1:1 thread and in any
    /// group. Used by the contact view, where "what did they write" is the
    /// question, not "where was it written".
    pub fn messages_from(
        &self,
        sender: &[u8; 32],
        limit: u32,
    ) -> Result<Vec<SearchHit>, StoreError> {
        let mut hits = Vec::new();

        let mut stmt = self.conn.prepare(
            "SELECT id, sent_at, body FROM messages
             WHERE contact_pubkey = ?1 AND direction = 0
             ORDER BY sent_at DESC, id DESC LIMIT ?2",
        )?;
        let sender_bi = self.bi(sender);
        let rows = stmt.query_map(params![sender_bi, limit], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, Vec<u8>>(2)?))
        })?;
        for row in rows {
            let (id, sent_at, body_ct) = row?;
            hits.push(SearchHit {
                id,
                peer_pubkey: *sender,
                group_id: None,
                outgoing: false,
                sent_at: sent_at as u64,
                body: String::from_utf8_lossy(&self.unseal(&body_ct)?).to_string(),
            });
        }

        let mut stmt = self.conn.prepare(
            "SELECT id, group_id, sent_at, body FROM group_messages
             WHERE sender_pubkey = ?1 AND direction = 0
             ORDER BY sent_at DESC, id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![sender_bi, limit], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        for row in rows {
            let (id, gid, sent_at, body_ct) = row?;
            hits.push(SearchHit {
                id,
                peer_pubkey: *sender,
                group_id: Some(self.id16_of(&gid)?),
                outgoing: false,
                sent_at: sent_at as u64,
                body: String::from_utf8_lossy(&self.unseal(&body_ct)?).to_string(),
            });
        }

        hits.sort_by_key(|h| std::cmp::Reverse(h.sent_at));
        hits.truncate(limit as usize);
        Ok(hits)
    }

    /// Every identity we have exchanged messages with, contact or not.
    pub fn message_peers(&self) -> Result<Vec<[u8; 32]>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT contact_pubkey FROM messages")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let indexes: Vec<Vec<u8>> = rows.collect::<Result<_, _>>()?;
        let mut out = Vec::new();
        for bi in indexes {
            if let Some(pk) = self.try_key32_of(&bi) {
                out.push(pk);
            }
        }
        Ok(out)
    }

    /// Give every peer with a history a contact row.
    ///
    /// A conversation started by *them* used to live only in the running app:
    /// the messages were stored, but with nothing in `contacts` the next start
    /// had no way to show the thread, and the keep-alive loop had no address to
    /// dial — so the other side saw us as permanently unreachable. Anything the
    /// peer later tells us about themselves (name, onion) overwrites the
    /// placeholder written here.
    ///
    /// Returns how many rows were added.
    pub fn backfill_missing_contacts(&self, now: u64) -> Result<usize, StoreError> {
        let mut added = 0;
        for peer in self.message_peers()? {
            if self.get_contact(&peer)?.is_some() {
                continue;
            }
            self.upsert_contact(&Contact {
                identity_pubkey: peer,
                display_name: String::new(), // the UI falls back to a placeholder
                onion_addr: String::new(),   // filled in when they tell us
                added_at: now,
                // A thread that already exists was a real conversation; asking
                // the user to approve it again would be nonsense.
                status: ContactStatus::Accepted,
                saved: false,
                // Nobody has compared anything: an old thread proves they talked
                // to us, not that they are who we think.
                verified: false,
                // Learned when they next connect, not invented here.
                pq_fingerprint: None,
            })?;
            added += 1;
        }
        Ok(added)
    }

    /// Remove contact rows that are not conversations: no name, no address, no
    /// message ever, never saved by the user.
    ///
    /// Such a row is an artefact, not a person. It appears when a peer connects
    /// and sends a `PROFILE` or `ADDRESS` frame whose fields are empty — the
    /// row is created, and the chat list then shows an "unknown contact" next
    /// to the real one, which reads as the same conversation twice.
    ///
    /// Deliberately narrow. A contact with a name, an address, any history, or
    /// one the user saved or blocked is left alone, so this cannot eat a real
    /// conversation: blocked ones especially must survive, or blocking would
    /// undo itself.
    ///
    /// Returns how many rows were removed.
    pub fn purge_empty_contacts(&self) -> Result<usize, StoreError> {
        let mut removed = 0;
        for c in self.list_contacts()? {
            if !c.display_name.is_empty()
                || !c.onion_addr.is_empty()
                || c.saved
                || c.status == ContactStatus::Blocked
            {
                continue;
            }
            if self.message_count(&c.identity_pubkey)? > 0 {
                continue;
            }
            self.conn.execute(
                "DELETE FROM contacts WHERE identity_pubkey = ?1",
                params![self.bi(&c.identity_pubkey)],
            )?;
            removed += 1;
        }
        Ok(removed)
    }

    /// Fold one contact's history into another and drop the empty one.
    ///
    /// This is for the case the app cannot decide by itself: the same person
    /// with two identities, because they reinstalled or made a new account.
    /// Both are real contacts with real history, so nothing here guesses —
    /// the user says which is which and the messages move, they are never
    /// deleted.
    ///
    /// Anything still queued for the old identity moves too, so a message
    /// waiting in the outbox is not stranded on a contact that no longer
    /// exists. It will be delivered to the *new* identity, which is what
    /// "these are the same person" means.
    ///
    /// Returns how many messages were moved.
    pub fn merge_contacts(
        &self,
        from: &[u8; 32],
        into: &[u8; 32],
    ) -> Result<usize, StoreError> {
        if from == into {
            return Ok(0);
        }
        if self.get_contact(into)?.is_none() {
            return Err(StoreError::Corrupt);
        }
        let from_bi = self.bi(from);
        let into_bi = self.indexed(into)?;

        self.conn.execute("BEGIN IMMEDIATE", [])?;
        let result = (|| -> Result<usize, StoreError> {
            let moved = self.conn.execute(
                "UPDATE messages SET contact_pubkey = ?2 WHERE contact_pubkey = ?1",
                params![from_bi, into_bi],
            )?;
            self.conn.execute(
                "UPDATE outbox SET peer_pubkey = ?2 WHERE peer_pubkey = ?1",
                params![from_bi, into_bi],
            )?;
            self.conn.execute(
                "DELETE FROM contacts WHERE identity_pubkey = ?1",
                params![from_bi],
            )?;
            Ok(moved)
        })();
        match result {
            Ok(moved) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(moved)
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// How many messages we hold for a peer.
    pub fn message_count(&self, identity_pubkey: &[u8; 32]) -> Result<u64, StoreError> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE contact_pubkey = ?1",
            params![self.bi(identity_pubkey)],
            |r| r.get(0),
        )?;
        Ok(n as u64)
    }

    // --- groups ---

    /// Insert or update a group *and* its roster. The member list is replaced
    /// wholesale: a roster is only ever accepted as a complete snapshot (see
    /// [`crate::group::Group::merge`]), never patched member by member.
    pub fn upsert_group(&self, g: &Group) -> Result<(), StoreError> {
        let name = self.seal(g.name.as_bytes())?;
        let group_bi = self.indexed(&g.id)?;
        self.conn.execute(
            "INSERT INTO groups(group_id, name, version, created_at)
             VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(group_id) DO UPDATE SET
                 name    = excluded.name,
                 version = excluded.version",
            params![group_bi, name, g.version as i64, g.created_at as i64],
        )?;
        self.conn
            .execute("DELETE FROM group_members WHERE group_id = ?1", params![group_bi])?;
        for m in &g.members {
            let member_name = self.seal(m.display_name.as_bytes())?;
            let onion = self.seal(m.onion.as_bytes())?;
            let member_bi = self.indexed(&m.identity)?;
            self.conn.execute(
                "INSERT INTO group_members(group_id, member_pubkey, display_name, onion_addr)
                 VALUES(?1, ?2, ?3, ?4)",
                params![group_bi, member_bi, member_name, onion],
            )?;
        }
        Ok(())
    }

    /// Fetch one group with its roster.
    pub fn get_group(&self, group_id: &[u8; 16]) -> Result<Option<Group>, StoreError> {
        let row: Option<(Vec<u8>, i64, i64)> = self
            .conn
            .query_row(
                "SELECT name, version, created_at FROM groups WHERE group_id = ?1",
                params![self.bi(group_id)],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((name_ct, version, created_at)) = row else { return Ok(None) };
        Ok(Some(Group {
            id: *group_id,
            name: self.decrypt_string(&name_ct)?,
            version: version as u32,
            created_at: created_at as u64,
            members: self.group_members(group_id)?,
        }))
    }

    /// The roster of a group, in insertion order.
    pub fn group_members(&self, group_id: &[u8; 16]) -> Result<Vec<GroupMember>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT member_pubkey, display_name, onion_addr FROM group_members
             WHERE group_id = ?1 ORDER BY rowid ASC",
        )?;
        let rows = stmt.query_map(params![self.bi(group_id)], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let members: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = rows.collect::<Result<_, _>>()?;
        let mut out = Vec::new();
        for (pk, name_ct, onion_ct) in members {
            let (Some(identity), Some(display_name), Some(onion)) = (
                self.try_key32_of(&pk),
                self.try_decrypt_string(&name_ct),
                self.try_decrypt_string(&onion_ct),
            ) else {
                continue;
            };
            out.push(GroupMember { identity, display_name, onion });
        }
        Ok(out)
    }

    /// All groups, newest first.
    pub fn list_groups(&self) -> Result<Vec<Group>, StoreError> {
        let ids: Vec<Vec<u8>> = {
            let mut stmt = self
                .conn
                .prepare("SELECT group_id FROM groups ORDER BY created_at DESC")?;
            let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
            rows.collect::<Result<_, _>>()?
        };
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let Some(gid) = self.try_id16_of(&id) else { continue };
            if let Some(g) = self.get_group(&gid)? {
                out.push(g);
            }
        }
        Ok(out)
    }

    /// Forget a group: its roster and its whole history.
    pub fn delete_group(&self, group_id: &[u8; 16]) -> Result<(), StoreError> {
        let bi = self.bi(group_id);
        self.conn
            .execute("DELETE FROM group_messages WHERE group_id = ?1", params![bi])?;
        self.conn
            .execute("DELETE FROM group_members WHERE group_id = ?1", params![bi])?;
        self.conn
            .execute("DELETE FROM groups WHERE group_id = ?1", params![bi])?;
        // The mapping stays: outbox rows and old messages may still point at it,
        // and it is sealed anyway.
        Ok(())
    }

    /// Append a group message, returning its row id.
    pub fn insert_group_message(&self, m: &NewGroupMessage) -> Result<i64, StoreError> {
        let body = self.seal(m.body)?;
        let group_bi = self.indexed(&m.group_id)?;
        let sender_bi = self.indexed(&m.sender_pubkey)?;
        self.conn.execute(
            "INSERT INTO group_messages(group_id, sender_pubkey, direction, sent_at, body)
             VALUES(?1, ?2, ?3, ?4, ?5)",
            params![
                group_bi,
                sender_bi,
                m.direction.to_i64(),
                m.sent_at as i64,
                body
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// The most recent `limit` messages in a group, oldest first.
    pub fn group_messages_for(
        &self,
        group_id: &[u8; 16],
        limit: u32,
    ) -> Result<Vec<GroupMessage>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, sender_pubkey, direction, sent_at, body FROM group_messages
             WHERE group_id = ?1 ORDER BY sent_at ASC, id ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![self.bi(group_id), limit], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, Vec<u8>>(4)?,
            ))
        })?;
        let found: Vec<GroupMessageRow> = rows.collect::<Result<_, _>>()?;
        let mut out = Vec::new();
        for (id, sender, dir, sent_at, body_ct) in found {
            out.push(GroupMessage {
                id,
                group_id: *group_id,
                sender_pubkey: self.key32_of(&sender)?,
                direction: Direction::from_i64(dir)?,
                sent_at: sent_at as u64,
                body: self.unseal(&body_ct)?.to_vec(),
            });
        }
        Ok(out)
    }

    fn decrypt_string(&self, blob: &[u8]) -> Result<String, StoreError> {
        let bytes = self.unseal(blob)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| StoreError::Corrupt)
    }
}

fn to_key32(bytes: &[u8]) -> Result<[u8; 32], StoreError> {
    bytes.try_into().map_err(|_| StoreError::Corrupt)
}

/// Separate key for the blind index, so that indexing a value can never reveal
/// anything about the key that seals the values themselves.
fn derive_index_key(data_key: &[u8; 32]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(data_key)
        .expect("HMAC accepts a key of any length");
    mac.update(INDEX_KEY_INFO);
    mac.finalize().into_bytes().into()
}

/// Every stored secret in a database, as `(name, value)`, read without opening
/// it properly.
///
/// The wrapped data key lives among the ordinary secrets under a random name,
/// so finding it means trying to open each of these in turn. That is the point:
/// a row that announced itself as "the wrapped key for the third passphrase"
/// would tell whoever holds the file how many passphrases it answers to, which
/// is the one thing this design will not say.
///
/// # Errors
/// A storage error if the file exists but cannot be read at all. A file with no
/// `secrets` table yet is not an error — it has no keys to find.
pub fn stored_secrets(path: &Path) -> Result<Vec<StoredSecret>, StoreError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    // CAST, because two rows keep plain text names — the schema marks, which
    // describe the file rather than any one passphrase and so must stay
    // findable without a key. Reading those as bytes would otherwise fail and
    // take the whole lookup with it.
    let Ok(mut stmt) = conn.prepare("SELECT CAST(name AS BLOB), value FROM secrets") else {
        return Ok(Vec::new());
    };
    let rows = stmt.query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Seal a value under a given key.
///
/// Free-standing for the same reason as [`bi_with`]: re-keying writes under the
/// new key while the store still holds the old one.
fn seal_with(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, StoreError> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| StoreError::Rng)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| StoreError::Crypto)?;
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| StoreError::Crypto)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// The blind index of `value` under a given index key.
///
/// Free-standing because re-keying has to compute indexes under the *new* key
/// while the store still holds the old one.
fn bi_with(index_key: &[u8; 32], value: &[u8]) -> Vec<u8> {
    // Fully qualified: the AEAD in scope has a `new_from_slice` of its own.
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(index_key)
        .expect("HMAC accepts a key of any length");
    mac.update(value);
    mac.finalize().into_bytes().to_vec()
}

/// Every column holding a blind index, and every column holding a sealed value.
///
/// Kept next to each other so that adding a column to [`SCHEMA`] and forgetting
/// it here is a visible omission rather than a silent one. A column missing
/// from the first list would keep an index nobody can match after a re-key; one
/// missing from the second would stay sealed under a key that no longer exists.
const INDEX_COLUMNS: &[(&str, &str)] = &[
    ("contacts", "identity_pubkey"),
    ("messages", "contact_pubkey"),
    ("messages", "msg_ref"),
    ("messages", "reply_to"),
    ("group_messages", "msg_ref"),
    ("group_messages", "reply_to"),
    ("reactions", "msg_ref"),
    ("reactions", "who"),
    ("outbox", "peer_pubkey"),
    ("outbox", "group_id"),
    ("groups", "group_id"),
    ("group_members", "group_id"),
    ("group_members", "member_pubkey"),
    ("group_messages", "group_id"),
    ("group_messages", "sender_pubkey"),
    ("secrets", "name"),
];

const SEALED_COLUMNS: &[(&str, &str)] = &[
    ("secrets", "value"),
    ("contacts", "display_name"),
    ("contacts", "onion_addr"),
    ("contacts", "pq_fingerprint"),
    ("messages", "body"),
    ("messages", "file_path"),
    ("messages", "file_name"),
    ("outbox", "payload"),
    ("outbox", "body"),
    ("groups", "name"),
    ("group_members", "display_name"),
    ("group_members", "onion_addr"),
    ("group_messages", "body"),
    ("reactions", "emoji"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A temp DB file that removes itself (and sqlite side files) on drop.
    struct TempDb(PathBuf);
    impl TempDb {
        fn new() -> Self {
            let mut b = [0u8; 8];
            getrandom::getrandom(&mut b).unwrap();
            let name = format!("nullchat-test-{}.sqlite", u64::from_le_bytes(b));
            TempDb(std::env::temp_dir().join(name))
        }
    }
    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_file(self.0.with_extension("sqlite-wal"));
            let _ = std::fs::remove_file(self.0.with_extension("sqlite-shm"));
        }
    }

    fn sample_contact() -> Contact {
        Contact {
            identity_pubkey: [7u8; 32],
            display_name: "Alice".into(),
            onion_addr: "abcdef.onion".into(),
            added_at: 1_700_000_000,
            status: ContactStatus::Accepted,
            saved: false,
            verified: false,
            pq_fingerprint: None,
        }
    }

    /// The fault under all of it: a row stored under an index that is not the
    /// one derived from its identity. Its messages are unreachable by identity,
    /// so the contact looks empty — and a repair that trusts the derived index
    /// deletes the row that actually has the history.
    #[test]
    fn a_row_on_the_wrong_index_keeps_its_history() {
        let s = Store::open_in_memory(&[29u8; 32]).unwrap();
        let identity = [9u8; 32];

        // A row under a stray index, with its thread stored under the same one.
        let stray = b"an-index-that-is-not-derived-yet".to_vec();
        s.conn
            .execute(
                "INSERT INTO blind_index(bi, sealed) VALUES(?1, ?2)",
                params![stray, s.seal(&identity).unwrap()],
            )
            .unwrap();
        s.conn
            .execute(
                "INSERT INTO contacts(identity_pubkey, display_name, onion_addr, added_at,
                                      status, saved, verified)
                 VALUES(?1, ?2, ?3, 100, 1, 1, 1)",
                params![
                    stray,
                    s.seal(b"Petr").unwrap(),
                    s.seal(b"petr.onion").unwrap()
                ],
            )
            .unwrap();
        for body in [b"prvni".as_slice(), b"druha".as_slice()] {
            s.conn
                .execute(
                    "INSERT INTO messages(contact_pubkey, direction, sent_at, body)
                     VALUES(?1, 0, 100, ?2)",
                    params![stray, s.seal(body).unwrap()],
                )
                .unwrap();
        }

        // Before: looking the person up by identity finds nothing.
        assert!(s.get_contact(&identity).unwrap().is_none());
        assert_eq!(s.message_count(&identity).unwrap(), 0);

        assert_eq!(s.normalise_contact_indexes().unwrap(), 1);

        // After: one contact, with its name, its decisions and its thread.
        let c = s.get_contact(&identity).unwrap().expect("contact is findable");
        assert_eq!(c.display_name, "Petr");
        assert!(c.saved && c.verified);
        assert_eq!(s.message_count(&identity).unwrap(), 2);
        assert_eq!(s.list_contacts().unwrap().len(), 1);

        // Nothing is left to move, and dedupe has no reason to touch it.
        assert_eq!(s.normalise_contact_indexes().unwrap(), 0);
        assert_eq!(s.dedupe_contacts().unwrap(), 0);
        assert_eq!(s.message_count(&identity).unwrap(), 2);
    }

    /// Deduping must keep the row the conversation is attached to, and must not
    /// drop a decision the user made on the row it removes.
    #[test]
    fn deduping_keeps_the_history_and_the_decisions() {
        let s = Store::open_in_memory(&[31u8; 32]).unwrap();
        let identity = [4u8; 32];

        // The row with the history, but nothing the user chose.
        let with_history = s.indexed(&identity).unwrap();
        s.upsert_contact(&Contact {
            identity_pubkey: identity,
            display_name: String::new(),
            onion_addr: String::new(),
            added_at: 200,
            status: ContactStatus::Accepted,
            saved: false,
            verified: false,
            pq_fingerprint: None,
        })
        .unwrap();
        s.insert_message(&NewMessage {
            contact_pubkey: identity,
            direction: Direction::Incoming,
            sent_at: 200,
            body: b"ctyricet zprav",
            msg_ref: None,
            reply_to: None,
            file: None,
        })
        .unwrap();

        // A second row for the same person: named, saved, no messages.
        let stray = b"second-row-for-the-same-person!!".to_vec();
        s.conn
            .execute(
                "INSERT INTO blind_index(bi, sealed) VALUES(?1, ?2)",
                params![stray, s.seal(&identity).unwrap()],
            )
            .unwrap();
        s.conn
            .execute(
                "INSERT INTO contacts(identity_pubkey, display_name, onion_addr, added_at,
                                      status, saved, verified)
                 VALUES(?1, ?2, ?3, 100, 1, 1, 0)",
                params![
                    stray,
                    s.seal(b"Petr").unwrap(),
                    s.seal(b"petr.onion").unwrap()
                ],
            )
            .unwrap();

        assert_eq!(s.dedupe_contacts().unwrap(), 1);
        let c = s.get_contact(&identity).unwrap().unwrap();
        assert_eq!(c.display_name, "Petr", "the name must survive");
        assert!(c.saved, "being in the address book must survive");
        assert_eq!(c.onion_addr, "petr.onion");
        assert_eq!(s.message_count(&identity).unwrap(), 1, "history must survive");
        assert_eq!(with_history, s.bi(&identity));
    }

    /// Two rows resolving to one identity is what put the same person in the
    /// chat list twice — once with the history, once without, because messages
    /// are found under the index derived from the identity.
    #[test]
    fn one_person_appears_once() {
        let s = Store::open_in_memory(&[23u8; 32]).unwrap();
        let c = sample_contact();
        s.upsert_contact(&c).unwrap();
        s.insert_message(&NewMessage {
            contact_pubkey: c.identity_pubkey,
            direction: Direction::Incoming,
            sent_at: 1_700_000_100,
            body: b"nikdy",
            msg_ref: None,
            reply_to: None,
            file: None,
        })
        .unwrap();

        // A second row for the same person, as an older build could leave
        // behind: its own routing index, resolving to the same identity.
        let stray = b"stray-index-for-the-same-person!".to_vec();
        let sealed_identity = s.seal(&c.identity_pubkey).unwrap();
        s.conn
            .execute(
                "INSERT INTO blind_index(bi, sealed) VALUES(?1, ?2)",
                params![stray, sealed_identity],
            )
            .unwrap();
        s.conn
            .execute(
                "INSERT INTO contacts(identity_pubkey, display_name, onion_addr, added_at,
                                      status, saved, verified, pq_fingerprint)
                 SELECT ?1, display_name, onion_addr, added_at, status, saved, verified,
                        pq_fingerprint FROM contacts WHERE identity_pubkey = ?2",
                params![stray, s.bi(&c.identity_pubkey)],
            )
            .unwrap();

        // Listing hides it even before anything is repaired.
        assert_eq!(s.list_contacts().unwrap().len(), 1);

        assert_eq!(s.dedupe_contacts().unwrap(), 1);
        assert_eq!(s.list_contacts().unwrap().len(), 1);
        // The surviving row is the one the messages are keyed by.
        assert_eq!(s.message_count(&c.identity_pubkey).unwrap(), 1);
        assert!(s.get_contact(&c.identity_pubkey).unwrap().is_some());
        // Idempotent, and it never touches a lone contact.
        assert_eq!(s.dedupe_contacts().unwrap(), 0);
    }

    /// The duplicate-conversation bug: an empty `PROFILE`/`ADDRESS` frame used
    /// to create a contact with nothing in it, and the chat list showed it next
    /// to the real one. Purging those must not touch anything a user would miss.
    #[test]
    fn purging_empties_leaves_every_real_contact_alone() {
        let s = Store::open_in_memory(&[19u8; 32]).unwrap();
        let empty = |pk: [u8; 32]| Contact {
            identity_pubkey: pk,
            display_name: String::new(),
            onion_addr: String::new(),
            added_at: 1_700_000_000,
            status: ContactStatus::Accepted,
            saved: false,
            verified: false,
            pq_fingerprint: None,
        };

        s.upsert_contact(&empty([1u8; 32])).unwrap(); // the artefact
        s.upsert_contact(&sample_contact()).unwrap(); // has a name and an onion

        // Empty, but the user chose to keep it.
        let mut kept = empty([2u8; 32]);
        kept.saved = true;
        s.upsert_contact(&kept).unwrap();

        // Empty, but blocked — purging it would silently unblock them.
        let mut blocked = empty([3u8; 32]);
        blocked.status = ContactStatus::Blocked;
        s.upsert_contact(&blocked).unwrap();

        // Empty name and address, but a real conversation happened.
        let talked = empty([4u8; 32]);
        s.upsert_contact(&talked).unwrap();
        s.insert_message(&NewMessage {
            contact_pubkey: talked.identity_pubkey,
            direction: Direction::Incoming,
            sent_at: 1_700_000_100,
            body: b"ahoj",
            msg_ref: None,
            reply_to: None,
            file: None,
        })
        .unwrap();

        assert_eq!(s.purge_empty_contacts().unwrap(), 1);
        assert!(s.get_contact(&[1u8; 32]).unwrap().is_none());
        assert!(s.get_contact(&[7u8; 32]).unwrap().is_some());
        assert!(s.get_contact(&[2u8; 32]).unwrap().is_some());
        assert!(s.get_contact(&[3u8; 32]).unwrap().is_some());
        assert!(s.get_contact(&[4u8; 32]).unwrap().is_some());

        // Idempotent: nothing left to remove on the next sign-in.
        assert_eq!(s.purge_empty_contacts().unwrap(), 0);
    }

    /// Merging is for one person with two identities. It must move history,
    /// never drop it, and must leave the surviving contact's own details alone.
    #[test]
    fn merging_moves_history_and_keeps_nothing_behind() {
        let s = Store::open_in_memory(&[23u8; 32]).unwrap();
        let old_pk = [1u8; 32];
        let new_pk = [2u8; 32];

        let mut old = sample_contact();
        old.identity_pubkey = old_pk;
        old.display_name = "Petr (stary ucet)".into();
        s.upsert_contact(&old).unwrap();

        let mut new = sample_contact();
        new.identity_pubkey = new_pk;
        new.display_name = "Petr".into();
        new.onion_addr = "new.onion".into();
        s.upsert_contact(&new).unwrap();

        for (pk, body, at) in [
            (old_pk, &b"stara zprava"[..], 1_700_000_000),
            (old_pk, &b"dalsi stara"[..], 1_700_000_100),
            (new_pk, &b"nova zprava"[..], 1_700_000_200),
        ] {
            s.insert_message(&NewMessage {
                contact_pubkey: pk,
                direction: Direction::Incoming,
                sent_at: at,
                body,
                file: None,
                msg_ref: None,
                reply_to: None,
            })
            .unwrap();
        }

        assert_eq!(s.merge_contacts(&old_pk, &new_pk).unwrap(), 2);
        assert!(s.get_contact(&old_pk).unwrap().is_none());

        let kept = s.get_contact(&new_pk).unwrap().unwrap();
        assert_eq!(kept.display_name, "Petr");
        assert_eq!(kept.onion_addr, "new.onion");

        // All three messages are now one thread, still in order.
        let msgs = s.messages_for(&new_pk, 100).unwrap();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].body, b"stara zprava");
        assert_eq!(msgs[2].body, b"nova zprava");
        assert_eq!(s.message_count(&old_pk).unwrap(), 0);

        // Merging into someone who does not exist must not delete anything.
        assert!(s.merge_contacts(&new_pk, &[9u8; 32]).is_err());
        assert!(s.get_contact(&new_pk).unwrap().is_some());
    }

    #[test]
    fn a_decision_about_a_contact_survives_an_update() {
        let s = Store::open_in_memory(&[17u8; 32]).unwrap();
        let mut c = sample_contact();
        c.status = ContactStatus::Waiting;
        s.upsert_contact(&c).unwrap();

        s.set_contact_status(&c.identity_pubkey, ContactStatus::Blocked).unwrap();
        s.set_contact_saved(&c.identity_pubkey, true).unwrap();
        // Verification is remembered, and survives everything else changing.
        s.set_contact_verified(&c.identity_pubkey, true).unwrap();
        assert!(s.get_contact(&c.identity_pubkey).unwrap().unwrap().verified);
        s.rename_contact(&c.identity_pubkey, "  Alice z prace  ").unwrap();
        assert!(s.is_blocked(&c.identity_pubkey).unwrap());

        // A profile arriving from the peer must not undo blocking, unsave them
        // or bring back the old name.
        let mut fresh = c.clone();
        fresh.display_name = "Alice".into();
        fresh.onion_addr = "new.onion".into();
        fresh.status = ContactStatus::Accepted;
        fresh.saved = false;
        s.upsert_contact(&fresh).unwrap();

        let stored = s.get_contact(&c.identity_pubkey).unwrap().unwrap();
        assert_eq!(stored.status, ContactStatus::Blocked);
        assert!(stored.saved);
        assert_eq!(stored.onion_addr, "new.onion"); // this one *should* update
        assert!(s.is_blocked(&c.identity_pubkey).unwrap());

        s.set_contact_status(&c.identity_pubkey, ContactStatus::Accepted).unwrap();
        assert!(!s.is_blocked(&c.identity_pubkey).unwrap());
    }

    #[test]
    fn renaming_keeps_the_trimmed_name() {
        let s = Store::open_in_memory(&[18u8; 32]).unwrap();
        let c = sample_contact();
        s.upsert_contact(&c).unwrap();
        s.rename_contact(&c.identity_pubkey, "  Bob  ").unwrap();
        assert_eq!(
            s.get_contact(&c.identity_pubkey).unwrap().unwrap().display_name,
            "Bob"
        );
    }

    #[test]
    fn secret_roundtrip_and_overwrite() {
        let s = Store::open_in_memory(&[1u8; 32]).unwrap();
        assert!(s.get_secret("id_seed").unwrap().is_none());
        s.put_secret("id_seed", b"first").unwrap();
        assert_eq!(&**s.get_secret("id_seed").unwrap().unwrap(), b"first");
        s.put_secret("id_seed", b"second").unwrap();
        assert_eq!(&**s.get_secret("id_seed").unwrap().unwrap(), b"second");
    }

    #[test]
    fn contacts_crud() {
        let s = Store::open_in_memory(&[2u8; 32]).unwrap();
        let c = sample_contact();
        s.upsert_contact(&c).unwrap();
        assert_eq!(s.get_contact(&c.identity_pubkey).unwrap().unwrap(), c);

        let mut c2 = c.clone();
        c2.display_name = "Alice Renamed".into();
        s.upsert_contact(&c2).unwrap();
        assert_eq!(s.get_contact(&c.identity_pubkey).unwrap().unwrap(), c2);
        assert_eq!(s.list_contacts().unwrap().len(), 1);
    }

    #[test]
    fn messages_insert_and_query_ordered() {
        let s = Store::open_in_memory(&[3u8; 32]).unwrap();
        let peer = [9u8; 32];
        s.insert_message(&NewMessage { contact_pubkey: peer, direction: Direction::Outgoing, sent_at: 100, body: b"hi",
        msg_ref: None,
        reply_to: None,
 file: None,
}).unwrap();
        s.insert_message(&NewMessage { contact_pubkey: peer, direction: Direction::Incoming, sent_at: 101, body: b"hey",
        msg_ref: None,
        reply_to: None,
 file: None,
}).unwrap();
        // A message with a different peer must not show up.
        s.insert_message(&NewMessage { contact_pubkey: [1u8; 32], direction: Direction::Incoming, sent_at: 102, body: b"other",
        msg_ref: None,
        reply_to: None,
 file: None,
}).unwrap();

        let msgs = s.messages_for(&peer, 10).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].body, b"hi");
        assert_eq!(msgs[0].direction, Direction::Outgoing);
        assert_eq!(msgs[1].body, b"hey");
        assert_eq!(msgs[1].sent_at, 101);
    }

    /// Attachments from before they were kept with the message: the file is on
    /// disk, the message names it, and the two can be put back together.
    #[test]
    fn old_attachments_are_matched_back_to_their_messages() {
        let s = Store::open_in_memory(&[29u8; 32]).unwrap();
        let peer = [6u8; 32];
        let dir = std::env::temp_dir().join(format!(
            "nullchat-backfill-{}",
            u64::from_le_bytes({
                let mut b = [0u8; 8];
                getrandom::getrandom(&mut b).unwrap();
                b
            })
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("sent-aaaa-kotatko.gif"), b"sealed bytes").unwrap();
        std::fs::write(dir.join("nesouvisejici.bin"), b"x").unwrap();

        let add = |body: &str| {
            s.insert_message(&NewMessage {
                contact_pubkey: peer,
                direction: Direction::Outgoing,
                sent_at: 10,
                body: body.as_bytes(),
                msg_ref: None,
                reply_to: None,
                file: None,
            })
            .unwrap()
        };
        add("📎 kotatko.gif");
        add("📎 nikdy-neexistoval.gif"); // no file for this one
        add("obycejny text");

        assert_eq!(s.backfill_attachments(&dir).unwrap(), 1);
        let msgs = s.messages_for(&peer, 10).unwrap();
        assert!(msgs[0].file_path.as_deref().unwrap().ends_with("sent-aaaa-kotatko.gif"));
        assert_eq!(msgs[0].file_name.as_deref(), Some("kotatko.gif"));
        assert!(msgs[1].file_path.is_none(), "no file, so nothing is invented");
        assert!(msgs[2].file_path.is_none(), "plain text is left alone");

        // The same file is never handed to a second message, and running the
        // repair twice changes nothing.
        add("📎 kotatko.gif");
        assert_eq!(s.backfill_attachments(&dir).unwrap(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A sent GIF showed no preview because the attachment lived only in the
    /// running app: the row in `messages` was the line of text describing it.
    #[test]
    fn an_attachment_survives_closing_the_app() {
        let tmp = TempDb::new();
        let key = [11u8; 32];
        let peer = [5u8; 32];
        {
            let s = Store::open(&tmp.0, &key).unwrap();
            s.insert_message(&NewMessage {
                contact_pubkey: peer,
                direction: Direction::Outgoing,
                sent_at: 10,
                body: "📎 kotatko.gif".as_bytes(),
                msg_ref: None,
                reply_to: None,
                file: Some(NewAttachment {
                    path: r"C:\files\sealed-kotatko.gif",
                    name: "kotatko.gif",
                    size: 1234,
                }),
            })
            .unwrap();
            // A plain message keeps no file, and must not grow one.
            s.insert_message(&NewMessage {
                contact_pubkey: peer,
                direction: Direction::Incoming,
                sent_at: 11,
                body: b"jen text",
                msg_ref: None,
                reply_to: None,
                file: None,
            })
            .unwrap();
        }

        let s = Store::open(&tmp.0, &key).unwrap();
        let msgs = s.messages_for(&peer, 10).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].file_path.as_deref(), Some(r"C:\files\sealed-kotatko.gif"));
        assert_eq!(msgs[0].file_name.as_deref(), Some("kotatko.gif"));
        assert_eq!(msgs[0].file_size, Some(1234));
        assert!(msgs[1].file_path.is_none());
        assert!(msgs[1].file_size.is_none());
    }

    #[test]
    fn data_persists_across_reopen() {
        let tmp = TempDb::new();
        let key = [4u8; 32];
        {
            let s = Store::open(&tmp.0, &key).unwrap();
            s.upsert_contact(&sample_contact()).unwrap();
            s.insert_message(&NewMessage {
                contact_pubkey: [7u8; 32],
                direction: Direction::Incoming,
                sent_at: 5,
                body: b"persisted",
                msg_ref: None,
                reply_to: None,
                file: None,
            })
            .unwrap();
        }
        let s = Store::open(&tmp.0, &key).unwrap();
        assert_eq!(s.list_contacts().unwrap().len(), 1);
        let msgs = s.messages_for(&[7u8; 32], 10).unwrap();
        assert_eq!(msgs[0].body, b"persisted");
    }

    #[test]
    fn queued_messages_survive_and_can_be_flushed() {
        let tmp = TempDb::new();
        let key = [14u8; 32];
        let peer = [5u8; 32];
        let msg_id;
        {
            let s = Store::open(&tmp.0, &key).unwrap();
            msg_id = s
                .insert_message(&NewMessage {
                    contact_pubkey: peer,
                    direction: Direction::Outgoing,
                    sent_at: 100,
                    body: b"jsi offline, ale precti si to pozdeji",
                    msg_ref: None,
                    reply_to: None,
                    file: None,
                })
                .unwrap();
            s.queue_outgoing(&peer, msg_id, None, b"\x00frame", b"jsi offline, ale precti si to pozdeji", 100)
                .unwrap();
        }
        // Closing the app must not lose the queue.
        let s = Store::open(&tmp.0, &key).unwrap();
        let queued = s.outbox_for(&peer).unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].payload, b"\x00frame");
        assert_eq!(queued[0].message_id, msg_id);
        assert_eq!(s.outbox_summary().unwrap(), vec![(peer, 1)]);
        assert_eq!(s.messages_for(&peer, 10).unwrap()[0].state, MessageState::Waiting);

        // Once it goes out the queue empties and the message counts as sent.
        s.dequeue(queued[0].id).unwrap();
        s.set_message_state(msg_id, MessageState::Sent).unwrap();
        assert!(s.outbox_for(&peer).unwrap().is_empty());
        assert_eq!(s.messages_for(&peer, 10).unwrap()[0].state, MessageState::Sent);
    }

    #[test]
    fn a_receipt_marks_the_matching_message_delivered() {
        let s = Store::open_in_memory(&[15u8; 32]).unwrap();
        let peer = [6u8; 32];
        for body in [&b"prvni"[..], &b"druha"[..], &b"prvni"[..]] {
            s.insert_message(&NewMessage {
                contact_pubkey: peer,
                direction: Direction::Outgoing,
                sent_at: 1,
                body,
                file: None,
                msg_ref: None,
                reply_to: None,
            })
            .unwrap();
        }
        // Two messages share a body: the oldest undelivered one wins, so a
        // second receipt marks the second copy rather than doing nothing.
        let first = s.mark_delivered(&peer, b"prvni").unwrap().unwrap();
        let second = s.mark_delivered(&peer, b"prvni").unwrap().unwrap();
        assert!(second > first);
        assert!(s.mark_delivered(&peer, b"prvni").unwrap().is_none());
        assert!(s.mark_delivered(&peer, b"nikdy neposlano").unwrap().is_none());

        let states: Vec<_> = s.messages_for(&peer, 10).unwrap().iter().map(|m| m.state).collect();
        assert_eq!(
            states,
            vec![MessageState::Delivered, MessageState::Waiting, MessageState::Delivered]
        );
    }

    /// A database written before message states existed must still open.
    #[test]
    fn older_databases_gain_the_state_column() {
        let tmp = TempDb::new();
        {
            let conn = Connection::open(&tmp.0).unwrap();
            conn.execute_batch(
                "CREATE TABLE messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    contact_pubkey BLOB NOT NULL,
                    direction INTEGER NOT NULL,
                    sent_at INTEGER NOT NULL,
                    body BLOB NOT NULL);",
            )
            .unwrap();
        }
        let s = Store::open(&tmp.0, &[16u8; 32]).unwrap();
        s.insert_message(&NewMessage {
            contact_pubkey: [7u8; 32],
            direction: Direction::Outgoing,
            sent_at: 1,
            body: b"po migraci",
            msg_ref: None,
            reply_to: None,
            file: None,
        })
        .unwrap();
        assert_eq!(s.messages_for(&[7u8; 32], 10).unwrap()[0].state, MessageState::Waiting);
    }

    /// The bug this guards against: a peer who wrote to us first had messages
    /// but no contact row, so the whole thread vanished on restart.
    #[test]
    fn search_finds_text_in_both_kinds_of_conversation() {
        let s = Store::open_in_memory(&[19u8; 32]).unwrap();
        let peer = [3u8; 32];
        let gid = [4u8; 16];
        s.insert_message(&NewMessage {
            contact_pubkey: peer,
            direction: Direction::Incoming,
            sent_at: 100,
            body: "sraz v pondeli".as_bytes(),
            msg_ref: None,
            reply_to: None,
            file: None,
        })
        .unwrap();
        s.insert_group_message(&NewGroupMessage {
            group_id: gid,
            sender_pubkey: peer,
            direction: Direction::Incoming,
            sent_at: 200,
            body: "Sraz az v utery".as_bytes(),
            msg_ref: None,
            reply_to: None,
        })
        .unwrap();
        s.insert_message(&NewMessage {
            contact_pubkey: peer,
            direction: Direction::Outgoing,
            sent_at: 300,
            body: "necо jineho".as_bytes(),
            msg_ref: None,
            reply_to: None,
            file: None,
        })
        .unwrap();

        // Case-insensitive, both tables, newest first.
        let hits = s.search_messages("SRAZ", 10).unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].sent_at, 200);
        assert_eq!(hits[0].group_id, Some(gid));
        assert_eq!(hits[1].group_id, None);

        assert!(s.search_messages("nikde", 10).unwrap().is_empty());
        assert!(s.search_messages("   ", 10).unwrap().is_empty());
        assert_eq!(s.search_messages("sraz", 1).unwrap().len(), 1);
    }

    #[test]
    fn a_contact_view_shows_only_what_they_sent() {
        let s = Store::open_in_memory(&[20u8; 32]).unwrap();
        let them = [5u8; 32];
        let someone_else = [6u8; 32];
        s.insert_message(&NewMessage {
            contact_pubkey: them,
            direction: Direction::Incoming,
            sent_at: 10,
            body: b"od nich primo",
            msg_ref: None,
            reply_to: None,
            file: None,
        })
        .unwrap();
        // Our own reply must not show up as something they sent.
        s.insert_message(&NewMessage {
            contact_pubkey: them,
            direction: Direction::Outgoing,
            sent_at: 11,
            body: b"moje odpoved",
            msg_ref: None,
            reply_to: None,
            file: None,
        })
        .unwrap();
        s.insert_group_message(&NewGroupMessage {
            group_id: [7u8; 16],
            sender_pubkey: them,
            direction: Direction::Incoming,
            sent_at: 12,
            body: b"od nich ve skupine",
            msg_ref: None,
            reply_to: None,
        })
        .unwrap();
        s.insert_group_message(&NewGroupMessage {
            group_id: [7u8; 16],
            sender_pubkey: someone_else,
            direction: Direction::Incoming,
            sent_at: 13,
            body: b"od nekoho jineho",
            msg_ref: None,
            reply_to: None,
        })
        .unwrap();

        let hits = s.messages_from(&them, 50).unwrap();
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|h| !h.outgoing));
        assert_eq!(hits[0].body, "od nich ve skupine");
        assert_eq!(hits[0].group_id, Some([7u8; 16]));
        assert_eq!(hits[1].group_id, None);
    }

    #[test]
    fn history_without_a_contact_row_gets_one() {
        let s = Store::open_in_memory(&[13u8; 32]).unwrap();
        let stranger = [42u8; 32];
        s.insert_message(&NewMessage {
            contact_pubkey: stranger,
            direction: Direction::Incoming,
            sent_at: 10,
            body: b"ahoj",
            msg_ref: None,
            reply_to: None,
            file: None,
        })
        .unwrap();
        assert!(s.get_contact(&stranger).unwrap().is_none());
        assert!(s.list_contacts().unwrap().is_empty());

        assert_eq!(s.backfill_missing_contacts(1_700_000_000).unwrap(), 1);
        assert_eq!(s.list_contacts().unwrap().len(), 1);
        assert_eq!(s.messages_for(&stranger, 10).unwrap().len(), 1);

        // Running it again adds nothing, and a real contact is left alone.
        let known = sample_contact();
        s.upsert_contact(&known).unwrap();
        s.insert_message(&NewMessage {
            contact_pubkey: known.identity_pubkey,
            direction: Direction::Outgoing,
            sent_at: 11,
            body: b"hi",
            msg_ref: None,
            reply_to: None,
            file: None,
        })
        .unwrap();
        assert_eq!(s.backfill_missing_contacts(1_700_000_000).unwrap(), 0);
        assert_eq!(
            s.get_contact(&known.identity_pubkey).unwrap().unwrap().display_name,
            known.display_name
        );
    }

    fn sample_group() -> Group {
        Group {
            id: [8u8; 16],
            name: "Rodina".into(),
            version: 1,
            created_at: 1_700_000_000,
            members: vec![
                GroupMember {
                    identity: [1u8; 32],
                    display_name: "Lukáš".into(),
                    onion: "aaa.onion".into(),
                },
                GroupMember {
                    identity: [2u8; 32],
                    display_name: "Eva".into(),
                    onion: "bbb.onion".into(),
                },
            ],
        }
    }

    #[test]
    fn groups_crud_with_roster() {
        let s = Store::open_in_memory(&[10u8; 32]).unwrap();
        let g = sample_group();
        s.upsert_group(&g).unwrap();
        assert_eq!(s.get_group(&g.id).unwrap().unwrap(), g);
        assert_eq!(s.list_groups().unwrap().len(), 1);

        // A newer roster replaces the members wholesale — no leftovers.
        let mut g2 = g.clone();
        g2.name = "Rodina a přátelé".into();
        g2.version = 2;
        g2.members.remove(1);
        s.upsert_group(&g2).unwrap();
        let stored = s.get_group(&g.id).unwrap().unwrap();
        assert_eq!(stored.name, "Rodina a přátelé");
        assert_eq!(stored.version, 2);
        assert_eq!(stored.members.len(), 1);
        assert_eq!(stored.created_at, g.created_at); // never rewritten

        s.delete_group(&g.id).unwrap();
        assert!(s.get_group(&g.id).unwrap().is_none());
        assert!(s.group_members(&g.id).unwrap().is_empty());
    }

    #[test]
    fn group_messages_are_scoped_and_ordered() {
        let s = Store::open_in_memory(&[11u8; 32]).unwrap();
        let gid = [8u8; 16];
        s.insert_group_message(&NewGroupMessage {
            group_id: gid,
            sender_pubkey: [1u8; 32],
            direction: Direction::Outgoing,
            sent_at: 100,
            body: b"ahoj",
            msg_ref: None,
            reply_to: None,
        })
        .unwrap();
        s.insert_group_message(&NewGroupMessage {
            group_id: gid,
            sender_pubkey: [2u8; 32],
            direction: Direction::Incoming,
            sent_at: 101,
            body: b"cau",
            msg_ref: None,
            reply_to: None,
        })
        .unwrap();
        // Another group's message must not leak in.
        s.insert_group_message(&NewGroupMessage {
            group_id: [9u8; 16],
            sender_pubkey: [3u8; 32],
            direction: Direction::Incoming,
            sent_at: 102,
            body: b"jinde",
            msg_ref: None,
            reply_to: None,
        })
        .unwrap();

        let msgs = s.group_messages_for(&gid, 10).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].body, b"ahoj");
        assert_eq!(msgs[0].direction, Direction::Outgoing);
        assert_eq!(msgs[1].sender_pubkey, [2u8; 32]);
        assert_eq!(msgs[1].sent_at, 101);
    }

    #[test]
    fn deleting_a_group_takes_its_history() {
        let s = Store::open_in_memory(&[12u8; 32]).unwrap();
        let g = sample_group();
        s.upsert_group(&g).unwrap();
        s.insert_group_message(&NewGroupMessage {
            group_id: g.id,
            sender_pubkey: [1u8; 32],
            direction: Direction::Outgoing,
            sent_at: 1,
            body: b"tajne",
            msg_ref: None,
            reply_to: None,
        })
        .unwrap();
        s.delete_group(&g.id).unwrap();
        assert!(s.group_messages_for(&g.id, 10).unwrap().is_empty());
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let tmp = TempDb::new();
        {
            let s = Store::open(&tmp.0, &[5u8; 32]).unwrap();
            s.upsert_contact(&sample_contact()).unwrap();
        }
        // Reopen with a different data key. The rows are simply not visible:
        // another key's data must look like absence, not like a locked door,
        // or a second passphrase could never share the file unnoticed.
        let s = Store::open(&tmp.0, &[6u8; 32]).unwrap();
        assert_eq!(s.list_contacts(), Ok(Vec::new()));
        // Asking about one specific person now answers "nobody like that here"
        // rather than "yes, but you cannot read it": the routing column holds a
        // blind index, and the wrong key computes a different one. Whoever takes
        // the file cannot even confirm a guess about who is in it.
        assert_eq!(s.get_contact(&[7u8; 32]), Ok(None));
        assert!(!s.is_blocked(&[7u8; 32]).unwrap());
    }

    /// Everything this key could read is still readable afterwards, under the
    /// new key and only under it.
    #[test]
    fn a_rekey_carries_the_whole_account_across() {
        let tmp = TempDb::new();
        let old = [1u8; 32];
        let new = [9u8; 32];

        let mut s = Store::open(&tmp.0, &old).unwrap();
        s.put_secret("identity_seed", b"the identity").unwrap();
        s.upsert_contact(&Contact {
            identity_pubkey: [0xAAu8; 32],
            display_name: "Kontakt".into(),
            onion_addr: "abc.onion".into(),
            added_at: 1,
            status: ContactStatus::Accepted,
            saved: true,
            verified: true,
            pq_fingerprint: Some([0xCCu8; 32]),
        })
        .unwrap();
        let id = s
            .insert_message(&NewMessage {
                contact_pubkey: [0xAAu8; 32],
                direction: Direction::Outgoing,
                sent_at: 10,
                body: b"ahoj",
                msg_ref: None,
                reply_to: None,
                file: None,
            })
            .unwrap();
        s.queue_outgoing(&[0xAAu8; 32], id, None, b"frame bytes", b"ahoj", 10)
            .unwrap();
        // Groups are three more tables and five more index columns — the part
        // of a re-key most likely to be forgotten.
        let group = sample_group();
        s.upsert_group(&group).unwrap();
        s.insert_group_message(&NewGroupMessage {
            group_id: group.id,
            sender_pubkey: [0xAAu8; 32],
            direction: Direction::Incoming,
            sent_at: 20,
            body: b"ve skupine",
            msg_ref: None,
            reply_to: None,
        })
        .unwrap();

        s.rekey(&new, b"a random looking name", b"a wrapped key", None).unwrap();

        // The handle keeps working: its key was swapped, not invalidated.
        assert_eq!(s.messages_for(&[0xAAu8; 32], 10).unwrap().len(), 1);

        let after = Store::open(&tmp.0, &new).unwrap();
        let contacts = after.list_contacts().unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].display_name, "Kontakt");
        assert_eq!(contacts[0].onion_addr, "abc.onion");
        assert!(contacts[0].verified);
        assert_eq!(contacts[0].pq_fingerprint, Some([0xCCu8; 32]));
        // Looked up by identity, which only works if the routing column moved
        // onto an index computed from the new key.
        assert!(after.get_contact(&[0xAAu8; 32]).unwrap().is_some());
        assert_eq!(after.messages_for(&[0xAAu8; 32], 10).unwrap()[0].body, b"ahoj");
        assert_eq!(after.outbox_for(&[0xAAu8; 32]).unwrap().len(), 1);
        assert_eq!(
            &*after.get_secret("identity_seed").unwrap().unwrap(),
            b"the identity"
        );
        assert_eq!(after.get_group(&group.id).unwrap().unwrap(), group);
        assert_eq!(after.group_messages_for(&group.id, 10).unwrap().len(), 1);

        // And the key it used to have opens nothing at all.
        let stale = Store::open(&tmp.0, &old).unwrap();
        assert!(stale.list_contacts().unwrap().is_empty());
        assert!(stale.get_secret("identity_seed").unwrap().is_none());
    }

    /// The reason this is a re-key and not a re-encrypt: one file answers to
    /// several passphrases, and converting one must not touch the others.
    #[test]
    fn a_rekey_leaves_the_other_passphrase_untouched() {
        let tmp = TempDb::new();
        let (real_old, real_new) = ([1u8; 32], [3u8; 32]);
        let (decoy_old, decoy_new) = ([2u8; 32], [4u8; 32]);

        for (key, who, addr) in [(real_old, "Skutecny", "real.onion"), (decoy_old, "Nastraceny", "decoy.onion")] {
            let s = Store::open(&tmp.0, &key).unwrap();
            s.put_secret("identity_seed", who.as_bytes()).unwrap();
            s.upsert_contact(&Contact {
                identity_pubkey: if who == "Skutecny" { [0xAAu8; 32] } else { [0xBBu8; 32] },
                display_name: who.into(),
                onion_addr: addr.into(),
                added_at: 1,
                status: ContactStatus::Accepted,
                saved: true,
                verified: false,
                pq_fingerprint: None,
            })
            .unwrap();
        }

        {
            let mut real = Store::open(&tmp.0, &real_old).unwrap();
            real.rekey(&real_new, b"wrap row for the real one", b"wrapped", None).unwrap();
        }

        // The decoy still opens on the key it always had, sees its own history,
        // and still cannot see the other profile's.
        let decoy = Store::open(&tmp.0, &decoy_old).unwrap();
        let seen = decoy.list_contacts().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].display_name, "Nastraceny");
        assert!(decoy.get_contact(&[0xAAu8; 32]).unwrap().is_none());
        drop(decoy);

        // …and converts itself later, without disturbing the one that went first.
        {
            let mut decoy = Store::open(&tmp.0, &decoy_old).unwrap();
            decoy.rekey(&decoy_new, b"wrap row for the decoy", b"wrapped too", None).unwrap();
        }
        let real = Store::open(&tmp.0, &real_new).unwrap();
        assert_eq!(real.list_contacts().unwrap()[0].display_name, "Skutecny");
        let decoy = Store::open(&tmp.0, &decoy_new).unwrap();
        assert_eq!(decoy.list_contacts().unwrap()[0].display_name, "Nastraceny");
        assert!(decoy.get_contact(&[0xAAu8; 32]).unwrap().is_none());
        assert!(real.get_contact(&[0xBBu8; 32]).unwrap().is_none());
    }

    /// Attachments are sealed with the database key and live outside the
    /// database, so a re-key that forgot them would turn every picture in the
    /// history into noise — and quietly, because an unsealable file is handed
    /// back as-is rather than reported.
    #[test]
    fn a_rekey_carries_the_attachments_too() {
        let tmp = TempDb::new();
        let files = tmp.0.with_extension("files");
        std::fs::create_dir_all(&files).unwrap();
        let mine = files.join("sent-aaaa-kotatko.gif");
        let theirs = files.join("sent-bbbb-jine.gif");

        let mut s = Store::open(&tmp.0, &[1u8; 32]).unwrap();
        s.put_secret("identity_seed", b"x").unwrap();
        s.encrypt_file(&mine, b"GIF89a pretend this is a picture").unwrap();
        // Another profile's attachment, sealed under a key we do not have.
        Store::open(&tmp.0, &[2u8; 32])
            .unwrap()
            .encrypt_file(&theirs, b"none of our business")
            .unwrap();
        let theirs_before = std::fs::read(&theirs).unwrap();

        s.rekey(&[9u8; 32], b"name", b"wrapped", Some(&files)).unwrap();

        let after = Store::open(&tmp.0, &[9u8; 32]).unwrap();
        assert_eq!(
            &*after.decrypt_file(&mine).unwrap(),
            b"GIF89a pretend this is a picture"
        );
        // Untouched, byte for byte, and still theirs.
        assert_eq!(std::fs::read(&theirs).unwrap(), theirs_before);
        assert_eq!(
            &*Store::open(&tmp.0, &[2u8; 32]).unwrap().decrypt_file(&theirs).unwrap(),
            b"none of our business"
        );
        // No half-finished work left lying about.
        assert!(!files.join("sent-aaaa-kotatko.gif.rekey-tmp").exists());
        let _ = std::fs::remove_dir_all(files);
    }

    /// A prepared copy is only adopted when it opens under the key the store
    /// actually ended up with. One left by an attempt that rolled back must be
    /// thrown away, not swapped in over a perfectly good file.
    #[test]
    fn an_abandoned_attempt_does_not_eat_the_file() {
        let tmp = TempDb::new();
        let files = tmp.0.with_extension("files2");
        std::fs::create_dir_all(&files).unwrap();
        let real = files.join("photo.jpg");

        let s = Store::open(&tmp.0, &[1u8; 32]).unwrap();
        s.encrypt_file(&real, b"the real picture").unwrap();
        // As if a conversion had prepared this and then failed.
        std::fs::write(
            files.join("photo.jpg.rekey-tmp"),
            seal_with(&[9u8; 32], b"from a key nobody adopted").unwrap(),
        )
        .unwrap();

        s.finish_file_rekey(&files);
        assert!(!files.join("photo.jpg.rekey-tmp").exists());
        assert_eq!(&*s.decrypt_file(&real).unwrap(), b"the real picture");
        let _ = std::fs::remove_dir_all(files);
    }

    /// The wrapped key is written under the exact name it was given, unsealed —
    /// it is the one row that cannot be sealed under the key it protects.
    #[test]
    fn the_wrapped_key_is_stored_verbatim() {
        let tmp = TempDb::new();
        let mut s = Store::open(&tmp.0, &[1u8; 32]).unwrap();
        s.put_secret("identity_seed", b"x").unwrap();
        s.rekey(&[9u8; 32], b"the name", b"the wrapped bytes", None).unwrap();

        let found = stored_secrets(&tmp.0).unwrap();
        assert!(found
            .iter()
            .any(|(name, value)| name == b"the name" && value == b"the wrapped bytes"));
    }

    /// Someone who wrote first, and whom the user then accepted, belongs in the
    /// address book — and a later decision to drop them has to stick.
    #[test]
    fn accepting_someone_puts_them_in_the_address_book() {
        let tmp = TempDb::new();
        let s = Store::open(&tmp.0, &[1u8; 32]).unwrap();

        // Two people who wrote to us first: one accepted, one still waiting.
        for (pk, status) in [([0xAAu8; 32], ContactStatus::Accepted), ([0xBBu8; 32], ContactStatus::Waiting)] {
            s.upsert_contact(&Contact {
                identity_pubkey: pk,
                display_name: "Kdosi".into(),
                onion_addr: String::new(),
                added_at: 1,
                status,
                saved: false,
                verified: false,
                pq_fingerprint: None,
            })
            .unwrap();
        }

        assert_eq!(s.save_accepted_contacts().unwrap(), 1);
        assert!(s.get_contact(&[0xAAu8; 32]).unwrap().unwrap().saved);
        // Waiting is a decision nobody has made yet, so it is not one to record.
        assert!(!s.get_contact(&[0xBBu8; 32]).unwrap().unwrap().saved);

        // Once. Otherwise "forget this person" would come undone at every start.
        s.set_contact_saved(&[0xAAu8; 32], false).unwrap();
        assert_eq!(s.save_accepted_contacts().unwrap(), 0);
        assert!(!s.get_contact(&[0xAAu8; 32]).unwrap().unwrap().saved);
    }

    #[test]
    fn a_reply_remembers_what_it_answers() {
        let tmp = TempDb::new();
        let s = Store::open(&tmp.0, &[1u8; 32]).unwrap();
        let peer = [0xAAu8; 32];
        let original = crate::envelope::message_ref(&peer, b"co delas?");
        s.insert_message(&NewMessage {
            contact_pubkey: peer,
            direction: Direction::Incoming,
            sent_at: 10,
            body: b"co delas?",
            file: None,
            msg_ref: Some(original),
            reply_to: None,
        })
        .unwrap();
        s.insert_message(&NewMessage {
            contact_pubkey: peer,
            direction: Direction::Outgoing,
            sent_at: 11,
            body: b"nic",
            file: None,
            msg_ref: None,
            reply_to: Some(original),
        })
        .unwrap();

        let thread = s.messages_for(&peer, 10).unwrap();
        assert_eq!(thread[0].reply_to, None);
        assert_eq!(thread[1].reply_to, Some(original));
        // And the reference resolves to the message it stands for, which is
        // what draws the quote.
        let quoted = s.message_by_ref(&original).unwrap().unwrap();
        assert_eq!(quoted.body, b"co delas?");

        // A reference is a digest of the plaintext, so it must not be sitting in
        // the file in the clear — that would be a way to confirm a guess at what
        // was said without the passphrase.
        let raw: Vec<Vec<u8>> = {
            let mut stmt = s.conn.prepare("SELECT reply_to FROM messages WHERE reply_to IS NOT NULL").unwrap();
            let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0)).unwrap();
            rows.map(|r| r.unwrap()).collect()
        };
        assert_eq!(raw.len(), 1);
        assert_ne!(raw[0].as_slice(), &original[..]);
    }

    #[test]
    fn a_reaction_is_one_per_person_and_can_be_taken_back() {
        let tmp = TempDb::new();
        let s = Store::open(&tmp.0, &[1u8; 32]).unwrap();
        let msg = crate::envelope::message_ref(&[0xAAu8; 32], b"neco");
        let me = [1u8; 32];
        let them = [2u8; 32];

        s.set_reaction(&msg, &me, "👍", 1).unwrap();
        s.set_reaction(&msg, &them, "🔥", 2).unwrap();
        assert_eq!(s.reactions_for(&msg).unwrap().len(), 2);

        // Reacting again replaces rather than piles up.
        s.set_reaction(&msg, &me, "😂", 3).unwrap();
        let now = s.reactions_for(&msg).unwrap();
        assert_eq!(now.len(), 2);
        assert!(now.iter().any(|(e, w)| e == "😂" && *w == me));
        assert!(!now.iter().any(|(e, _)| e == "👍"));

        // Empty takes mine off and leaves theirs alone.
        s.set_reaction(&msg, &me, "", 4).unwrap();
        let left = s.reactions_for(&msg).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0], ("🔥".to_string(), them));
    }

    /// Two passphrases, one file, neither able to see the other.
    #[test]
    fn a_second_passphrase_gets_its_own_separate_history() {
        let tmp = TempDb::new();
        let real_key = [1u8; 32];
        let decoy_key = [2u8; 32];

        {
            let real = Store::open(&tmp.0, &real_key).unwrap();
            real.set_profile_kind(ProfileKind::Normal).unwrap();
            real.put_secret("identity_seed", b"the real identity").unwrap();
            real.upsert_contact(&Contact {
                identity_pubkey: [0xAAu8; 32],
                display_name: "Skutecny kontakt".into(),
                onion_addr: "real.onion".into(),
                added_at: 1,
                status: ContactStatus::Accepted,
                saved: true,
                verified: true,
                pq_fingerprint: None,
            })
            .unwrap();
            real.insert_message(&NewMessage {
                contact_pubkey: [0xAAu8; 32],
                direction: Direction::Incoming,
                sent_at: 10,
                body: b"neco co nikdo nema videt",
                msg_ref: None,
                reply_to: None,
                file: None,
            })
            .unwrap();
        }
        {
            let decoy = Store::open(&tmp.0, &decoy_key).unwrap();
            decoy.set_profile_kind(ProfileKind::Decoy).unwrap();
            decoy.put_secret("identity_seed", b"a different identity").unwrap();
            decoy.upsert_contact(&Contact {
                identity_pubkey: [0xBBu8; 32],
                display_name: "Nastraceny kontakt".into(),
                onion_addr: "decoy.onion".into(),
                added_at: 2,
                status: ContactStatus::Accepted,
                saved: true,
                verified: false,
                pq_fingerprint: None,
            })
            .unwrap();
        }

        // Each side sees exactly its own, and nothing suggests the other.
        let real = Store::open(&tmp.0, &real_key).unwrap();
        let seen = real.list_contacts().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].display_name, "Skutecny kontakt");
        assert_eq!(real.profile_kind(), ProfileKind::Normal);
        assert_eq!(&*real.get_secret("identity_seed").unwrap().unwrap(), b"the real identity");
        assert_eq!(real.search_messages("nikdo", 10).unwrap().len(), 1);

        let decoy = Store::open(&tmp.0, &decoy_key).unwrap();
        let seen = decoy.list_contacts().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].display_name, "Nastraceny kontakt");
        assert_eq!(decoy.profile_kind(), ProfileKind::Decoy);
        assert_eq!(&*decoy.get_secret("identity_seed").unwrap().unwrap(), b"a different identity");
        // The real conversation is not merely hidden from the UI — it cannot be
        // found by searching either.
        assert!(decoy.search_messages("nikdo", 10).unwrap().is_empty());
        assert!(decoy.message_peers().unwrap().is_empty());
    }

    /// An attachment on disk must not be readable without the passphrase, and
    /// one written by an older version must still open.
    #[test]
    fn attachments_are_sealed_but_old_ones_still_open() {
        let dir = std::env::temp_dir().join(format!("nc-files-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let s = Store::open_in_memory(&[11u8; 32]).unwrap();

        let secret = b"a photograph somebody sent in confidence";
        let sealed = dir.join("photo.png");
        s.encrypt_file(&sealed, secret).unwrap();

        // On disk it is not the file any more.
        let raw = std::fs::read(&sealed).unwrap();
        assert_ne!(raw.as_slice(), secret);
        assert!(
            !raw.windows(secret.len()).any(|w| w == secret),
            "the attachment is still readable on disk"
        );
        assert!(s.file_is_encrypted(&sealed));
        assert_eq!(&*s.decrypt_file(&sealed).unwrap(), secret);

        // Another passphrase cannot read it.
        let other = Store::open_in_memory(&[12u8; 32]).unwrap();
        assert_ne!(&*other.decrypt_file(&sealed).unwrap(), secret);

        // A file from before this existed is returned unchanged rather than
        // treated as corrupt — otherwise updating would lose it.
        let legacy = dir.join("old.txt");
        std::fs::write(&legacy, b"plain old attachment").unwrap();
        assert!(!s.file_is_encrypted(&legacy));
        assert_eq!(&*s.decrypt_file(&legacy).unwrap(), b"plain old attachment");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deleting_a_contact_takes_the_conversation_with_it() {
        let s = Store::open_in_memory(&[4u8; 32]).unwrap();
        let a = sample_contact();
        let b = Contact { identity_pubkey: [8u8; 32], ..sample_contact() };
        s.upsert_contact(&a).unwrap();
        s.upsert_contact(&b).unwrap();
        for who in [a.identity_pubkey, b.identity_pubkey] {
            s.insert_message(&NewMessage {
                contact_pubkey: who,
                direction: Direction::Incoming,
                sent_at: 1,
                body: b"hello",
                msg_ref: None,
                reply_to: None,
                file: None,
            })
            .unwrap();
        }
        s.queue_outgoing(&a.identity_pubkey, 1, None, b"frame", b"hello", 1).unwrap();

        assert_eq!(s.delete_contact(&a.identity_pubkey).unwrap(), 1);
        assert!(s.get_contact(&a.identity_pubkey).unwrap().is_none());
        assert!(s.messages_for(&a.identity_pubkey, 10).unwrap().is_empty());
        assert!(s.outbox_for(&a.identity_pubkey).unwrap().is_empty());

        // The other conversation is untouched — deleting one must not take a
        // neighbour with it.
        assert!(s.get_contact(&b.identity_pubkey).unwrap().is_some());
        assert_eq!(s.messages_for(&b.identity_pubkey, 10).unwrap().len(), 1);
    }

    /// A database from 1.7.x — routing columns already converted, secret names
    /// still in the clear — must still find its identity.
    ///
    /// This is the bug that shipped in 2.0.0 and 2.0.1. The name conversion was
    /// added inside the blind-index migration, which only runs when its mark is
    /// missing; every 1.7.x database already had that mark, so the names were
    /// never converted, `identity_seed` was never found, and the app told
    /// people their passphrase was wrong while their account sat there intact.
    #[test]
    fn an_account_with_plaintext_secret_names_still_opens() {
        let tmp = TempDb::new();
        let key = [0x5Au8; 32];

        {
            // Build the 1.7.x shape by hand: sealed values under *plain* names,
            // and the blind-index mark already present.
            let conn = rusqlite::Connection::open(&tmp.0).unwrap();
            conn.execute_batch(SCHEMA).unwrap();
            let helper = Store {
                conn: rusqlite::Connection::open(&tmp.0).unwrap(),
                key: Zeroizing::new(key),
                index_key: Zeroizing::new(derive_index_key(&key)),
            };
            for (name, value) in [
                ("identity_seed", &b"a real identity seed here!!!!!!!"[..]),
                ("username", b"lukas"),
            ] {
                conn.execute(
                    "INSERT INTO secrets(name, value) VALUES(?1, ?2)",
                    params![name, helper.seal(value).unwrap()],
                )
                .unwrap();
            }
            conn.execute(
                "INSERT INTO secrets(name, value) VALUES(?1, ?2)",
                params![BLIND_INDEX_MARK, helper.seal(b"1").unwrap()],
            )
            .unwrap();
        }

        // Opening must find both, convert them, and leave the account usable.
        let s = Store::open(&tmp.0, &key).unwrap();
        assert_eq!(
            &*s.get_secret("identity_seed").unwrap().unwrap(),
            b"a real identity seed here!!!!!!!",
            "the identity seed must be found, or the app reports a wrong passphrase"
        );
        assert_eq!(&*s.get_secret("username").unwrap().unwrap(), b"lukas");

        // And after conversion the names are no longer readable in the file.
        drop(s);
        let raw = std::fs::read(&tmp.0).unwrap();
        assert!(
            !raw.windows(b"identity_seed".len()).any(|w| w == b"identity_seed"),
            "the name should have been converted to a blind index"
        );

        // Reopening still works, and does not convert a second time.
        let s = Store::open(&tmp.0, &key).unwrap();
        assert_eq!(
            &*s.get_secret("identity_seed").unwrap().unwrap(),
            b"a real identity seed here!!!!!!!"
        );
    }

    /// A duress passphrase destroys what it cannot read, and the file keeps its
    /// size and shape so the destruction does not announce itself.
    #[test]
    fn a_duress_passphrase_destroys_the_real_history_in_place() {
        let tmp = TempDb::new();
        let real_key = [3u8; 32];
        let panic_key = [4u8; 32];

        {
            let real = Store::open(&tmp.0, &real_key).unwrap();
            real.put_secret("identity_seed", b"real seed").unwrap();
            for i in 0..20 {
                real.insert_message(&NewMessage {
                    contact_pubkey: [0xCCu8; 32],
                    direction: Direction::Incoming,
                    sent_at: i,
                    body: b"tajna zprava ktera musi zmizet",
                    msg_ref: None,
                    reply_to: None,
                    file: None,
                })
                .unwrap();
            }
        }
        let before = std::fs::metadata(&tmp.0).unwrap().len();
        let rows_before: i64 = {
            let s = Store::open(&tmp.0, &panic_key).unwrap();
            s.conn
                .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
                .unwrap()
        };

        {
            let duress = Store::open(&tmp.0, &panic_key).unwrap();
            duress.set_profile_kind(ProfileKind::Wipe).unwrap();
            let destroyed = duress.destroy_unreadable().unwrap();
            assert!(destroyed >= 20, "expected the real rows to be overwritten");
        }

        // Gone for good: the right passphrase no longer recovers anything.
        let real = Store::open(&tmp.0, &real_key).unwrap();
        assert!(real.list_contacts().unwrap().is_empty());
        assert!(real.search_messages("tajna", 10).unwrap().is_empty());
        assert!(real.get_secret("identity_seed").unwrap().is_none());

        // …and the file still looks like a database in use, not like one that
        // has just been emptied: same rows, same size.
        let after = std::fs::metadata(&tmp.0).unwrap().len();
        let rows_after: i64 = real
            .conn
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows_after, rows_before, "row count changed — the wipe is visible");
        assert_eq!(after, before, "file size changed — the wipe is visible");
    }

    #[test]
    fn routing_columns_hold_no_identity_key() {
        let tmp = TempDb::new();
        let key = [9u8; 32];
        let peer = [0xABu8; 32];
        let gid = [0xCDu8; 16];
        {
            let s = Store::open(&tmp.0, &key).unwrap();
            s.upsert_contact(&Contact {
                identity_pubkey: peer,
                display_name: "Alice".into(),
                onion_addr: "abc.onion".into(),
                added_at: 1,
                status: ContactStatus::Accepted,
                saved: true,
                verified: false,
                pq_fingerprint: None,
            })
            .unwrap();
            s.insert_message(&NewMessage {
                contact_pubkey: peer,
                direction: Direction::Outgoing,
                sent_at: 2,
                body: b"ahoj",
                msg_ref: None,
                reply_to: None,
                file: None,
            })
            .unwrap();
            s.upsert_group(&Group {
                id: gid,
                name: "Parta".into(),
                version: 1,
                created_at: 3,
                members: vec![GroupMember {
                    identity: peer,
                    display_name: "Alice".into(),
                    onion: "abc.onion".into(),
                }],
            })
            .unwrap();
            s.queue_outgoing(&peer, 1, Some(gid), b"frame", b"ahoj", 4).unwrap();
        }

        // The file on disk must not contain the identity key or the group id
        // anywhere — not in a routing column, not in an index.
        let raw = std::fs::read(&tmp.0).unwrap();
        assert!(
            !raw.windows(peer.len()).any(|w| w == peer),
            "the identity key is still somewhere in the database file"
        );
        assert!(
            !raw.windows(gid.len()).any(|w| w == gid),
            "the group id is still somewhere in the database file"
        );

        // And with the right key everything still reads back.
        let s = Store::open(&tmp.0, &key).unwrap();
        assert_eq!(s.list_contacts().unwrap()[0].identity_pubkey, peer);
        assert_eq!(s.messages_for(&peer, 10).unwrap().len(), 1);
        assert_eq!(s.group_members(&gid).unwrap()[0].identity, peer);
        assert_eq!(s.outbox_summary().unwrap(), vec![(peer, 1)]);
        assert_eq!(s.outbox_for(&peer).unwrap()[0].group_id, Some(gid));
        assert_eq!(s.message_peers().unwrap(), vec![peer]);
    }

    /// A database written by an older NullChat opens, converts itself, and keeps
    /// every row reachable by the same lookups as before.
    #[test]
    fn an_old_database_is_converted_on_open() {
        let tmp = TempDb::new();
        let key = [3u8; 32];
        let peer = [0x11u8; 32];
        let gid = [0x22u8; 16];
        {
            // Write the pre-blind-index shape by hand: raw values in the
            // routing columns, no marker.
            let conn = rusqlite::Connection::open(&tmp.0).unwrap();
            conn.execute_batch(SCHEMA).unwrap();
            let helper = Store {
                conn: rusqlite::Connection::open(&tmp.0).unwrap(),
                key: Zeroizing::new(key),
                index_key: Zeroizing::new(derive_index_key(&key)),
            };
            let name = helper.seal(b"Bob").unwrap();
            let onion = helper.seal(b"xyz.onion").unwrap();
            let body = helper.seal(b"stara zprava").unwrap();
            let gname = helper.seal(b"Stara parta").unwrap();
            conn.execute(
                "INSERT INTO contacts(identity_pubkey, display_name, onion_addr, added_at, status, saved)
                 VALUES(?1, ?2, ?3, 1, 1, 1)",
                params![peer.as_slice(), name, onion],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO messages(contact_pubkey, direction, sent_at, body)
                 VALUES(?1, 0, 5, ?2)",
                params![peer.as_slice(), body],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO groups(group_id, name, version, created_at) VALUES(?1, ?2, 1, 6)",
                params![gid.as_slice(), gname],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO group_members(group_id, member_pubkey, display_name, onion_addr)
                 VALUES(?1, ?2, ?3, ?4)",
                params![gid.as_slice(), peer.as_slice(), helper.seal(b"Bob").unwrap(), helper.seal(b"xyz.onion").unwrap()],
            )
            .unwrap();
        }

        let s = Store::open(&tmp.0, &key).unwrap();
        assert_eq!(s.get_contact(&peer).unwrap().unwrap().display_name, "Bob");
        assert_eq!(s.messages_for(&peer, 10).unwrap().len(), 1);
        assert_eq!(s.get_group(&gid).unwrap().unwrap().name, "Stara parta");
        assert_eq!(s.group_members(&gid).unwrap()[0].identity, peer);
        drop(s);

        // The raw values are gone from the file, and a second open is a no-op.
        let raw = std::fs::read(&tmp.0).unwrap();
        assert!(!raw.windows(peer.len()).any(|w| w == peer));

        // The pre-conversion copy is there, so a botched upgrade is survivable.
        let backup = tmp.0.with_extension("db.pre-blind-index.bak");
        assert!(backup.exists(), "no backup was taken before converting");
        let old = std::fs::read(&backup).unwrap();
        assert!(
            old.windows(peer.len()).any(|w| w == peer),
            "the backup should still be the old, unconverted file"
        );
        let _ = std::fs::remove_file(&backup);
        let s = Store::open(&tmp.0, &key).unwrap();
        assert_eq!(s.get_contact(&peer).unwrap().unwrap().display_name, "Bob");
    }

    /// Converting with the wrong key would compute indexes that can never be
    /// matched again, so it must refuse rather than damage the file.
    #[test]
    fn an_old_database_is_not_converted_with_the_wrong_key() {
        let tmp = TempDb::new();
        let peer = [0x44u8; 32];
        {
            let conn = rusqlite::Connection::open(&tmp.0).unwrap();
            conn.execute_batch(SCHEMA).unwrap();
            let helper = Store {
                conn: rusqlite::Connection::open(&tmp.0).unwrap(),
                key: Zeroizing::new([1u8; 32]),
                index_key: Zeroizing::new(derive_index_key(&[1u8; 32])),
            };
            conn.execute(
                "INSERT INTO contacts(identity_pubkey, display_name, onion_addr, added_at, status, saved)
                 VALUES(?1, ?2, ?3, 1, 1, 1)",
                params![peer.as_slice(), helper.seal(b"Bob").unwrap(), helper.seal(b"o.onion").unwrap()],
            )
            .unwrap();
        }

        assert_eq!(Store::open(&tmp.0, &[2u8; 32]).err(), Some(StoreError::Corrupt));
        // Untouched: the right key still converts it later.
        let s = Store::open(&tmp.0, &[1u8; 32]).unwrap();
        assert_eq!(s.get_contact(&peer).unwrap().unwrap().display_name, "Bob");
    }
}
