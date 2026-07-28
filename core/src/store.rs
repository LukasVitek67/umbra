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
use rusqlite::{params, Connection, OptionalExtension};
use sha2::Sha256;
use std::path::Path;
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
}

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
        // Fully qualified: the AEAD in scope has a `new_from_slice` of its own.
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&*self.index_key)
            .expect("HMAC accepts a key of any length");
        mac.update(value);
        mac.finalize().into_bytes().to_vec()
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
        for (table, column) in [
            ("secrets", "value"),
            ("contacts", "display_name"),
            ("messages", "body"),
            ("groups", "name"),
        ] {
            let sealed: Option<Vec<u8>> = self
                .conn
                .query_row(&format!("SELECT {column} FROM {table} LIMIT 1"), [], |r| r.get(0))
                .optional()?;
            let Some(sealed) = sealed else { continue };
            return Ok(self.unseal(&sealed).is_ok());
        }
        Ok(true)
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

    /// Store a named secret (overwrites any existing value).
    ///
    /// The *name* is blind-indexed like every other lookup key, which is what
    /// lets two passphrases share one file without either being able to see
    /// that the other exists: the same name under a different key lands on a
    /// different row, and neither row says what it is for.
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
        let row: Option<(Vec<u8>, Vec<u8>, i64, i64, i64, i64, Option<Vec<u8>>)> = self
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

    /// List all contacts, newest first.
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
        let mut out = Vec::new();
        for (pk, name_ct, onion_ct, added, status, saved, verified, pq_ct) in found {
            // Rows belonging to another passphrase are skipped, not reported.
            let (Some(identity_pubkey), Some(display_name), Some(onion_addr)) = (
                self.try_key32_of(&pk),
                self.try_decrypt_string(&name_ct),
                self.try_decrypt_string(&onion_ct),
            ) else {
                continue;
            };
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
        self.conn.execute(
            "INSERT INTO messages(contact_pubkey, direction, sent_at, body)
             VALUES(?1, ?2, ?3, ?4)",
            params![bi, m.direction.to_i64(), m.sent_at as i64, body],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// The most recent `limit` messages with a contact, oldest first.
    pub fn messages_for(
        &self,
        contact_pubkey: &[u8; 32],
        limit: u32,
    ) -> Result<Vec<Message>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, direction, sent_at, body, state FROM messages
             WHERE contact_pubkey = ?1 ORDER BY sent_at ASC, id ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![self.bi(contact_pubkey), limit], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, dir, sent_at, body_ct, state) = row?;
            out.push(Message {
                id,
                contact_pubkey: *contact_pubkey,
                direction: Direction::from_i64(dir)?,
                sent_at: sent_at as u64,
                body: self.unseal(&body_ct)?.to_vec(),
                state: MessageState::from_i64(state),
            });
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
    pub fn outbox_summary(&self) -> Result<Vec<([u8; 32], u32)>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT peer_pubkey, COUNT(*) FROM outbox GROUP BY peer_pubkey")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)))?;
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

        hits.sort_by(|a, b| b.sent_at.cmp(&a.sent_at));
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

        hits.sort_by(|a, b| b.sent_at.cmp(&a.sent_at));
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
        let found: Vec<(i64, Vec<u8>, i64, i64, Vec<u8>)> = rows.collect::<Result<_, _>>()?;
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
        s.insert_message(&NewMessage { contact_pubkey: peer, direction: Direction::Outgoing, sent_at: 100, body: b"hi" }).unwrap();
        s.insert_message(&NewMessage { contact_pubkey: peer, direction: Direction::Incoming, sent_at: 101, body: b"hey" }).unwrap();
        // A message with a different peer must not show up.
        s.insert_message(&NewMessage { contact_pubkey: [1u8; 32], direction: Direction::Incoming, sent_at: 102, body: b"other" }).unwrap();

        let msgs = s.messages_for(&peer, 10).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].body, b"hi");
        assert_eq!(msgs[0].direction, Direction::Outgoing);
        assert_eq!(msgs[1].body, b"hey");
        assert_eq!(msgs[1].sent_at, 101);
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
        })
        .unwrap();
        s.insert_group_message(&NewGroupMessage {
            group_id: gid,
            sender_pubkey: peer,
            direction: Direction::Incoming,
            sent_at: 200,
            body: "Sraz az v utery".as_bytes(),
        })
        .unwrap();
        s.insert_message(&NewMessage {
            contact_pubkey: peer,
            direction: Direction::Outgoing,
            sent_at: 300,
            body: "necо jineho".as_bytes(),
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
        })
        .unwrap();
        // Our own reply must not show up as something they sent.
        s.insert_message(&NewMessage {
            contact_pubkey: them,
            direction: Direction::Outgoing,
            sent_at: 11,
            body: b"moje odpoved",
        })
        .unwrap();
        s.insert_group_message(&NewGroupMessage {
            group_id: [7u8; 16],
            sender_pubkey: them,
            direction: Direction::Incoming,
            sent_at: 12,
            body: b"od nich ve skupine",
        })
        .unwrap();
        s.insert_group_message(&NewGroupMessage {
            group_id: [7u8; 16],
            sender_pubkey: someone_else,
            direction: Direction::Incoming,
            sent_at: 13,
            body: b"od nekoho jineho",
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
        })
        .unwrap();
        s.insert_group_message(&NewGroupMessage {
            group_id: gid,
            sender_pubkey: [2u8; 32],
            direction: Direction::Incoming,
            sent_at: 101,
            body: b"cau",
        })
        .unwrap();
        // Another group's message must not leak in.
        s.insert_group_message(&NewGroupMessage {
            group_id: [9u8; 16],
            sender_pubkey: [3u8; 32],
            direction: Direction::Incoming,
            sent_at: 102,
            body: b"jinde",
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
