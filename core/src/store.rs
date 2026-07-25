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
//! Consequence, stated plainly (see `docs/THREAT_MODEL.md`): message *bodies*,
//! contact names, onion addresses and all secrets are ciphertext at rest, but
//! **routing columns are plaintext** — a disk image reveals which contact keys
//! exist, how many messages, and their timestamps. Closing that needs whole-DB
//! encryption, tracked as future hardening.
//!
//! The data key itself is expected to be a random key sealed under the user
//! passphrase via [`crate::crypto::keystore`]; this module just consumes the
//! raw key.

use crate::error::StoreError;
use crate::group::{Group, GroupMember};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use zeroize::Zeroizing;

const NONCE_LEN: usize = 24;

const SCHEMA: &str = "
PRAGMA secure_delete = ON;
CREATE TABLE IF NOT EXISTS secrets (
    name  TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS contacts (
    identity_pubkey BLOB PRIMARY KEY,   -- 32 bytes, plaintext (lookup key)
    display_name    BLOB NOT NULL,      -- sealed
    onion_addr      BLOB NOT NULL,      -- sealed
    added_at        INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    contact_pubkey BLOB NOT NULL,       -- 32 bytes, plaintext (query/order)
    direction      INTEGER NOT NULL,    -- 0 = incoming, 1 = outgoing
    sent_at        INTEGER NOT NULL,    -- plaintext (ordering)
    body           BLOB NOT NULL        -- sealed
);
CREATE INDEX IF NOT EXISTS idx_messages_contact
    ON messages(contact_pubkey, sent_at);
CREATE TABLE IF NOT EXISTS groups (
    group_id   BLOB PRIMARY KEY,        -- 16 bytes, plaintext (lookup key)
    name       BLOB NOT NULL,           -- sealed
    version    INTEGER NOT NULL,        -- roster version (plaintext, ordering)
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS group_members (
    group_id      BLOB NOT NULL,        -- 16 bytes, plaintext
    member_pubkey BLOB NOT NULL,        -- 32 bytes, plaintext (routing)
    display_name  BLOB NOT NULL,        -- sealed
    onion_addr    BLOB NOT NULL,        -- sealed
    PRIMARY KEY (group_id, member_pubkey)
);
CREATE TABLE IF NOT EXISTS group_messages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id      BLOB NOT NULL,        -- 16 bytes, plaintext (query/order)
    sender_pubkey BLOB NOT NULL,        -- 32 bytes, plaintext (who wrote it)
    direction     INTEGER NOT NULL,     -- 0 = incoming, 1 = outgoing
    sent_at       INTEGER NOT NULL,     -- plaintext (ordering)
    body          BLOB NOT NULL         -- sealed
);
CREATE INDEX IF NOT EXISTS idx_group_messages
    ON group_messages(group_id, sent_at);
";

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
}

/// The encrypted local store.
pub struct Store {
    conn: Connection,
    key: Zeroizing<[u8; 32]>,
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
        Ok(Self { conn, key: Zeroizing::new(*data_key) })
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
    pub fn put_secret(&self, name: &str, plaintext: &[u8]) -> Result<(), StoreError> {
        let value = self.seal(plaintext)?;
        self.conn.execute(
            "INSERT INTO secrets(name, value) VALUES(?1, ?2)
             ON CONFLICT(name) DO UPDATE SET value = excluded.value",
            params![name, value],
        )?;
        Ok(())
    }

    /// Fetch a named secret, or `None` if absent.
    pub fn get_secret(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        let blob: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT value FROM secrets WHERE name = ?1", params![name], |r| r.get(0))
            .optional()?;
        match blob {
            Some(b) => Ok(Some(self.unseal(&b)?)),
            None => Ok(None),
        }
    }

    // --- contacts ---

    /// Insert or update a contact.
    pub fn upsert_contact(&self, c: &Contact) -> Result<(), StoreError> {
        let name = self.seal(c.display_name.as_bytes())?;
        let onion = self.seal(c.onion_addr.as_bytes())?;
        self.conn.execute(
            "INSERT INTO contacts(identity_pubkey, display_name, onion_addr, added_at)
             VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(identity_pubkey) DO UPDATE SET
                 display_name = excluded.display_name,
                 onion_addr   = excluded.onion_addr",
            params![c.identity_pubkey.as_slice(), name, onion, c.added_at as i64],
        )?;
        Ok(())
    }

    /// Fetch a contact by identity key.
    pub fn get_contact(&self, identity_pubkey: &[u8; 32]) -> Result<Option<Contact>, StoreError> {
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = self
            .conn
            .query_row(
                "SELECT display_name, onion_addr, added_at FROM contacts WHERE identity_pubkey = ?1",
                params![identity_pubkey.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((name_ct, onion_ct, added)) => Ok(Some(Contact {
                identity_pubkey: *identity_pubkey,
                display_name: self.decrypt_string(&name_ct)?,
                onion_addr: self.decrypt_string(&onion_ct)?,
                added_at: added as u64,
            })),
        }
    }

    /// List all contacts, newest first.
    pub fn list_contacts(&self) -> Result<Vec<Contact>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT identity_pubkey, display_name, onion_addr, added_at
             FROM contacts ORDER BY added_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (pk, name_ct, onion_ct, added) = row?;
            out.push(Contact {
                identity_pubkey: to_key32(&pk)?,
                display_name: self.decrypt_string(&name_ct)?,
                onion_addr: self.decrypt_string(&onion_ct)?,
                added_at: added as u64,
            });
        }
        Ok(out)
    }

    // --- messages ---

    /// Append a message, returning its row id.
    pub fn insert_message(&self, m: &NewMessage) -> Result<i64, StoreError> {
        let body = self.seal(m.body)?;
        self.conn.execute(
            "INSERT INTO messages(contact_pubkey, direction, sent_at, body)
             VALUES(?1, ?2, ?3, ?4)",
            params![m.contact_pubkey.as_slice(), m.direction.to_i64(), m.sent_at as i64, body],
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
            "SELECT id, direction, sent_at, body FROM messages
             WHERE contact_pubkey = ?1 ORDER BY sent_at ASC, id ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![contact_pubkey.as_slice(), limit], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, dir, sent_at, body_ct) = row?;
            out.push(Message {
                id,
                contact_pubkey: *contact_pubkey,
                direction: Direction::from_i64(dir)?,
                sent_at: sent_at as u64,
                body: self.unseal(&body_ct)?.to_vec(),
            });
        }
        Ok(out)
    }

    /// Every identity we have exchanged messages with, contact or not.
    pub fn message_peers(&self) -> Result<Vec<[u8; 32]>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT contact_pubkey FROM messages")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(to_key32(&row?)?);
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
        self.conn.execute(
            "INSERT INTO groups(group_id, name, version, created_at)
             VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(group_id) DO UPDATE SET
                 name    = excluded.name,
                 version = excluded.version",
            params![g.id.as_slice(), name, g.version as i64, g.created_at as i64],
        )?;
        self.conn
            .execute("DELETE FROM group_members WHERE group_id = ?1", params![g.id.as_slice()])?;
        for m in &g.members {
            let member_name = self.seal(m.display_name.as_bytes())?;
            let onion = self.seal(m.onion.as_bytes())?;
            self.conn.execute(
                "INSERT INTO group_members(group_id, member_pubkey, display_name, onion_addr)
                 VALUES(?1, ?2, ?3, ?4)",
                params![g.id.as_slice(), m.identity.as_slice(), member_name, onion],
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
                params![group_id.as_slice()],
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
        let rows = stmt.query_map(params![group_id.as_slice()], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (pk, name_ct, onion_ct) = row?;
            out.push(GroupMember {
                identity: to_key32(&pk)?,
                display_name: self.decrypt_string(&name_ct)?,
                onion: self.decrypt_string(&onion_ct)?,
            });
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
            let gid: [u8; 16] = id.as_slice().try_into().map_err(|_| StoreError::Corrupt)?;
            if let Some(g) = self.get_group(&gid)? {
                out.push(g);
            }
        }
        Ok(out)
    }

    /// Forget a group: its roster and its whole history.
    pub fn delete_group(&self, group_id: &[u8; 16]) -> Result<(), StoreError> {
        self.conn
            .execute("DELETE FROM group_messages WHERE group_id = ?1", params![group_id.as_slice()])?;
        self.conn
            .execute("DELETE FROM group_members WHERE group_id = ?1", params![group_id.as_slice()])?;
        self.conn
            .execute("DELETE FROM groups WHERE group_id = ?1", params![group_id.as_slice()])?;
        Ok(())
    }

    /// Append a group message, returning its row id.
    pub fn insert_group_message(&self, m: &NewGroupMessage) -> Result<i64, StoreError> {
        let body = self.seal(m.body)?;
        self.conn.execute(
            "INSERT INTO group_messages(group_id, sender_pubkey, direction, sent_at, body)
             VALUES(?1, ?2, ?3, ?4, ?5)",
            params![
                m.group_id.as_slice(),
                m.sender_pubkey.as_slice(),
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
        let rows = stmt.query_map(params![group_id.as_slice(), limit], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, Vec<u8>>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, sender, dir, sent_at, body_ct) = row?;
            out.push(GroupMessage {
                id,
                group_id: *group_id,
                sender_pubkey: to_key32(&sender)?,
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
            let name = format!("umbra-test-{}.sqlite", u64::from_le_bytes(b));
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
        }
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

    /// The bug this guards against: a peer who wrote to us first had messages
    /// but no contact row, so the whole thread vanished on restart.
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
        // Reopen with a different data key: the row exists but won't decrypt.
        let s = Store::open(&tmp.0, &[6u8; 32]).unwrap();
        assert_eq!(s.list_contacts(), Err(StoreError::Corrupt));
        assert_eq!(s.get_contact(&[7u8; 32]), Err(StoreError::Corrupt));
    }
}
