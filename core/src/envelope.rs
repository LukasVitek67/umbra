// SPDX-License-Identifier: AGPL-3.0-or-later
//! Typed payloads carried *inside* the encrypted session.
//!
//! Everything here travels through [`umbra_transport::Session`], so it is
//! already end-to-end encrypted, authenticated, length-padded and onion-routed
//! before it hits the network. This module only decides what the bytes *mean*:
//! plain text, a profile (name + picture), or a file split into chunks.
//!
//! ```text
//! byte 0 = kind
//!   0 TEXT     utf-8 body
//!   1 PROFILE  name_len(u16) ‖ name ‖ picture bytes
//!   2 FILE_OFFER  id(16) ‖ name_len(u16) ‖ name ‖ size(u64)
//!   3 FILE_CHUNK  id(16) ‖ seq(u32) ‖ data
//!   4 FILE_END    id(16)
//!   5 GROUP_TEXT  gid(16) ‖ utf-8 body
//!   6 GROUP_INFO  gid(16) ‖ version(u32) ‖ name_len(u16) ‖ name
//!                 ‖ member_count(u16) ‖ member*
//!       member =  identity(32) ‖ name_len(u16) ‖ name ‖ onion_len(u16) ‖ onion
//! ```
//!
//! The two group kinds are the whole group protocol: `GROUP_TEXT` is a message
//! fanned out to every member over their own 1:1 session, `GROUP_INFO` is the
//! shared roster (see [`crate::group`]) and doubles as the invitation.
//!
//! Chunks stay well under the transport's 1 MiB frame cap. A file's bytes never
//! touch disk unencrypted on the way through: they are read, encrypted, sent,
//! and only written out once the receiver reassembles them locally.

use crate::group::{Group, GroupMember};

/// Largest slice of a file we put in one message.
pub const CHUNK: usize = 48 * 1024;

pub const TEXT: u8 = 0;
pub const PROFILE: u8 = 1;
pub const FILE_OFFER: u8 = 2;
pub const FILE_CHUNK: u8 = 3;
pub const FILE_END: u8 = 4;
pub const GROUP_TEXT: u8 = 5;
pub const GROUP_INFO: u8 = 6;

/// A decoded incoming payload.
pub enum Payload {
    Text(String),
    Profile { name: String, picture: Vec<u8> },
    FileOffer { id: [u8; 16], name: String, size: u64 },
    FileChunk { id: [u8; 16], seq: u32, data: Vec<u8> },
    FileEnd { id: [u8; 16] },
    GroupText { group_id: [u8; 16], text: String },
    /// A group roster. `created_at` is not on the wire — the receiver stamps
    /// its own arrival time, so a peer cannot rewrite our history.
    GroupInfo { group: Group },
}

pub fn encode_text(text: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + text.len());
    v.push(TEXT);
    v.extend_from_slice(text.as_bytes());
    v
}

pub fn encode_profile(name: &str, picture: &[u8]) -> Vec<u8> {
    let n = name.as_bytes();
    let mut v = Vec::with_capacity(3 + n.len() + picture.len());
    v.push(PROFILE);
    v.extend_from_slice(&(n.len() as u16).to_be_bytes());
    v.extend_from_slice(n);
    v.extend_from_slice(picture);
    v
}

pub fn encode_file_offer(id: &[u8; 16], name: &str, size: u64) -> Vec<u8> {
    let n = name.as_bytes();
    let mut v = Vec::with_capacity(1 + 16 + 2 + n.len() + 8);
    v.push(FILE_OFFER);
    v.extend_from_slice(id);
    v.extend_from_slice(&(n.len() as u16).to_be_bytes());
    v.extend_from_slice(n);
    v.extend_from_slice(&size.to_be_bytes());
    v
}

pub fn encode_file_chunk(id: &[u8; 16], seq: u32, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 16 + 4 + data.len());
    v.push(FILE_CHUNK);
    v.extend_from_slice(id);
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(data);
    v
}

pub fn encode_file_end(id: &[u8; 16]) -> Vec<u8> {
    let mut v = Vec::with_capacity(17);
    v.push(FILE_END);
    v.extend_from_slice(id);
    v
}

pub fn encode_group_text(group_id: &[u8; 16], text: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 16 + text.len());
    v.push(GROUP_TEXT);
    v.extend_from_slice(group_id);
    v.extend_from_slice(text.as_bytes());
    v
}

/// Serialise a roster. Only the shared facts travel: id, version, name and the
/// members — never our local timestamps.
pub fn encode_group_info(group: &Group) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    v.push(GROUP_INFO);
    v.extend_from_slice(&group.id);
    v.extend_from_slice(&group.version.to_be_bytes());
    push_str(&mut v, &group.name);
    let count = group.members.len().min(u16::MAX as usize) as u16;
    v.extend_from_slice(&count.to_be_bytes());
    for m in group.members.iter().take(count as usize) {
        v.extend_from_slice(&m.identity);
        push_str(&mut v, &m.display_name);
        push_str(&mut v, &m.onion);
    }
    v
}

fn push_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    let n = b.len().min(u16::MAX as usize);
    out.extend_from_slice(&(n as u16).to_be_bytes());
    out.extend_from_slice(&b[..n]);
}

/// Read a `len(u16) ‖ bytes` string, returning it and the rest of the buffer.
fn take_str(rest: &[u8]) -> Option<(String, &[u8])> {
    if rest.len() < 2 {
        return None;
    }
    let n = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    if rest.len() < 2 + n {
        return None;
    }
    Some((
        String::from_utf8_lossy(&rest[2..2 + n]).to_string(),
        &rest[2 + n..],
    ))
}

/// Decode a payload. Unknown kinds and truncated buffers return `None` rather
/// than guessing — a peer speaking a newer protocol must not corrupt our state.
pub fn decode(bytes: &[u8]) -> Option<Payload> {
    let (&kind, rest) = bytes.split_first()?;
    match kind {
        TEXT => Some(Payload::Text(String::from_utf8_lossy(rest).to_string())),
        PROFILE => {
            if rest.len() < 2 {
                return None;
            }
            let n = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            if rest.len() < 2 + n {
                return None;
            }
            Some(Payload::Profile {
                name: String::from_utf8_lossy(&rest[2..2 + n]).to_string(),
                picture: rest[2 + n..].to_vec(),
            })
        }
        FILE_OFFER => {
            if rest.len() < 16 + 2 {
                return None;
            }
            let id: [u8; 16] = rest[..16].try_into().ok()?;
            let n = u16::from_be_bytes([rest[16], rest[17]]) as usize;
            if rest.len() < 18 + n + 8 {
                return None;
            }
            let name = String::from_utf8_lossy(&rest[18..18 + n]).to_string();
            let size = u64::from_be_bytes(rest[18 + n..26 + n].try_into().ok()?);
            Some(Payload::FileOffer { id, name, size })
        }
        FILE_CHUNK => {
            if rest.len() < 16 + 4 {
                return None;
            }
            let id: [u8; 16] = rest[..16].try_into().ok()?;
            let seq = u32::from_be_bytes(rest[16..20].try_into().ok()?);
            Some(Payload::FileChunk { id, seq, data: rest[20..].to_vec() })
        }
        FILE_END => {
            let id: [u8; 16] = rest.get(..16)?.try_into().ok()?;
            Some(Payload::FileEnd { id })
        }
        GROUP_TEXT => {
            let group_id: [u8; 16] = rest.get(..16)?.try_into().ok()?;
            Some(Payload::GroupText {
                group_id,
                text: String::from_utf8_lossy(&rest[16..]).to_string(),
            })
        }
        GROUP_INFO => {
            let group_id: [u8; 16] = rest.get(..16)?.try_into().ok()?;
            let rest = &rest[16..];
            if rest.len() < 4 {
                return None;
            }
            let version = u32::from_be_bytes(rest[..4].try_into().ok()?);
            let (name, rest) = take_str(&rest[4..])?;
            if rest.len() < 2 {
                return None;
            }
            let count = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            let mut rest = &rest[2..];
            let mut members = Vec::with_capacity(count);
            for _ in 0..count {
                let identity: [u8; 32] = rest.get(..32)?.try_into().ok()?;
                let (display_name, r) = take_str(&rest[32..])?;
                let (onion, r) = take_str(r)?;
                rest = r;
                members.push(GroupMember { identity, display_name, onion });
            }
            Some(Payload::GroupInfo {
                group: Group {
                    id: group_id,
                    name,
                    version,
                    created_at: 0,
                    members,
                },
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::GroupMember;

    #[test]
    fn text_roundtrip() {
        let e = encode_text("ahoj 🦊");
        match decode(&e).unwrap() {
            Payload::Text(t) => assert_eq!(t, "ahoj 🦊"),
            _ => panic!("wrong kind"),
        }
    }

    #[test]
    fn file_offer_roundtrip() {
        let id = [7u8; 16];
        let e = encode_file_offer(&id, "tajný soubor.pdf", 123456);
        match decode(&e).unwrap() {
            Payload::FileOffer { id: i, name, size } => {
                assert_eq!(i, id);
                assert_eq!(name, "tajný soubor.pdf");
                assert_eq!(size, 123456);
            }
            _ => panic!("wrong kind"),
        }
    }

    #[test]
    fn chunk_roundtrip() {
        let id = [3u8; 16];
        let e = encode_file_chunk(&id, 42, &[1, 2, 3, 4]);
        match decode(&e).unwrap() {
            Payload::FileChunk { id: i, seq, data } => {
                assert_eq!(i, id);
                assert_eq!(seq, 42);
                assert_eq!(data, vec![1, 2, 3, 4]);
            }
            _ => panic!("wrong kind"),
        }
    }

    #[test]
    fn truncated_and_unknown_are_rejected() {
        assert!(decode(&[]).is_none());
        assert!(decode(&[FILE_OFFER, 1, 2, 3]).is_none());
        assert!(decode(&[250, 1, 2]).is_none());
        assert!(decode(&[GROUP_TEXT, 1, 2, 3]).is_none());
        assert!(decode(&[GROUP_INFO, 1, 2, 3]).is_none());
    }

    #[test]
    fn group_text_roundtrip() {
        let gid = [9u8; 16];
        match decode(&encode_group_text(&gid, "sraz v 18:00")).unwrap() {
            Payload::GroupText { group_id, text } => {
                assert_eq!(group_id, gid);
                assert_eq!(text, "sraz v 18:00");
            }
            _ => panic!("wrong kind"),
        }
    }

    #[test]
    fn group_info_roundtrip() {
        let group = Group {
            id: [4u8; 16],
            name: "Rodina 🏠".to_string(),
            version: 7,
            created_at: 12345, // local only — must not survive the wire
            members: vec![
                GroupMember {
                    identity: [1u8; 32],
                    display_name: "Lukáš".to_string(),
                    onion: "aaa.onion".to_string(),
                },
                GroupMember {
                    identity: [2u8; 32],
                    display_name: "Eva".to_string(),
                    onion: "bbb.onion".to_string(),
                },
            ],
        };
        match decode(&encode_group_info(&group)).unwrap() {
            Payload::GroupInfo { group: g } => {
                assert_eq!(g.id, group.id);
                assert_eq!(g.name, group.name);
                assert_eq!(g.version, 7);
                assert_eq!(g.created_at, 0);
                assert_eq!(g.members, group.members);
            }
            _ => panic!("wrong kind"),
        }
    }

    /// A roster whose member count promises more members than the buffer holds
    /// must be refused, not partially applied.
    #[test]
    fn group_info_with_a_lying_member_count_is_rejected() {
        let group = Group {
            id: [4u8; 16],
            name: "x".to_string(),
            version: 1,
            members: vec![GroupMember {
                identity: [1u8; 32],
                display_name: "a".to_string(),
                onion: "a.onion".to_string(),
            }],
            created_at: 0,
        };
        let mut bytes = encode_group_info(&group);
        // member_count sits right after gid(16) + version(4) + name(2+1).
        let count_at = 1 + 16 + 4 + 2 + group.name.len();
        bytes[count_at] = 0;
        bytes[count_at + 1] = 5;
        assert!(decode(&bytes).is_none());
    }
}
