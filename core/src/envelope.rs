// SPDX-License-Identifier: AGPL-3.0-or-later
//! Typed payloads carried *inside* the encrypted session.
//!
//! Everything here travels through [`nullchat_transport::Session`], so it is
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
//!   7 ADDRESS     onion_len(u16) ‖ onion ‖ name
//!   8 RECEIPT     utf-8 body of the message that arrived
//! ```
//!
//! `RECEIPT` echoes the text back so the sender can turn "sent" into
//! "delivered". Echoing the body avoids adding message ids to the `TEXT` frame,
//! which older builds would not understand — and it travels inside the same
//! encrypted session, so it reveals nothing a passive observer did not already
//! see as ciphertext.
//!
//! `ADDRESS` is sent right after a session comes up. Without it, a peer who
//! contacted us first would be someone we can never dial back: the session
//! proves *who* they are, but not *where* to reach them.
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

// The kind byte. These numbers are the wire format: an older build reads them
// too, so a value may never be reused for something else.
/// A chat message.
pub const TEXT: u8 = 0;
/// The sender's display name and picture.
pub const PROFILE: u8 = 1;
/// Announces a file that the following chunks belong to.
pub const FILE_OFFER: u8 = 2;
/// One slice of a file, at most [`CHUNK`] bytes.
pub const FILE_CHUNK: u8 = 3;
/// The last chunk has been sent; the receiver can reassemble.
pub const FILE_END: u8 = 4;
/// A message addressed to a group rather than to us alone.
pub const GROUP_TEXT: u8 = 5;
/// The shared group roster, which doubles as the invitation.
pub const GROUP_INFO: u8 = 6;
/// The sender's onion address, so we can dial them back.
pub const ADDRESS: u8 = 7;
/// Confirmation that a message of ours arrived.
pub const RECEIPT: u8 = 8;
/// A message that answers another one.
pub const REPLY: u8 = 9;
/// An emoji put on a message.
pub const REACTION: u8 = 10;
/// What the sender's build understands, sent once per session.
pub const CAPABILITIES: u8 = 11;

/// The features this build can be sent.
///
/// A peer that says nothing is a build from before this existed, so anything
/// above 0 has to degrade rather than be sent and dropped — see
/// [`encode_capabilities`].
pub const FEATURES: u16 = 1;

/// How a message is referred to across two computers.
///
/// Row ids are local, and the timestamp on a message is stamped by whoever
/// received it, so neither identifies the same message on both sides. What both
/// sides do hold is *who wrote it* and *what it says*, so the reference is a
/// digest of the two.
///
/// The consequence, stated because it is visible: the same person sending the
/// identical text twice produces one reference. A reply then attaches to the
/// most recent of them. Getting that last case right would need an id minted by
/// the sender and carried on every message, which is a wire change that costs
/// every older build its ability to read a plain message at all.
#[must_use]
pub fn message_ref(sender_identity: &[u8; 32], body: &[u8]) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"nullchat message ref v1");
    h.update(sender_identity);
    h.update(body);
    let full: [u8; 32] = h.finalize().into();
    let mut short = [0u8; 16];
    short.copy_from_slice(&full[..16]);
    short
}

/// A decoded incoming payload.
pub enum Payload {
    /// A chat message, already valid UTF-8.
    Text(String),
    /// The sender's profile. Both fields are what *they* claim, so neither is
    /// trusted for anything but display.
    Profile {
        /// Display name.
        name: String,
        /// Picture bytes, in whatever format the sender chose.
        picture: Vec<u8>,
    },
    /// A file is about to arrive in chunks.
    FileOffer {
        /// Ties the offer, its chunks and its end together.
        id: [u8; 16],
        /// The name the sender gave the file; treat as untrusted input.
        name: String,
        /// Size the sender claims, in bytes.
        size: u64,
    },
    /// One slice of a file.
    FileChunk {
        /// Which file this belongs to.
        id: [u8; 16],
        /// Position of this chunk, counted from zero.
        seq: u32,
        /// The bytes themselves.
        data: Vec<u8>,
    },
    /// A file is complete.
    FileEnd {
        /// Which file finished.
        id: [u8; 16],
    },
    /// A message sent to a group.
    GroupText {
        /// Which group it was sent to.
        group_id: [u8; 16],
        /// The message body.
        text: String,
    },
    /// A group roster. `created_at` is not on the wire — the receiver stamps
    /// its own arrival time, so a peer cannot rewrite our history.
    GroupInfo {
        /// The roster as the sender has it.
        group: Group,
    },
    /// Where to reach the sender, so a conversation they started can be
    /// continued from our side later.
    Address {
        /// Their onion address.
        onion: String,
        /// Their display name.
        name: String,
    },
    /// "Your message arrived" — carries the text it confirms.
    Receipt {
        /// The body of the message that arrived.
        body: String,
    },
    /// A message answering another one.
    Reply {
        /// Which message is being answered; see [`message_ref`].
        to: [u8; 16],
        /// Empty for a direct reply, otherwise the group it was written in.
        group_id: Option<[u8; 16]>,
        /// The reply itself.
        text: String,
    },
    /// An emoji put on a message, or taken off it again.
    Reaction {
        /// Which message; see [`message_ref`].
        to: [u8; 16],
        /// The emoji. **Empty means the sender removed theirs.**
        emoji: String,
    },
    /// What the sender's build understands.
    Capabilities {
        /// Feature level; see [`FEATURES`].
        features: u16,
    },
}

/// Frame a chat message.
pub fn encode_text(text: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + text.len());
    v.push(TEXT);
    v.extend_from_slice(text.as_bytes());
    v
}

/// Frame our display name and picture.
pub fn encode_profile(name: &str, picture: &[u8]) -> Vec<u8> {
    let n = name.as_bytes();
    let mut v = Vec::with_capacity(3 + n.len() + picture.len());
    v.push(PROFILE);
    v.extend_from_slice(&(n.len() as u16).to_be_bytes());
    v.extend_from_slice(n);
    v.extend_from_slice(picture);
    v
}

/// Announce a file. `id` must be the same for its chunks and its end.
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

/// Frame one slice of a file. Keep `data` at or below [`CHUNK`] so the result
/// stays under the transport's frame cap.
pub fn encode_file_chunk(id: &[u8; 16], seq: u32, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 16 + 4 + data.len());
    v.push(FILE_CHUNK);
    v.extend_from_slice(id);
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(data);
    v
}

/// Tell the receiver that every chunk of `id` has been sent.
pub fn encode_file_end(id: &[u8; 16]) -> Vec<u8> {
    let mut v = Vec::with_capacity(17);
    v.push(FILE_END);
    v.extend_from_slice(id);
    v
}

/// Frame a group message. The caller fans it out to each member over that
/// member's own 1:1 session — there is no group session.
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

/// Frame our onion address and name, sent right after a session comes up.
pub fn encode_address(onion: &str, name: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(3 + onion.len() + name.len());
    v.push(ADDRESS);
    push_str(&mut v, onion);
    v.extend_from_slice(name.as_bytes());
    v
}

/// Confirm a message we received, by echoing its body back.
pub fn encode_receipt(body: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + body.len());
    v.push(RECEIPT);
    v.extend_from_slice(body.as_bytes());
    v
}

/// Frame a reply. `group_id` is `None` for a direct message.
///
/// Only send this to a peer that has announced [`FEATURES`] — an older build
/// drops a kind it does not know, and dropping a *message* is not an acceptable
/// way to degrade. See `send_reply` on the app side for what happens instead.
pub fn encode_reply(to: &[u8; 16], group_id: Option<&[u8; 16]>, text: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 16 + 17 + text.len());
    v.push(REPLY);
    v.extend_from_slice(to);
    match group_id {
        Some(g) => {
            v.push(1);
            v.extend_from_slice(g);
        }
        None => v.push(0),
    }
    v.extend_from_slice(text.as_bytes());
    v
}

/// Frame a reaction. An empty `emoji` takes the sender's reaction off again.
///
/// Safe to send to any peer: a build that does not know this kind ignores it,
/// and an emoji that does not arrive costs nobody a message.
pub fn encode_reaction(to: &[u8; 16], emoji: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 16 + emoji.len());
    v.push(REACTION);
    v.extend_from_slice(to);
    v.extend_from_slice(emoji.as_bytes());
    v
}

/// Announce what this build understands. Sent once, when a session comes up.
#[must_use]
pub fn encode_capabilities() -> Vec<u8> {
    let mut v = Vec::with_capacity(3);
    v.push(CAPABILITIES);
    v.extend_from_slice(&FEATURES.to_be_bytes());
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
        RECEIPT => Some(Payload::Receipt {
            body: String::from_utf8_lossy(rest).to_string(),
        }),
        REPLY => {
            let to: [u8; 16] = rest.get(..16)?.try_into().ok()?;
            let (&flag, rest) = rest[16..].split_first()?;
            let (group_id, text) = match flag {
                0 => (None, rest),
                1 => {
                    let g: [u8; 16] = rest.get(..16)?.try_into().ok()?;
                    (Some(g), &rest[16..])
                }
                _ => return None,
            };
            Some(Payload::Reply {
                to,
                group_id,
                text: String::from_utf8_lossy(text).to_string(),
            })
        }
        REACTION => {
            let to: [u8; 16] = rest.get(..16)?.try_into().ok()?;
            Some(Payload::Reaction {
                to,
                emoji: String::from_utf8_lossy(&rest[16..]).to_string(),
            })
        }
        CAPABILITIES => Some(Payload::Capabilities {
            features: u16::from_be_bytes(rest.get(..2)?.try_into().ok()?),
        }),
        ADDRESS => {
            let (onion, rest) = take_str(rest)?;
            Some(Payload::Address {
                onion,
                name: String::from_utf8_lossy(rest).to_string(),
            })
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
    fn receipt_roundtrip() {
        match decode(&encode_receipt("ahoj světe")).unwrap() {
            Payload::Receipt { body } => assert_eq!(body, "ahoj světe"),
            _ => panic!("wrong kind"),
        }
    }

    #[test]
    fn a_reply_carries_what_it_answers() {
        let to = message_ref(&[9u8; 32], b"puvodni zprava");
        match decode(&encode_reply(&to, None, "odpoved")).unwrap() {
            Payload::Reply { to: got, group_id, text } => {
                assert_eq!(got, to);
                assert_eq!(group_id, None);
                assert_eq!(text, "odpoved");
            }
            _ => panic!("wrong kind"),
        }
        let group = [7u8; 16];
        match decode(&encode_reply(&to, Some(&group), "ve skupine")).unwrap() {
            Payload::Reply { group_id, text, .. } => {
                assert_eq!(group_id, Some(group));
                assert_eq!(text, "ve skupine");
            }
            _ => panic!("wrong kind"),
        }
    }

    /// The reference is the same on both computers, and different for two
    /// different messages — that is the whole requirement.
    #[test]
    fn a_message_reference_is_agreed_and_specific() {
        let me = [1u8; 32];
        let you = [2u8; 32];
        assert_eq!(message_ref(&me, b"ahoj"), message_ref(&me, b"ahoj"));
        assert_ne!(message_ref(&me, b"ahoj"), message_ref(&me, b"ahoj!"));
        // Same words from two people are two messages.
        assert_ne!(message_ref(&me, b"ahoj"), message_ref(&you, b"ahoj"));
    }

    #[test]
    fn a_reaction_and_its_removal_both_travel() {
        let to = message_ref(&[3u8; 32], b"neco");
        match decode(&encode_reaction(&to, "🔥")).unwrap() {
            Payload::Reaction { to: got, emoji } => {
                assert_eq!(got, to);
                assert_eq!(emoji, "🔥");
            }
            _ => panic!("wrong kind"),
        }
        // Empty is "I took mine off", not a malformed frame.
        match decode(&encode_reaction(&to, "")).unwrap() {
            Payload::Reaction { emoji, .. } => assert!(emoji.is_empty()),
            _ => panic!("wrong kind"),
        }
    }

    #[test]
    fn capabilities_round_trip() {
        match decode(&encode_capabilities()).unwrap() {
            Payload::Capabilities { features } => assert_eq!(features, FEATURES),
            _ => panic!("wrong kind"),
        }
    }

    /// The reason replies and reactions could be added without forcing everyone
    /// to update on the same day: an older build does not guess.
    #[test]
    fn an_unknown_kind_is_declined_not_guessed() {
        assert!(decode(&[200, 1, 2, 3]).is_none());
        assert!(decode(&[]).is_none());
    }

    #[test]
    fn truncated_new_kinds_are_refused() {
        assert!(decode(&[REPLY, 1, 2, 3]).is_none());
        assert!(decode(&[REACTION, 1, 2]).is_none());
        assert!(decode(&[CAPABILITIES]).is_none());
        // A reply that claims a group id and then does not carry one.
        let mut short = vec![REPLY];
        short.extend_from_slice(&[0u8; 16]);
        short.push(1);
        assert!(decode(&short).is_none());
    }

    #[test]
    fn address_roundtrip() {
        let e = encode_address("abcdef.onion", "Lukáš");
        match decode(&e).unwrap() {
            Payload::Address { onion, name } => {
                assert_eq!(onion, "abcdef.onion");
                assert_eq!(name, "Lukáš");
            }
            _ => panic!("wrong kind"),
        }
        // A peer whose onion is not up yet still sends a well-formed frame.
        match decode(&encode_address("", "")).unwrap() {
            Payload::Address { onion, name } => {
                assert!(onion.is_empty() && name.is_empty());
            }
            _ => panic!("wrong kind"),
        }
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
