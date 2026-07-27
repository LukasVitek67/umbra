// SPDX-License-Identifier: AGPL-3.0-or-later
//! Every parser, fed rubbish, on purpose.
//!
//! These are the functions a hostile peer reaches directly: they see bytes that
//! somebody else chose, before anything has been decided about who that
//! somebody is. A panic in any of them is a denial of service another user can
//! trigger at will — in Rust it aborts the process, so "just a panic" means
//! "they can close your messenger from across the world, repeatedly".
//!
//! The generator is deterministic (a small SplitMix64), so a failure here can be
//! reproduced exactly rather than "sometimes on CI". Two strategies, because
//! they find different things:
//!
//! * **random bytes** — reaches the early length checks and the "this is not
//!   our protocol at all" paths;
//! * **mutated valid input** — bit flips, truncations and extensions of things
//!   that *do* parse, which is what actually reaches the deeper arithmetic
//!   where an off-by-one turns into a panicking slice index.
//!
//! This is not a substitute for coverage-guided fuzzing (`cargo-fuzz`), which
//! needs a nightly toolchain and libFuzzer; it is what runs on every `cargo
//! test` on any machine, so a regression cannot sit unnoticed.

use umbra_core::crypto::padding::{pad, unpad};
use umbra_core::envelope::{self, Payload};
use umbra_core::identity::Keypair;
use umbra_core::invite::Invite;

/// Deterministic PRNG — same sequence on every machine and every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn byte(&mut self) -> u8 {
        (self.next() & 0xFF) as u8
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }
}

/// Damage a valid input the way a hostile peer would: flip, cut, extend.
fn mutate(rng: &mut Rng, input: &[u8]) -> Vec<u8> {
    let mut out = input.to_vec();
    match rng.below(4) {
        0 if !out.is_empty() => {
            let i = rng.below(out.len());
            out[i] ^= 1 << rng.below(8);
        }
        1 if !out.is_empty() => out.truncate(rng.below(out.len())),
        2 => {
            let n = rng.below(64);
            let extra = rng.bytes(n);
            out.extend_from_slice(&extra);
        }
        _ if !out.is_empty() => {
            // Overwrite a length-ish field near the front, where the arithmetic
            // that indexes into the rest of the buffer usually lives.
            let i = rng.below(out.len().min(8));
            out[i] = rng.byte();
        }
        _ => {}
    }
    out
}

/// Valid payloads of every kind, as seeds for mutation.
fn seeds() -> Vec<Vec<u8>> {
    vec![
        envelope::encode_text("ahoj"),
        envelope::encode_profile("Někdo Nový", &[0xFF; 40]),
        envelope::encode_file_offer(&[7u8; 16], "dokument.pdf", u64::MAX),
        envelope::encode_file_chunk(&[7u8; 16], u32::MAX, &[1, 2, 3]),
        envelope::encode_file_end(&[7u8; 16]),
        envelope::encode_group_text(&[2u8; 16], "skupinová zpráva"),
        envelope::encode_address("abcdefghij.onion", "jméno"),
        envelope::encode_receipt("ahoj"),
        pad(b"padded message").unwrap(),
        vec![],
        vec![0],
        vec![0xFF; 300],
    ]
}

#[test]
fn envelope_decoding_survives_anything() {
    let mut rng = Rng(0xC0FFEE);
    let seeds = seeds();

    // Pure rubbish first: lengths from empty to well past a frame.
    for _ in 0..20_000 {
        let len = rng.below(600);
        let junk = rng.bytes(len);
        let _ = envelope::decode(&junk);
        let _ = unpad(&junk);
    }

    // Then rubbish derived from things that really do parse.
    for _ in 0..40_000 {
        let seed = &seeds[rng.below(seeds.len())];
        let damaged = mutate(&mut rng, seed);
        let _ = envelope::decode(&damaged);
        let _ = unpad(&damaged);
    }
}

#[test]
fn invite_decoding_survives_anything() {
    let mut rng = Rng(0xBADC0DE);
    let real = Invite::with_pq([3u8; 32], "alice", "abcdefghij.onion", [9u8; 32]).encode();
    let legacy = Invite::new([3u8; 32], "alice", "abcdefghij.onion").encode();

    for _ in 0..20_000 {
        // Arbitrary text, including things that look almost right.
        let n = rng.below(200);
        let junk = rng.bytes(n);
        let as_text = String::from_utf8_lossy(&junk).to_string();
        let _ = Invite::decode(&as_text);
        let _ = Invite::decode(&format!("umbra1:{as_text}"));
    }

    for seed in [&real, &legacy] {
        for _ in 0..20_000 {
            let damaged = mutate(&mut rng, seed.as_bytes());
            let _ = Invite::decode(&String::from_utf8_lossy(&damaged));
        }
    }
}

/// A payload that survives a round trip must come back *identical*. Silent
/// corruption is worse than a rejection: a message that changes on the way is
/// one nobody can trust, and nothing downstream would notice.
#[test]
fn valid_payloads_round_trip_exactly() {
    // Text, including the awkward cases: empty, non-ASCII, embedded NULs, long.
    for text in ["", "ěščřžýáíé 🦊 \u{0}\u{1}", &"x".repeat(10_000)] {
        match envelope::decode(&envelope::encode_text(text)) {
            Some(Payload::Text(out)) => assert_eq!(out, text),
            other => panic!("text did not round trip: {:?}", other.is_some()),
        }
    }

    for (name, picture) in [("", &[][..]), (&"a".repeat(300), &[7u8; 5000][..])] {
        match envelope::decode(&envelope::encode_profile(name, picture)) {
            Some(Payload::Profile { name: n, picture: p }) => {
                assert_eq!(n, name);
                assert_eq!(p, picture);
            }
            _ => panic!("profile did not round trip"),
        }
    }

    for (id, fname, size) in [
        ([0u8; 16], "".to_string(), 0u64),
        ([255u8; 16], "ř".repeat(200), u64::MAX),
    ] {
        match envelope::decode(&envelope::encode_file_offer(&id, &fname, size)) {
            Some(Payload::FileOffer { id: i, name: n, size: s }) => {
                assert_eq!(i, id);
                assert_eq!(n, fname);
                assert_eq!(s, size, "a size field must survive intact");
            }
            _ => panic!("file offer did not round trip"),
        }
    }

    match envelope::decode(&envelope::encode_file_chunk(&[1u8; 16], u32::MAX, &[])) {
        Some(Payload::FileChunk { id, seq, data }) => {
            assert_eq!(id, [1u8; 16]);
            assert_eq!(seq, u32::MAX);
            assert!(data.is_empty());
        }
        _ => panic!("file chunk did not round trip"),
    }

    match envelope::decode(&envelope::encode_receipt("ahoj")) {
        Some(Payload::Receipt { body }) => assert_eq!(body, "ahoj"),
        _ => panic!("receipt did not round trip"),
    }
}

/// Padding must never hand back more than it was given, whatever the header
/// claims — a length field is attacker-controlled input like any other.
#[test]
fn padding_never_trusts_its_own_length_field() {
    let mut rng = Rng(0x5EED);
    for _ in 0..20_000 {
        let len = rng.below(2048);
        let junk = rng.bytes(len);
        if let Ok(out) = unpad(&junk) {
            assert!(
                out.len() <= junk.len(),
                "unpad returned more data than it was given"
            );
        }
    }
    // And a genuine round trip still works.
    for len in [0usize, 1, 63, 64, 65, 1000] {
        let msg = vec![0xABu8; len];
        assert_eq!(unpad(&pad(&msg).unwrap()).unwrap(), msg);
    }
}

/// Signature verification must reject rubbish rather than panic on it: this
/// runs on bytes from an unauthenticated peer during the handshake.
#[test]
fn signature_verification_survives_hostile_input() {
    let mut rng = Rng(0x5163_4E47);
    let kp = Keypair::generate().unwrap();
    let public = kp.public();
    let msg = b"prekey bundle";
    let good = kp.sign(msg);

    // Fewer rounds than the parser tests on purpose: each one is two real
    // Ed25519 verifications, and a suite nobody waits for is a suite nobody
    // runs. Damaged signatures are refused by construction, not by luck.
    for _ in 0..400 {
        let mut sig = good;
        let i = rng.below(64);
        sig[i] ^= 1 << rng.below(8);
        assert!(
            !umbra_core::identity::verify(&public, msg, &sig),
            "a damaged signature must never verify"
        );

        let mut key = public;
        key[rng.below(32)] ^= 1 << rng.below(8);
        assert!(!umbra_core::identity::verify(&key, msg, &good));
    }
}
