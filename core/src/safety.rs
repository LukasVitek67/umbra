// SPDX-License-Identifier: AGPL-3.0-or-later
//! Safety numbers — the one thing that catches a swapped invite.
//!
//! Everything else in Umbra proves that the person on the other end holds the
//! private key named in the invite. Nothing proves the invite came from who you
//! think: replace it while it travels (a read of someone's chat account, a
//! hostile network between you) and every signature still verifies. You are
//! simply talking to somebody else, and the app cannot tell.
//!
//! A safety number closes that, and it is the only mechanism here that needs a
//! human. Both sides derive the same 60 digits from the two identity keys, read
//! them to each other over a channel an attacker would have to control *as
//! well* — a phone call where you recognise the voice, or standing next to each
//! other — and if the digits match, no third party sits in the middle.
//!
//! # Construction
//!
//! The same shape Signal uses, and for the same reasons:
//!
//! * Each identity is hashed **iteratively** ([`ITERATIONS`] rounds of
//!   SHA-512), so an attacker who wants a key whose digits collide with a
//!   target's cannot simply grind hashes cheaply — each candidate costs them
//!   the same 5200 rounds it costs us once.
//! * The version is mixed in, so a future change of scheme produces different
//!   numbers instead of quietly comparing across schemes.
//! * The two halves are **sorted** before being joined, so both people see the
//!   same number without either having to know who "goes first".
//! * The result is digits, not hex: they survive being read aloud in any
//!   language, over a bad line, by someone who does not know what hex is.
//!
//! Comparing all 60 digits is what gives the full guarantee. Comparing a few is
//! not "almost as good" — see [`safety_number`].

use sha2::{Digest, Sha512};

/// Rounds of hashing per identity. Signal's number; the point is cost, not
/// secrecy — it makes searching for a colliding key expensive.
const ITERATIONS: u32 = 5200;

/// Mixed into every fingerprint. Bump it if the construction ever changes, so
/// old and new numbers can never be mistaken for each other.
const VERSION: u16 = 1;

/// How many digits each side contributes.
const DIGITS_PER_SIDE: usize = 30;

/// One identity's half of the number: 30 digits.
///
/// `pq` is the commitment to that person's post-quantum key. Mixing it in is
/// what makes the comparison cover the *whole* identity: without it two people
/// could read matching digits while their post-quantum halves differed, which
/// is exactly the substitution the second scheme exists to prevent. Contacts
/// from before post-quantum identities have none, and their number is computed
/// the old way — their conversation has no post-quantum protection to confirm.
fn fingerprint(identity: &[u8; 32], pq: Option<&[u8; 32]>) -> String {
    let mut hash = {
        let mut h = Sha512::new();
        h.update(VERSION.to_be_bytes());
        h.update(identity);
        if let Some(pq) = pq {
            h.update(pq);
        }
        h.finalize().to_vec()
    };
    // Feeding the identity back in every round keeps each iteration bound to
    // this key, so the work cannot be shared across candidate keys.
    for _ in 1..ITERATIONS {
        let mut h = Sha512::new();
        h.update(&hash);
        h.update(identity);
        hash = h.finalize().to_vec();
    }

    // Six groups of five digits, each from five bytes of the digest.
    let mut out = String::with_capacity(DIGITS_PER_SIDE);
    for chunk in hash.chunks(5).take(DIGITS_PER_SIDE / 5) {
        let mut n: u64 = 0;
        for &b in chunk {
            n = (n << 8) | b as u64;
        }
        out.push_str(&format!("{:05}", n % 100_000));
    }
    out
}

/// The 60-digit number both sides must see identically.
///
/// Read **all of it**. Truncating is not a smaller version of the same check:
/// each digit dropped makes a forged key ten times cheaper to search for, and
/// the whole construction exists to make that search expensive.
///
/// Returned as one run of digits; use [`grouped`] for something readable.
pub fn safety_number(a: &[u8; 32], b: &[u8; 32]) -> String {
    safety_number_full(a, None, b, None)
}

/// The full number, covering both halves of both identities.
///
/// Each side passes its own post-quantum commitment and the one it holds for
/// the other person. Both compute the same digits, because the halves are
/// sorted by identity key.
pub fn safety_number_full(
    a: &[u8; 32],
    a_pq: Option<&[u8; 32]>,
    b: &[u8; 32],
    b_pq: Option<&[u8; 32]>,
) -> String {
    // Sorted, so both people compute the same string without agreeing on an
    // order first.
    let ((first, first_pq), (second, second_pq)) =
        if a <= b { ((a, a_pq), (b, b_pq)) } else { ((b, b_pq), (a, a_pq)) };
    format!("{}{}", fingerprint(first, first_pq), fingerprint(second, second_pq))
}

/// The same number in groups of five, for showing on screen and reading aloud.
pub fn grouped(number: &str) -> String {
    number
        .as_bytes()
        .chunks(5)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_compute_the_same_number() {
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        // Whoever asks, in whichever order: the same digits.
        assert_eq!(safety_number(&alice, &bob), safety_number(&bob, &alice));
    }

    #[test]
    fn it_is_sixty_digits() {
        let n = safety_number(&[3u8; 32], &[4u8; 32]);
        assert_eq!(n.len(), 60);
        assert!(n.chars().all(|c| c.is_ascii_digit()), "must be readable aloud: {n}");
        assert_eq!(grouped(&n).split(' ').count(), 12);
    }

    /// The whole point: a different identity gives a different number, so a
    /// swapped invite shows up when the two people compare.
    #[test]
    fn a_substituted_identity_changes_the_number() {
        let me = [7u8; 32];
        let friend = [8u8; 32];
        let impostor = [9u8; 32];
        let real = safety_number(&me, &friend);
        let mitm = safety_number(&me, &impostor);
        assert_ne!(real, mitm);

        // And a single bit of difference is enough.
        let mut nearly = friend;
        nearly[31] ^= 0x01;
        assert_ne!(real, safety_number(&me, &nearly));
    }

    #[test]
    fn each_half_belongs_to_one_identity() {
        let a = [10u8; 32];
        let b = [11u8; 32];
        let c = [12u8; 32];
        let ab = safety_number(&a, &b);
        let ac = safety_number(&a, &c);
        // a < b and a < c, so both numbers open with a's half.
        assert_eq!(&ab[..30], &ac[..30]);
        assert_ne!(&ab[30..], &ac[30..]);
    }

    /// A swapped post-quantum key changes the digits, so comparing them catches
    /// it. Without this the second scheme could be substituted unnoticed by two
    /// people who checked their numbers and believed they were done.
    #[test]
    fn the_post_quantum_half_is_part_of_the_number() {
        let me = [20u8; 32];
        let friend = [21u8; 32];
        let my_pq = [0xA0u8; 32];
        let their_pq = [0xB0u8; 32];
        let impostor_pq = [0xC0u8; 32];

        let real = safety_number_full(&me, Some(&my_pq), &friend, Some(&their_pq));
        let swapped = safety_number_full(&me, Some(&my_pq), &friend, Some(&impostor_pq));
        assert_ne!(real, swapped);

        // Both sides compute the same digits whichever way round they ask.
        assert_eq!(
            real,
            safety_number_full(&friend, Some(&their_pq), &me, Some(&my_pq))
        );

        // A contact with no post-quantum half keeps the classical number, so
        // upgrading does not silently invalidate what someone already verified
        // with a peer who has not upgraded.
        assert_eq!(safety_number_full(&me, None, &friend, None), safety_number(&me, &friend));
        assert_ne!(real, safety_number(&me, &friend));
    }

    #[test]
    fn talking_to_yourself_is_not_a_crash() {
        let me = [5u8; 32];
        let n = safety_number(&me, &me);
        assert_eq!(n.len(), 60);
        assert_eq!(&n[..30], &n[30..]);
    }
}
