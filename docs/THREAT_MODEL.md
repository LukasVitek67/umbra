<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# NullChat — Threat Model

> This is a living document. It states honestly what NullChat does and does **not**
> protect. Claiming more than this would put people at risk.

## Who we defend against

- **Network observers** — ISPs, national backbones, Wi-Fi operators watching
  traffic in transit.
- **Relay / infrastructure operators** — including a hostile party who *runs* or
  *seizes* a node that carries other people's traffic.
- **Mass-surveillance / content-scanning mandates** — bulk collection and
  client-/server-side scanning of message content.
- **A central-server seizure** — the NullChat failure mode is designed away: there
  is no central server to seize.

## What we protect

- **Message & file content** — end-to-end encrypted with the **Signal protocol**
  (`libsignal`): PQXDH session setup and the Double Ratchet. Only the intended
  recipient's device can decrypt; relays carry opaque ciphertext.
- **Recorded traffic against a future quantum computer (session setup)** —
  PQXDH mixes a post-quantum KEM (Kyber) into the key agreement, so a session
  captured today is not opened by a quantum computer built later.
- **Identity against a future quantum computer** (since 1.9.0) — identities are
  signed with Ed25519 **and** ML-DSA-65 together, and a signature is accepted
  only if both verify. Breaking the classical half does not let anyone forge an
  invite, sign a key bundle in your name, or place themselves in the middle of a
  conversation. Onion routing itself is still classical, as is Tor's own
  cryptography, which is outside NullChat's control.
- **Message length** — padded to fixed size buckets before encryption, so
  content can't be inferred from size within a bucket.
- **Transport metadata (partial)** — onion routing (Tor) hides the network path;
  no single relay sees both ends. Sealed sender (Fáze 2) hides the sender from
  the relay.
- **Forward secrecy & post-compromise security** — from the Double Ratchet:
  stealing one message key doesn't retro-decrypt history or all future messages.
- **Data at rest** — identity keys and the local database are encrypted with a
  random key, of which the passphrase opens a wrapped copy (Argon2id, 256 MiB /
  3 / 4). Keeping the key separate from the passphrase is what lets that cost
  rise on an account that already exists; deriving the key directly, as builds
  before 2.4.0 did, froze it at whatever the default was the day the account was
  made. The columns SQL must match
  on cannot be encrypted, so they hold a blind index instead; see the limitation
  on activity metadata below for exactly what that does and does not hide.

## What we do NOT protect (limitations)

- **Endpoint compromise.** If the OS/device is compromised (malware, a coerced
  unlock, screen capture, a keylogger), NullChat cannot help. Content is plaintext
  on the endpoints by necessity.
- **Global passive adversary / traffic-confirmation.** An adversary who watches a
  large fraction of the network can attempt end-to-end timing/volume correlation
  against Tor. Cover traffic (Fáze 2) raises the cost but does not eliminate it.
- **Local database activity metadata at rest (partly).** Since 1.7.0 the routing
  columns hold a **blind index** — `HMAC-SHA256(key derived from the data key,
  value)` — instead of the raw value, and the value itself lives once, sealed,
  in the `blind_index` table. So identity keys and group ids are no longer
  readable from a seized file, and two seized devices cannot be shown to share a
  contact or a group, because each account's index key differs.

  What still leaks from the file without the passphrase, stated plainly:

  - **How many distinct parties** there are, and **how many messages** went to
    each. Rows for the same person carry the same index — that is what makes a
    lookup possible at all.
  - **Timestamps, direction and delivery state**, because ordering and filtering
    need them in the clear.

  So "who" is now protected and "how much, when" is not. An adversary who
  already suspects a specific contact still cannot confirm it: without the key
  they cannot compute that person's index. Whole-file encryption (SQLCipher)
  remains the better answer where its build toolchain is available, and would
  close the counting and timing leak as well.
- **Coarse size class.** Padding quantises length; it does not equalise a 2 MB
  file with a text. Size *class* still leaks; very large transfers leak coarse
  magnitude. Constant-rate cover traffic is the mitigation (Fáze 2).
- **The fact that you run NullChat.** Using Tor / running an onion service can be
  observable to a local network watcher. Pluggable transports / bridges are a
  future item.
- **Contact-graph metadata beyond the transport.** Who you add as a contact,
  timing of activity, and similar side channels are only partially mitigated.
- **Availability.** A determined adversary can try to block Tor; NullChat is a
  privacy tool, not a censorship-circumvention guarantee.
- **A hostile group member.** A group is a shared roster fanned out over the
  existing 1:1 channels, so every hop keeps full end-to-end encryption — but the
  roster itself is flat: **any** member can rename the group, add someone, or
  remove someone, and the highest roster version wins. That converges and it
  keeps a stranger out (a roster is only accepted from someone already inside
  it), yet it does not defend against a member who turns hostile. Signed,
  ordered membership changes with an owner are the planned hardening.
- **Group delivery.** A group message reaches only the members reachable at the
  time of sending; there is no server to hold it, and nobody re-sends it later
  (same limitation as 1:1, multiplied by the number of members).

## Trust assumptions

- The **cryptographic primitives and their crates** are correct (RustCrypto,
  vodozemac, Argon2, Arti). We do not roll our own.
- **Tor's anonymity properties** hold within their documented limits.
- The user protects their **passphrase** and their **device**.
- Builds are **reproducible** and match published source (a Phase 5 goal).

## Explicitly out of scope (for now)

- Resistance to a global active adversary.
- Deniable encryption / duress passwords.
- Anti-forensics beyond at-rest encryption.

## Pre-audit status

NullChat has **not** been independently audited. Until it has (Fáze 5), treat every
guarantee above as *intended*, not *verified*, and do not use NullChat where a
person's safety depends on it.
