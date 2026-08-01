<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Hardening review — July 2026

A read of the whole application (Rust core, transport, the frb API layer and the
Flutter UI — about 12 000 lines of hand-written code), together with a look at
what [Briar](https://code.briarproject.org/briar) does that NullChat does not.

Findings are ordered by how much they matter, not by how hard they are to fix.
Anything marked **fixed** was fixed in the same pass and has a test; everything
else is listed with what it would take.

## Fixed in this pass

### 1. The app log held message text in the clear — critical

`emit()` wrote every event to `nullchat-app.log` as
`{kind} peer={12 hex of identity} {data}`. For a text message, `data` **was the
message**. The file sits next to the encrypted database, is not encrypted, and
needs no passphrase.

This was not theoretical: the author's own log was 1.25 MB and contained 22
`message` lines with readable text, 4030 `dial` lines with contacts' onion
addresses, and 15 `profile` lines with contacts' names. Sealing the database
columns while this file existed protected nothing.

Now the log records only the *shape* of an event — kind, a per-run peer label,
and a byte count. The label is `SHA-256(random per-process salt ‖ identity)`
truncated to 6 hex characters: enough to tell two peers apart while debugging,
useless to anyone reading the file, and different after every restart so two
logs cannot be lined up. The log is also truncated at every start, which
disposes of the plaintext older builds wrote.

### 2. Incoming files were unbounded and unattributed — high

`FILE_OFFER` was accepted at any size, chunks were appended without checking
against the size that was offered, and `INCOMING_FILES` was keyed by transfer id
alone. Three consequences: any peer — including one still sitting unaccepted in
*Waiting* — could fill the disk; a sender could promise 1 KB and stream
gigabytes; and **anyone who knew a transfer id could append to someone else's
file**, because the chunk handler never checked who sent it.

Now: a 4 GiB ceiling refused at the offer, at most 16 transfers in flight, a
chunk that would exceed the offered size is dropped, and a chunk or an end
marker is only accepted from the peer that made the offer.

### 3. File names from the network were barely sanitised — high

The old filter replaced `\/:*?"<>|` and nothing else. `..` survived intact, as
did control characters, Windows device names (`CON`, `NUL`, `COM1`…) and
trailing dots and spaces, which Windows strips silently so two different names
can collide.

`safe_file_name()` now handles all of those, and the test asserts the property
that actually matters: joining the result onto the downloads folder always stays
*inside* that folder.

### 4. Profile pictures were written to disk at any size — medium

A peer chose the byte count and it went straight to `avatar-<peer>.img`. Capped
at 8 MiB.

## Fixed since — 2.3.11

### 5. Signing out did not end the session — critical

`AppState.signOut()` set its own fields to null and stopped there. The session
itself lived on the Rust side and nothing let go of it: `APP`, `SERVICE`,
`CONTACTS`, `MY_PROFILE` and the running network tasks all held the same
`Arc<Mutex<Inner>>`, so the open database, the identity key and the live Signal
sessions survived a sign-out intact. The account picker came up, the passphrase
was asked for again, and none of that had any bearing on what was still in
memory. "Locked" meant a different screen.

Now `UmbraApp::end_session()` drops all of it — which also kills the tor daemon
and closes the database cleanly — and the app then restarts itself, coming back
at the picker. The restart is the part that matters: a passphrase-derived key
that has been live leaves copies no destructor reaches, in the allocator, in a
saved stack, in the page file. Leaving the process is the only thing that
settles those, and `Store`'s keys are `Zeroizing` precisely so that the ones it
does own go first.

The cost is a Tor bootstrap on the way back in. That was the objection to doing
it this way, and it does not hold: measured on the author's machine, from
`start_network` to a ready onion took 6 s and 23 s on two runs, not the minutes
the connecting screen used to claim (that string is fixed too).

Not covered: an idle timer. Walking away without signing out still leaves
everything unlocked.

### 6. A contact's queue could be delivered twice at once — high

`flush_pending` is called from two places — the keep-alive loop every 20 s, and
the "connected" event. Both read the outbox for the same contact and both send
what they find, so an overlap put every waiting message on the wire twice. The
second copy is worse than noise: it arrives against a Double Ratchet state that
has already moved past it.

One flush per contact at a time now, with `try_lock` rather than a queue — if a
delivery is already running there is nothing to add, and waiting would only hold
the keep-alive loop, which walks every contact in turn, behind one slow peer.
Anything queued during a flush goes out on the next tick.

## Open — worth doing, in this order

### A. ~~There is no way to verify a contact~~ — **done**

Shipped: `core/src/safety.rs` derives 60 digits from both identity keys (5200
rounds of SHA-512 per identity, version mixed in, halves sorted so both sides
compute the same string). Stored as `contacts.verified`, set only by an explicit
human answer, shown as a badge that opens the number and explains what to do
with it. What follows is the original finding, kept for the record.

### A-original. There is no way to verify a contact — high

The invite (`umbra1:…`) carries an identity key, a name and an onion address.
The handshake proves that whoever answers holds the private half of that
identity key, and that is genuinely strong — but nothing proves the invite came
from the person you think. Swap the invite in transit (a compromised chat
account, a hostile network on the way to the recipient) and every signature
still checks out; you are simply talking to someone else.

`toggleVerified` exists in `app/lib/mock.dart` but is never called and never
stored, so the "Verified" badge can never appear. Nothing predends a check
happened, which is the right failure — but there is no defence at all.

**Plan:** a *safety number* derived from both identity keys (sorted, hashed,
rendered as digit groups the way Signal does), shown on the contact screen, with
a stored "verified" flag and a visible difference in the conversation. Two
people read it to each other over the phone. Then a QR code carrying the invite,
so an in-person exchange needs no reading at all.

### B. Auto sign-in stores the passphrase — high

DPAPI ties it to the Windows account, so copying the file elsewhere is useless —
but malware running as the user can call `CryptUnprotectData` just as easily as
NullChat can, and that yields the passphrase, and with it the whole database.

**Partly addressed in 2.3.11, and the finding stands.** The blob is now bound to
extra entropy derived from the account's own salt, so `accounts.json` by itself
is no longer enough — which defeats the common shape of the attack, a tool that
walks the disk for protected blobs and hands each one to `CryptUnprotectData`.
It does not defeat anyone who targets NullChat: the source is public and both
files are on the same disk. The warning next to the checkbox says as much, and
now names the real threat (any program running as you) rather than a person at
the keyboard.

**Plan for the rest:** keep the feature, because typing a long passphrase at
every start is what makes people pick short ones — but bound the damage. An idle
lock that ends the session the way signing out now does (finding 5), and a
Windows Hello gate on the stored blob so recovering it needs a person, not just
a process.

### C. Handshake signatures lack domain separation — medium

`identity.rs` gets this right: roster signatures are prefixed with
`nullchat-roster-v1\0`. The transport does not — it signs the prekey bundle and the
first message body raw. Both inputs are structured enough that a practical
cross-protocol attack is not obvious, but "not obvious" is a poor place to
stand, and the codebase already knows better in another module.

**Plan:** prefix both with their own tags. It is a wire change, so it belongs
with the next version bump that both sides must take.

### D. Anyone can make us do a PQXDH — medium

`accept()` answers any connection that sends the magic bytes, generating Kyber
and X25519 keys before it knows who is calling. Blocking is applied afterwards,
at the payload layer. Someone who knows the onion address can therefore make the
app do real cryptographic work in a loop.

**Plan:** cheap per-source throttling, and refuse a new handshake from an
identity already blocked as soon as it is known.

### E. Deleting an account does not erase it — medium

`remove()` calls `remove_dir_all`. The bytes stay on the disk until something
overwrites them, and on an SSD even that is not assured.

**Plan:** overwrite the database and key material before unlinking, and say
plainly in the UI that this is best-effort on modern storage.

### F. A group's roster is flat — known, documented

Any member can rename the group, add anyone, or remove anyone; the highest
version wins. This keeps strangers out and converges, but it does not defend
against a member who turns hostile. Signed, ordered membership changes with an
owner are the fix, and they are a real piece of work.

## What Briar has that NullChat does not

Briar has been doing this since 2015 and is worth borrowing from. What stands
out, and what it would mean here:

| Briar | NullChat today | Worth taking? |
|---|---|---|
| **QR pairing in person** (BQP): each side shows a hash *commitment* to an ephemeral key, then the keys are exchanged over an insecure channel and checked against what was scanned | invite string, no verification step | **Yes** — this is the answer to finding A, and the commitment trick is the part to copy |
| **Mailbox**: a contact, or a box on a spare device, holds messages for you while you are offline | outbox is local only — both sides must be online at the same moment | **Yes, eventually.** The single biggest usability gap, and it can be done without weakening encryption |
| **Bluetooth and Wi-Fi transports** — works with no internet at all | Tor only | Maybe. Large piece of work; matters for the crisis scenario Briar targets |
| **Transport key rotation with pre-computed tags**, so streams are unlinkable and replays are caught by a reordering window | fresh PQXDH per connection, no long-lived transport keys | Not needed — the property is already there by a different route |
| **Reproducible builds** verified via Docker | signed releases only | **Yes** — a signature proves who built it, not *what* they built |

Two things NullChat already does that Briar does not: post-quantum session setup
(PQXDH/Kyber, Briar's handshake is classical X25519), and the blind index over
routing columns.

## Proposed order

1. **A — contact verification.** The largest real hole left, and the one a user
   can act on.
2. **C + D — domain separation and handshake throttling.** Both small, both go
   in the next wire-format bump together.
3. **B + E — idle lock and erase-on-delete.** Bounded work, clear benefit.
4. **Reproducible builds.**
5. **Mailbox**, then possibly local transports.
6. **F — signed group membership.** Largest, and only matters once groups are
   used with people you do not fully trust.
