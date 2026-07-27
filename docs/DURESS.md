<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Duress passphrases — what they do, and what they cannot do

Umbra lets one account answer to more than one passphrase:

| Passphrase | What happens |
|---|---|
| **normal** | your real account |
| **decoy** (optional) | a separate, self-contained history — its own contacts and messages, which you fill in yourself |
| **duress** (optional) | destroys everything it cannot read, then behaves like a brand-new account |

You may set none, one, or both of the optional ones.

This page is written to be read *before* relying on any of it. A feature like
this is worth having only if you know exactly where it stops working, because
the situations it is for are the ones where being wrong costs the most.

## How it works

There is no list of passphrases anywhere. A passphrase is turned into a key
(Argon2id over the account's salt), and that key is simply used to open rows.
Rows sealed under a different key do not decrypt, and Umbra treats a row it
cannot decrypt as **absent** — not as an error, not as a locked door.

The consequences are what the design is for:

* Nothing in the file records how many passphrases it answers to. Adding a
  decoy adds rows; it does not add a field saying "there is a decoy".
* Every lookup key — contact identities, group ids, even the *names* of stored
  secrets — is a blind index computed from the key that wrote it. Two profiles
  writing "identity_seed" land on two unrelated rows, and neither row says what
  it is.
* The app behaves identically in all three cases. There is no second code path
  that a screenshot or a stopwatch could distinguish.

The duress passphrase overwrites every sealed value it cannot read with random
bytes **of the same length**, leaving the rows in place. The file keeps its
size, its row counts and its structure; the content is unrecoverable, because
no key opens random bytes. Then the account opens as if it were new.

## What this does **not** protect against

Stated plainly, because a false sense of safety here is worse than none.

1. **Anyone who copied the disk beforehand.** This is the big one. If a border
   post images the drive first and then makes you unlock it, they compare the
   two images and see that rows changed. Nothing that runs on the machine
   afterwards can prevent that — the same limit applies to GrapheneOS's duress
   PIN and to every hidden-volume scheme ever built. If you expect an image to
   be taken, the only real answer is not to carry the data.

2. **A decoy that is not believable.** The file shows how many rows exist, even
   though it shows nothing about what they say. A decoy with three messages in a
   database holding thousands of unreadable rows invites exactly the question
   you were avoiding. Fill the decoy with enough ordinary conversation to match
   the size of the file, and keep using it occasionally so its timestamps are
   not all from one afternoon.

3. **Being watched while you type.** A passphrase of a visibly different length,
   or a hesitation, is not something software can hide.

4. **The rest of the machine.** Message notifications in the OS history, a
   thumbnail cache, the Windows page file, a backup tool, `tor.log`'s timestamps
   — Umbra controls its own directory and nothing else.

5. **Someone who knows Umbra has this feature.** The design hides *whether you
   used it*, not that it exists — the source is public. Being asked "is there a
   second passphrase?" is a question about you, not about the file, and no
   amount of cryptography answers it on your behalf.

## Legal note, once

In some jurisdictions, destroying data during a lawful search is itself an
offence, regardless of what the data was. That is a decision about your own
situation and your own law, and it is yours to make — this document only makes
sure you are making it with accurate information about what the software does.

## What is verified

Both properties are asserted by tests in `core/src/store.rs`, not just claimed:

* `a_second_passphrase_gets_its_own_separate_history` — two passphrases, one
  file. Each sees exactly its own contacts, secrets and messages; searching from
  one finds nothing belonging to the other.
* `a_duress_passphrase_destroys_the_real_history_in_place` — after the wipe the
  real passphrase recovers nothing, and the file's **row count and byte size are
  unchanged**, so the destruction does not announce itself in the file's shape.
