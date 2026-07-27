<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Changelog

What changed in each release, in plain English. This file is the source of the
release notes on GitHub and of the "What changed" text the app shows before you
agree to an update, so it is written for the person installing it, not for the
person who wrote the code. Newest first.

Umbra is experimental and has not been independently audited.

## 1.7.1

Findings from a full read of the application. See `docs/HARDENING.md`.

- **The app's own log file was storing your messages in readable form.** Every
  event was written to `umbra-app.log` together with its content — so message
  text, contacts' names and their onion addresses sat unencrypted next to the
  database, readable without your passphrase. Encrypting the database while this
  file existed protected very little. The log now records only what kind of
  event happened and how big it was, identifies peers by a label that is random
  per run, and is emptied at every start, which also disposes of what older
  versions wrote.
- **Incoming files are now bounded and attributed.** A file offer is refused
  above 4 GB, no more than 16 transfers run at once, a sender that streams more
  than it promised is cut off, and — this one mattered — a file chunk is only
  accepted from the peer that offered that transfer. Previously anyone who
  guessed a transfer id could append data to a file you were receiving from
  somebody else.
- **File names arriving from the network are properly sanitised**: `..`, control
  characters, Windows device names like `CON` and `NUL`, and trailing dots are
  all defused, so a chosen name cannot write outside your downloads folder.
- Profile pictures from contacts are capped at 8 MB instead of being written to
  disk at whatever size the sender chose.

## 1.7.0

- **The local database no longer reveals who you talk to.** Until now the
  columns the database has to search and sort on — contact and sender identity
  keys, group ids, who is in which group — held those values in the clear.
  Message content was sealed, but anyone who got hold of the file (a seized or
  stolen machine, a backup, malware running as you) could read the whole social
  graph **without knowing your passphrase**. This was the most serious finding
  of the outside review of 1.5.1.

  Those columns now hold a *blind index*: `HMAC-SHA256` of the value under a key
  derived from your passphrase. Searching still works, because a search is
  always for something you already have — Umbra computes the same index and
  matches it. The real value is stored once, encrypted. Without the passphrase
  the identity keys cannot be recovered, and an adversary who already suspects a
  particular contact cannot confirm the guess either, because computing that
  person's index needs the key.

  Two devices no longer betray each other: each account has its own index key,
  so the same person or group looks completely different in two seized files.

- **Your existing history is converted automatically** the first time 1.7.0
  opens it — in one transaction, so it either completes or leaves the file
  untouched. Nothing is lost and nothing needs to be re-added. A copy of the
  database as it was is kept beside it as `umbra.db.pre-blind-index.bak` (still
  encrypted, exactly as before), so even a conversion that goes wrong in some
  way nobody anticipated is survivable. A conversion is refused outright if the
  key is wrong, because converting with the wrong key would leave the data in
  place and permanently unreachable.

- **What is still readable from a stolen file**, stated plainly rather than
  glossed over: how many distinct people you talk to, how many messages went to
  each, and when. Ordering and filtering need timestamps in the clear. Full
  file-level encryption would close that too, and remains the better answer
  where its build toolchain is available. See `docs/THREAT_MODEL.md`.

## 1.6.2

- **The actual reason "Connecting to Tor" hung.** Tor refuses to share its data
  directory: when a copy left over from an earlier run of Umbra was still alive,
  the new one waited five seconds, gave up and exited — and the app, unable to
  tell "Tor died" from "Tor is still trying", reported a 900-second timeout that
  had never happened. Umbra now writes down the daemon it starts, ends a
  leftover one on the next start, and if the directory is busy anyway it waits
  and retries the same route instead of failing. Only a process Umbra itself
  recorded, and which is still called `tor`, is ever touched.
- Failures now name what Tor said, so the next problem does not need guessing.

## 1.6.1

- **Umbra connects directly first.** It used to force every start through the
  bundled bridges, for no better reason than that the bridge file shipped next
  to the program. Bridges exist to get through censorship — they are slower
  everywhere else, and the public ones we ship are the first a censor blocks, so
  many of them are dead. Direct first, like Tor Browser, bridges as the fallback
  (measured on an ordinary connection: 36 s direct, 124 s through the bundled
  bridges). Your own bridges, if you pasted any in Settings, are still tried
  first.
- A start that has stopped making progress is now noticed in about a minute
  instead of after fifteen, and the next route is tried immediately. A crashed
  run's leftover lock is cleared, and cached network data is thrown away between
  attempts. Your identity, onion address and messages are never touched.
- **When Tor does fail, it now says why.** Tor's own error was being thrown
  away, so every failure was reported as "the network is probably blocking it" —
  including failures that were nothing of the sort. The message now carries what
  Tor actually reported, and how far the start got.
- **Updates can no longer download forever.** A Tor circuit that dies mid-file
  does not close the connection, it just goes quiet — and the download waited
  for the next byte with no time limit while the app cheerfully reported
  "downloading". Every step now has a deadline and fails with a reason you can
  act on.
- **The download shows real percentages.** The signed manifest is fetched first
  and states the archive's exact size, so the bar has something to divide by
  even when GitHub's CDN sends no length. The dialog shows `42 %` next to the
  bar and how many megabytes of how many have arrived.
- If even the automatic repair fails, the connecting screen offers a
  **"Repair and try again"** button instead of just reporting failure, and the
  bootstrap percentage is shown as a number.

## 1.6.0

Changes from an outside security review of 1.5.1 (thanks, PORT).

- **Much stronger passphrase protection.** The key that unlocks the local
  database is now derived with Argon2id at 256 MiB, 3 passes, 4 lanes (was
  19 MiB, 2, 1) — the setting that makes guessing a stolen file expensive.
  Existing accounts keep opening: every database records the settings it was
  made with.
- Passphrases must now be at least 12 characters, with a strength meter and an
  explanation of why length wins.
- **Updates cannot be rolled back on you.** Each release now carries a signed
  manifest naming the version and the archive's SHA-256, and the app refuses
  anything that is not both correctly signed and newer than what is installed.
  Previously a signature alone did not stop an old release being replayed.
- **Your own Tor bridges** can be pasted in Settings. The bundled ones are
  public and therefore the first to be blocked on a censored network.
- Released binaries are stripped: no more developer paths and module names
  inside the executable.

Still open, and named plainly: the local database keeps routing data (contact
keys, group membership, timestamps) in plaintext, so someone who takes the file
learns who you talk to and when, without the passphrase. The next release
replaces those columns with a blind index. See `docs/THREAT_MODEL.md`.

## 1.5.1

- The update offer now shows what changed before you agree to anything.
- Installing an update keeps the dialog open and shows a progress bar with a
  percentage, then the signature check, then the restart. Previously the dialog
  closed and nothing visible happened for minutes.
- If an update fails, the reason is shown in red and the button becomes "Try
  again" instead of silently offering the download again.
- README banner.

## 1.5.0

- **Search** in Chats: one field finds people, groups and individual messages;
  the matching text is highlighted and opens the conversation.
- **Contact view**: click a person in Contacts to switch between the
  conversations you share with them and everything they have written to you
  (filter: everything / direct only / from groups).
- **Notifications** now say "New message on @account". A detailed form (sender →
  account: message) can be turned on, but only for accounts that sign in
  automatically — an account that asks for a passphrase every time keeps its
  messages off an unattended screen.
- Licences screen in Settings, listing every component Umbra ships or links
  against, with its licence.
- The version number moved out of the sidebar into Settings.

## 1.4.1

- Fixed: "Tor did not connect in 900 s". Starting Umbra several times left every
  copy fighting over the same Tor data directory, so none of them connected, and
  updates could not replace files the other copies held open. A second launch now
  hands over to the one already running and exits.

## 1.4.0

- **Encryption moved to the Signal protocol** (`libsignal`): PQXDH session setup
  and the Double Ratchet. PQXDH mixes a post-quantum key exchange (Kyber) into
  the handshake, so traffic recorded today cannot be opened by a quantum computer
  built later.
- Keys are still bound to your Ed25519 identity and checked against the identity
  in the invite, so nobody can slip in the middle.
- **This changes the wire format**: 1.3.x and 1.4.x cannot talk to each other.
  Both sides need to update.

## 1.3.0

- **Android**: signed APKs for arm64, armv7 and x86_64, with the official Tor
  daemon bundled inside. Experimental — not yet tested on a physical phone, no
  bridges, and background operation is unfinished.
- Umbra starts with Windows into the tray and stays reachable with the window
  closed; closing the window hides it, quitting is a choice in the tray menu.
- Fixed themes: parts of the interface kept the colours of the previous theme.
- Empty state for the chat list and day separators in conversations.

## 1.2.0

- People who write to you first land in **Waiting**, where you can read what they
  sent and then accept the conversation or block them.
- **Contacts**: save someone from a conversation, rename them (your own label,
  never sent anywhere), block or unblock.
- Groups can be renamed; the new name travels to every member.
- Desktop notifications for incoming messages.
- The account button moved to the bottom of the sidebar.

## 1.1.1

- Fixed: the update check asked the GitHub API, which is rate-limited per IP —
  over Tor that IP is a shared exit, so the app kept getting 403 and never
  updated. It now reads the version from the releases page and retries on a
  different Tor circuit when refused.

## 1.1.0

- Messages written to someone who is offline wait in an encrypted outbox on
  disk, survive closing the app, and go out by themselves once the other side
  appears.
- Message states: waiting → sent → delivered (the recipient's app confirms).
- The update check runs shortly after start and every five minutes, and asks
  before downloading anything.

## 1.0.1

- Fixed: a conversation started by the other side disappeared after a restart and
  they could never reach you again, because no contact record was created. Old
  histories are repaired on sign-in, and both sides now exchange their addresses
  after connecting.

## 1.0.0

- First release: encrypted peer-to-peer messaging over Tor onion services, with
  no server and no account registry. Text, files, group conversations, profiles,
  English/Czech, colour themes, and signed self-updates checked through Tor.
