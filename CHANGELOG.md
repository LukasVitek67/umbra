<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Changelog

What changed in each release, in plain English. This file is the source of the
release notes on GitHub and of the "What changed" text the app shows before you
agree to an update, so it is written for the person installing it, not for the
person who wrote the code. Newest first.

Umbra is experimental and has not been independently audited.

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
