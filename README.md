<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<div align="center">

<img src="docs/big-sister.gif" alt="BIG SISTER IS WATCHING YOU" width="320">

### She is always watching. NullChat is what she cannot read.

</div>

# NullChat

[![CI](https://github.com/LukasVitek67/umbra/actions/workflows/ci.yml/badge.svg)](https://github.com/LukasVitek67/umbra/actions/workflows/ci.yml)
[![Dependency audit](https://github.com/LukasVitek67/umbra/actions/workflows/ci.yml/badge.svg?event=schedule)](https://github.com/LukasVitek67/umbra/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/licence-AGPL--3.0-blue)](LICENSE)

**Fully open-source, end-to-end encrypted, peer-to-peer messenger** for text and
files. Native on **Android, Windows, Linux** — no web, no central server.

Messages are sealed with the **Signal protocol** (PQXDH + Double Ratchet, from
Signal's own `libsignal`) and carried over **Tor onion services**, so there is
no server to subpoena, no directory of users, and nothing in the middle that
could hand anything over — because it never had it.

> ⚠️ **Experimental. Unaudited. Do not rely on NullChat to protect anyone whose
> safety depends on it until it has passed an independent security audit
> (planned, Phase 5).** See [`SECURITY.md`](SECURITY.md).

## Why

NullChat is built to resist mass communication surveillance (e.g. the EU "chat
control" / CSAR client-side-scanning proposals). It has **no central server** to
locate, seize, or wiretap — the failure mode that took down centrally-hosted
"secure" services. Every running instance is its own node.

## Design goals → how

| Goal | Mechanism |
|------|-----------|
| Message length can't leak content | Padding to fixed size buckets (min 256 B) — a 1-char message and a 200-char message are identical on the wire. |
| Relays can't read or run anything they carry | Onion routing over Tor (each hop peels one layer) + end-to-end Double Ratchet (only the recipient decrypts). Files are opaque encrypted blobs, never executed. |
| No central server to find | Each instance runs as a Tor v3 onion service; later, a store-and-forward relay for others. |
| Forever free & inspectable | 100% OSI-licensed dependencies; our code is AGPL-3.0. |
| You control your identity & devices | Self-sovereign key identity + a locally-held, signed, revocable device list. No account server. |

**Cardinal rule:** we do **not** invent cryptography. Every primitive is a
well-reviewed open-source crate; this project only composes them. See
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Architecture

```
Flutter app (Dart)  — UI: onboarding · chat · contacts · devices   [app/]
        │  flutter_rust_bridge (FFI)
Rust core (.so/.dll) — identity · crypto · transport · store        [core/]
```

Full detail: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Status

Vertical, compiling-and-tested slices, one at a time. Current detail:
[`STATUS.md`](STATUS.md).

- [x] Repo scaffold, workspace, docs, license
- [x] `crypto::padding` — length-hiding framing (+ property tests)
- [x] `crypto::keystore` — Argon2id + XChaCha20-Poly1305 at-rest keys
- [x] `identity` — Ed25519 identity + signed, revocable device roster + short user codes
- [x] `invite` — shareable `umbra1:` contact invites (key + onion + username, checksummed)
- [x] `crypto::ratchet` — Double Ratchet E2E sessions (vodozemac)
- [x] `store` — local SQLite + app-layer AEAD (see threat-model tradeoff)
- [x] `transport` — Tor v3 onion service via the bundled `tor` daemon (Arti deadlocked on Windows)
- [x] `api` — flutter_rust_bridge surface: the UI runs on the real core
- [x] Flutter desktop app — accounts, chats, files, profiles, EN/CZ, colour themes
- [x] `group` — group conversations fanned out over the 1:1 channels
- [x] Signed self-update from GitHub releases, checked **through Tor**
- [ ] Android build; store-and-forward so both sides need not be online at once

## Build & test

Needs **Rust**, the **Flutter SDK** and **VS Build Tools** (Desktop C++ + CMake).

```bash
cargo test -p nullchat-core          # core test suite
cd app && flutter build windows --release
```

A finished build needs `tor.exe`, `lyrebird.exe` and `bridges.txt` next to
`nullchat.exe` — take them from a release zip, or from the Tor Project's
[Tor Expert Bundle](https://www.torproject.org/download/tor/).

## Updates

The app asks GitHub for the newest release **over its own Tor circuit**, so the
check does not reveal who is running NullChat. An archive is installed only if it
carries a valid Ed25519 signature made with the author's key (the public half is
compiled into the app), and the swap never happens under a running conversation —
the app tells you to restart.

Publishing a release: `powershell -File tools/release.ps1 -Version X.Y.Z -KeyFile <key>`.

## License

[AGPL-3.0-or-later](LICENSE). Copyleft, so it stays free and editable forever.
