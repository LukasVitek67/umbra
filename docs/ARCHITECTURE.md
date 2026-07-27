<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# NullChat — Architecture

## Layers

```
┌───────────────────────────────────────────────┐
│  Flutter app (Dart) — UI, Android/Win/Linux    │  app/
│  onboarding · chat · contacts · devices        │
└───────────────▲────────────────────────────────┘
                │ flutter_rust_bridge (FFI, async)
┌───────────────┴────────────────────────────────┐
│  Rust core (one lib → .so / .dll)              │  core/
│  identity · crypto · transport · store · api   │
└─────────────────────────────────────────────────┘
```

The Rust core is compiled **once per platform** and loaded by the Flutter UI:
Android via `cargo-ndk`, Windows/Linux as a native dynamic library. All crypto
and networking lives in Rust (memory-safe); Dart only calls the API and draws.

## Cardinal rule

**We do not invent cryptography.** Every primitive below is an audited,
open-source crate. This project owns only the framing and state-machine glue.

## Rust core modules (`core/src/`)

| Module | Responsibility | Key crates (planned) | Status |
|--------|----------------|----------------------|--------|
| `crypto/padding` | Length-hiding framing (min 256 B buckets). | std only | **done** |
| `crypto/keystore` | Protect secrets at rest. | `argon2`, `chacha20poly1305`, `zeroize` | planned |
| `identity` | Ed25519 identity = "account"; per-device keypair; device certificate signed by identity key; signed, revocable **device roster**. | `ed25519-dalek`, `x25519-dalek` | planned |
| `crypto/ratchet` | End-to-end **Double Ratchet** sessions; X3DH-style prekey bundles. | `vodozemac` (Apache-2.0) | planned |
| `transport/tor` | Bootstrap Tor; run a **v3 onion service** (inbound); dial contacts' onion addresses. | `arti-client`, `tor-hsservice` | planned |
| `transport/noise` | Node-to-node **Noise** handshake over the Tor circuit; AEAD = XChaCha20-Poly1305. | `snow` | planned |
| `store` | Local **SQLCipher**-encrypted DB (keys, roster, contacts, ratchet state, history). | `rusqlite` + `bundled-sqlcipher` | planned |
| `api` | `flutter_rust_bridge` surface (async). | `flutter_rust_bridge` | planned |
| `mailbox` (Fáze 2) | Store-and-forward relay: holds onion-encrypted, padded blobs it **cannot read**; recipient fetches when online. Sealed sender. | — | later |

## Message send path (Phase 1, both peers online)

```
plaintext
  → pad()                       # fixed bucket, hides length
  → Double Ratchet encrypt      # E2E; only recipient can open
  → Noise session encrypt       # hop-to-hop authenticity/confidentiality
  → Tor circuit (onion routing)  # each relay peels one layer only
  → recipient's onion service
```

Reverse on receipt. A relay sees only onion-wrapped ciphertext; the recipient
device is the only place the Double-Ratchet layer opens.

## Identity & devices (serverless)

- **Identity key** (Ed25519) is the root of trust and *is* the account, held
  encrypted at rest (keystore).
- Each **device** has its own keypair. Linking a device = the identity key signs
  a device certificate; the certificate is appended to a **device roster** that
  is itself signed by the identity key.
- **Revocation** = a signed revocation entry appended to the roster; contacts
  refetch the roster and stop trusting the revoked device.
- "Absolute overview of your devices" = this signed roster, shown in the UI.
  Propagation is best-effort P2P (your own devices sync it; contacts cache it).

## Flutter app (`app/lib/`)

`features/onboarding`, `features/contacts`, `features/chat`,
`features/devices`, `features/settings`, and `design/` (a bespoke design system
— privacy-forward, not the generic Material default; light + dark).

## Licensing note

All planned dependencies are OSI-approved and AGPL-compatible (MIT/Apache/BSD).
`vodozemac` (Apache-2.0) is preferred over `libsignal` (AGPL, heavier).
