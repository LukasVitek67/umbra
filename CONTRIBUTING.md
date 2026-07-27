<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Contributing to NullChat

## Reporting a security hole

**Not here.** See [`SECURITY.md`](SECURITY.md) — report it privately, so there
is a fix before there is an announcement.

## Reporting a bug

Open an [issue](https://github.com/LukasVitek67/umbra/issues) with:

- what you did, what happened, what you expected instead;
- your version (Settings → About) and operating system;
- for a connection problem, the last few lines of `tor.log` from your account
  directory.

Do **not** attach `nullchat.db`, `nullchat.salt`, or anything from `hs/` — those are
your identity and your history. `nullchat-app.log` is safe to attach: it records
only event types and sizes, never message content.

## Changing code

Everything must pass before a change is considered:

```bash
cargo test --workspace
cargo clippy --workspace
cd app && flutter analyze && flutter test
```

CI runs the same on every push.

Beyond that, three rules that are not negotiable in this codebase:

1. **No home-grown cryptography.** Every primitive comes from a reviewed crate —
   Signal's `libsignal`, RustCrypto, `ed25519-dalek`, `argon2`. If a change
   needs a new one, say in the pull request why an existing one does not do.
2. **New behaviour comes with a test**, and for anything security-relevant the
   test should demonstrate the *failure* being prevented, not just the happy
   path. `core/src/crypto/pq.rs` shows the shape: a signature truncated to its
   classical half is refused, and there is a test that says so.
3. **Comments explain why, not what.** The code says what it does. Reviewing
   this project a year from now means understanding the reasoning, especially
   where something looks odd on purpose.

## Documenting limitations

If a change adds a guarantee, it usually also adds a limit. Both go in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Claiming more than the software
delivers is the one bug in this project that could get someone hurt, so an
honest sentence about what is *not* protected is as valuable as the feature.

## Licence

NullChat is **AGPL-3.0-or-later**, and links against `libsignal`, which is AGPL as
well. Contributions are accepted under the same licence. Every source file
carries an `SPDX-License-Identifier` header; keep it.
