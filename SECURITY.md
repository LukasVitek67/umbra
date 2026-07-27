<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Security policy

## Reporting a vulnerability

Report privately through GitHub's **[Security Advisories](https://github.com/LukasVitek67/umbra/security/advisories/new)**,
not as a public issue. A public issue tells everyone about the hole before there
is a fix, and the people this software is meant to protect are the ones who pay
for that.

You can expect:

- an acknowledgement within **7 days**;
- an assessment (is it real, how bad, what is affected) within **14 days**;
- a fix released as soon as it is ready, with credit if you want it.

There is no bug bounty. This is a one-person project without funding, and
promising money it does not have would be worse than saying so.

## What Umbra has and has not been through

Stated plainly, because getting this wrong could put someone in danger.

**Umbra has never been independently audited.** No security firm has reviewed
this code. For comparison, Briar — the closest comparable project — has had two
independent audits (Cure53 in 2017, Radically Open Security in 2024). If you
need a messenger whose cryptography strangers have checked, use one of those
instead, today.

What *has* been done, all of it by the author and all of it re-runnable by you:

| | |
|---|---|
| Test suite | ~110 tests, including ~140 000 malformed inputs through every parser a hostile peer can reach (`core/tests/hostile_input.rs`) |
| Dependency audit | `cargo audit` against the RustSec database — no known vulnerabilities |
| Static analysis | `cargo clippy` across the workspace |
| Outside opinion | One informal review of 1.5.1 by a non-author, which found six issues; five were fixed in 1.6.0 and the sixth (plaintext routing metadata) in 1.7.0 |

Everything above runs in [CI](https://github.com/LukasVitek67/umbra/actions) on
every push, so the results are not something you have to take on trust from a
screenshot.

Running the tests yourself:

```bash
cargo test --workspace
cargo audit
```

`docs/SECURITY_TESTING.md` describes what still has to be tested by hand — most
importantly, verifying that nothing ever leaves the machine outside Tor.

## Known limitations

These are design limits, not bugs, and they are documented rather than hidden:

- `docs/THREAT_MODEL.md` — what Umbra protects, and what it does not
- `docs/DURESS.md` — where emergency passphrases stop working
- Groups use a flat roster: any member can add or remove anyone. A hostile
  member is not defended against yet.
- Releases are signed but **not yet reproducible**, so a signature proves the
  author built it, not that it matches this source.

## Supported versions

Only the latest release. This is experimental software under active development;
there is no long-term support branch and pretending otherwise would be a lie.
