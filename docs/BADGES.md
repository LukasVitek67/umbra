<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Badges and certifications — what is real and what is not

Written down because the temptation to overstate is strong, and because in a
tool like this an overstatement is not marketing, it is a person deciding to
trust something they should not have.

## There is no certificate for passing your own tests

`cargo audit`, `cargo clippy`, and the fuzzing suite are tools you run on your
own code. They issue nothing. Nobody signs their output and nobody stands behind
it. "Passed `cargo audit`" means "no *known* vulnerability in our dependencies
today" — the floor, not an achievement.

Claiming otherwise would be false, and it is exactly the kind of claim a person
in danger might rely on.

## What can honestly be claimed today

| Claim | Evidence | Honest? |
|---|---|---|
| "Tests run on every commit, in public" | the CI badge and its logs | yes |
| "No known vulnerabilities in dependencies" | `cargo audit` in CI | yes, and only as of the last run |
| "Every parser is fuzzed with ~140 000 malformed inputs" | `core/tests/hostile_input.rs` | yes |
| "Releases are signed by the author" | `MANIFEST-<version>.txt.sig` | yes |
| "Independently audited" | — | **no. Never claim this.** |
| "Reproducible builds" | — | not yet |

## Badges worth getting, in order of effort

### 1. OpenSSF Best Practices Badge — free, self-certified

<https://www.bestpractices.dev>

A checklist from the Linux Foundation covering how a project is *run*: a
security policy, a public bug tracker, tests that run automatically, released
signatures, documented crypto choices. Levels: **passing → silver → gold**.

It is self-certified, which is both why it is achievable and why it is not an
audit — it says "this project follows good practice", never "this code is
secure". Presenting it as the latter would be dishonest.

**Where NullChat stands against the *passing* criteria** (assessed against the
current repository):

| Criterion | Status |
|---|---|
| Public repository, OSI licence | met — AGPL-3.0, full text in `LICENSE` (added 28 Jul 2026; **it was missing until then**, which also breached libsignal's own AGPL terms) |
| Documented how to contribute | met — `CONTRIBUTING.md` (added 28 Jul 2026) |
| **Security policy / how to report a hole** | met — `SECURITY.md` |
| Automated test suite | met — ~110 tests |
| Tests run on every change | met — CI |
| New functionality comes with tests | met, consistently |
| Static analysis | met — clippy in CI |
| Dependency vulnerability checks | met — `cargo audit` in CI |
| Cryptography: published, standard algorithms only | met — Signal protocol, Ed25519, ML-DSA-65, Argon2id, XChaCha20-Poly1305 |
| No proprietary crypto | met — nothing home-grown |
| Signed releases | met — Ed25519 |
| **Reproducible builds** | **not met** (silver-level requirement) |
| Two or more maintainers | **not met** (gold-level requirement) |

So *passing* looks reachable now; *silver* needs reproducible builds; *gold*
needs a second maintainer, which is a people problem, not a code problem.

**This has to be submitted by the project owner** — it is a statement about the
project made in the owner's name, so it is not something anyone else should file
for you. The table above is the material for it.

### 2. OpenSSF Scorecard — free, automatic

<https://scorecard.dev> — already wired up in `.github/workflows/scorecard.yml`.
It scores the repository's process (branch protection, pinned actions, signed
releases, whether CI exists). No human involvement, no claim about the
cryptography.

### 3. An independent audit — the only one that means "reviewed"

This is what Briar has and NullChat does not. Two routes:

- **Pay for it.** Cure53, Radically Open Security, Trail of Bits, NCC Group.
  A review of this size is realistically tens of thousands of euros.
- **Apply for funded review.** The [Open Technology Fund](https://www.opentech.fund)
  ran the audits Briar went through, and [OSTIF](https://ostif.org) arranges
  audits for open-source projects. Both fund work in the public interest and
  cost the project nothing but the application — and both expect a project with
  real users and a maintained codebase, so this is worth applying for *after*
  NullChat has been used by more than its author.

## A worked example of getting this wrong

The first draft of the table above said the licence and contribution criteria
were "met". Neither was: the repository had **no `LICENSE` file at all** — only
SPDX headers in source files — and no `CONTRIBUTING.md`. Both were written down
as satisfied because they *felt* satisfied, and the check happened afterwards.

That is the failure mode this whole page is about, in miniature. The missing
licence was not a formality either: NullChat links against libsignal, which is
AGPL-3.0 and requires the full licence text to be distributed with anything
built on it. NullChat had been shipping releases without it.

Check first, then claim. Including here.

## The rule

Publish what can be checked, and name what has not been done in the same breath.
The `SECURITY.md` in this repository opens by saying NullChat has never been
audited and points people at Briar if they need reviewed software today. That
sentence is worth more to a person at risk than every badge on this page.
