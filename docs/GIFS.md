<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# GIFs — the design, and what it costs

A large uncensored GIF library means one thing technically: querying somebody
else's search service. There is no way around that — nobody can carry millions
of animations inside a messenger. So the question is not *whether* an external
service is involved, but exactly how much it learns and who else is exposed.

## What was chosen

**1. The recipient never contacts the service. Ever.**

This is the decision that matters most. The obvious implementation sends a
link — that is what most messengers do — and then *every recipient's device*
fetches the file from Tenor, handing over their IP address, the time, and which
GIF they were sent. In a messenger whose entire point is that no third party
learns who talks to whom, that would be self-defeating.

Instead the **sender** downloads the GIF and transmits the bytes over the
existing end-to-end encrypted file channel. The recipient's device makes no
outside request at all; the GIF arrives exactly like a photo they were sent.

Cost: a GIF is 1–3 MB instead of a 100-byte link, and that travels over Tor.

**2. Searching goes through Tor, on its own circuit.**

Never the clearnet. And with a different circuit label than messaging uses, so
the exit node that sees "someone searched for a cat GIF" is not the same exit
that sees NullChat traffic. Tenor sees a search term from a Tor exit — not who,
not where, and not linked to any conversation.

**3. Off until switched on, with the reason on screen.**

The picker explains what it does before it is first used. Anyone whose threat
model does not allow contacting Google's servers at all should be able to make
that decision knowingly rather than discover it afterwards — and the honest
answer for them is: leave it off and send GIFs as files.

**4. Nothing cached on disk.**

Search results and previews live in memory and die with the app. A disk cache
of what someone searched for is a record of what they searched for, and a
duress passphrase cannot reach it if it is outside the encrypted database.

**5. Hard limits, because a decoder is an attack surface.**

Image decoders have a long history of memory-corruption bugs — the 2023 WebP
flaw (CVE-2023-4863) was exploitable with no interaction at all. So:

- a GIF over **8 MB** is refused before a single byte is decoded;
- dimensions over 2000 px are refused;
- the payload must actually start with `GIF87a`/`GIF89a` — a file that claims
  to be a GIF and is not never reaches the decoder;
- received GIFs go through the same path as any other received file, which
  already caps size and sanitises names.

**6. The key ships with the build; the user never sets anything up.**

Every GIF service now requires a registered API key. Measured 2026-07-30, so
this is not folklore:

| endpoint | result |
|---|---|
| Tenor v1 with the old public `LIVDSRZULELA` | 403 |
| Tenor v1 with no key | 401 |
| Tenor v2 with that key | 400 |
| Giphy with the public beta key `dc6zaTOxFJmzC` | 403 |
| Giphy with no key | 401 |

So there is no keyless path, and "ask every user to register one" is a setup
step in a messenger where nothing else has one. Releases therefore carry a key,
compiled in from `NULLCHAT_TENOR_KEY` at build time
(`tools/release.ps1` reads it from `~/Documents/nullchat-tenor-key.txt`, CI from
the `TENOR_KEY` secret).

Not written into the source, because the repository is public and keys in public
repositories get scraped and then disabled — which would break GIF search for
every real user. In the binary it is still extractable by anyone who looks, and
that is acceptable: it identifies the *application*, not a person, and unlocks
nothing but GIF search.

Two consequences worth stating:

- **A build from a plain checkout has no key.** That is deliberate, not a bug:
  forks do not spend the author's quota. Such a build falls back to a key the
  user supplies, and the picker explains where to get one.
- **The user's own key always wins.** If the shipped key is exhausted or
  revoked, anyone can paste theirs into Settings → GIF search and keep going
  without waiting for a release. It is stored in the encrypted account like any
  other secret.

## What this still leaks

Named plainly, because the list above reads reassuringly and this part is the
price:

- **Tenor learns the search terms**, from a Tor exit. Not who typed them — but
  "someone" searched them, with timing. Search for something identifying and
  the timing is a correlation risk like any other.
- **Sending a GIF is visible as a file transfer of that size** to anyone who
  could already see file transfers, which over Tor is the peers themselves.
- **Google is Google.** Tenor is theirs. Using it means one request per search
  to a company this project otherwise takes care to avoid.

If that is unacceptable for a particular person, the feature stays off and
nothing about NullChat changes. That is why it is opt-in.

## What was rejected

| Idea | Why not |
|---|---|
| Send the Tenor URL, recipient fetches it | Hands every recipient's IP to Google. This is the common implementation and it is the wrong one here. |
| Bundle a GIF library in the app | A "large uncensored library" cannot fit in an installer; it would be a token gesture. |
| Proxy searches through a NullChat server | There is no server, and adding one to fetch GIFs would create the single point of surveillance the whole project exists to avoid. |
| Cache GIFs on disk for speed | A list of what someone searched for, sitting outside the encrypted database. |
| Put the shipped key in the source | Public repo, scraped within days, disabled by Google — GIF search then breaks for everyone until the next release. |
| Make every user register their own key | The only feature in NullChat with a setup step, for something every other messenger does by pressing a button. |
