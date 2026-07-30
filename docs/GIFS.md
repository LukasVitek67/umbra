<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# GIFs — the design, and what it costs

A large GIF library means one thing technically: querying somebody else's search
service. There is no way around that — nobody can carry millions of animations
inside a messenger, and every provider that has them requires a registered API
key (measured, see below). So the question is not *whether* an external service
is involved, but exactly how much it learns and who else is exposed.

## What was chosen

**1. The recipient never contacts the service. Ever.**

This is the decision that matters most. The obvious implementation sends a
link — that is what most messengers do — and then *every recipient's device*
fetches the file from GIPHY, handing over their IP address, the time, and which
GIF they were sent. In a messenger whose entire point is that no third party
learns who talks to whom, that would be self-defeating.

Instead the **sender** downloads the GIF and transmits the bytes over the
existing end-to-end encrypted file channel. The recipient's device makes no
outside request at all; the GIF arrives exactly like a photo they were sent.

Cost: a GIF is 1–3 MB instead of a 100-byte link, and that travels over Tor.

**2. Searching goes through Tor, on its own circuit.**

Never the clearnet. And with a different circuit label than messaging uses, so
the exit node that sees "someone searched for a cat GIF" is not the same exit
that sees NullChat traffic. GIPHY sees a search term from a Tor exit — not who,
not where, and not linked to any conversation.

**3. Off until switched on, with the reason on screen.**

The picker explains what it does before it is first used. Anyone whose threat
model does not allow contacting a third party at all should be able to make that
decision knowingly rather than discover it afterwards — and the honest answer
for them is: leave it off and send GIFs as files.

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
- the download URL must be on a GIPHY media host, compared as an exact host
  after being cut out of the URL. A `starts_with` check would accept
  `https://media.giphy.com.evil.example/`, so a tampered search response cannot
  turn the fetcher into a general-purpose one;
- received GIFs go through the same path as any other received file, which
  already caps size and sanitises names.

**6. The key ships with the build; the user sets up nothing.**

Every GIF service requires a registered API key. Measured 2026-07-30, so this is
not folklore:

| endpoint | result |
|---|---|
| Tenor v1 with the old public `LIVDSRZULELA` | 403 |
| Tenor v1 with no key | 401 |
| Tenor v2 with that key | 400 |
| Giphy with the public beta key `dc6zaTOxFJmzC` | 403 |
| Giphy with no key | 401 |

Releases therefore carry a key, compiled in from `NULLCHAT_GIPHY_KEY` at build
time (`tools/release.ps1` reads it from `~/Documents/nullchat-giphy-key.txt`, CI
from the `GIPHY_KEY` secret). Not written into the source, because the
repository is public and keys in public repositories get scraped and then
disabled — which would break GIF search for every real user. In the binary it is
still extractable by anyone who looks, and that is acceptable: it identifies the
*application*, not a person, and unlocks nothing but GIF search.

A build from a plain checkout has no key and falls back to one the user
supplies; the picker explains where to get it. The user's own key always wins,
so an exhausted or revoked shipped key can be worked around without a release.

## Why GIPHY and not Tenor

Tenor was the original provider. Google discontinued it: the developer
documentation now reads "Tenor API Service Discontinuation" and "As of Jan 2026,
we are no longer accepting new API clients", and the API cannot be enabled on a
new Cloud project — it is absent from the API Library and its enablement page
does not load.

GIPHY publishes Tenor-compatible endpoints (`api.giphy.com/v2/search`,
`/v2/featured`) that keep Tenor's request and response shape, so the migration
changed the host and the key, not the parsing. `contentfilter=off` maps to G,
PG, PG-13 and R — everything the API will serve.

## What this still leaks

Named plainly, because the list above reads reassuringly and this part is the
price:

- **GIPHY learns the search terms**, from a Tor exit. Not who typed them — but
  "someone" searched them, with timing. Search for something identifying and
  the timing is a correlation risk like any other.
- **Sending a GIF is visible as a file transfer of that size** to anyone who
  could already see file transfers, which over Tor is the peers themselves.
- **One request per search leaves the machine**, to a company this project
  otherwise takes care to avoid. That is why the feature is opt-in.

## Where this design and GIPHY's terms disagree

Stated openly rather than left for someone to discover: GIPHY's API terms
require that requests come directly from the client and prohibit proxying,
caching, or storing copies of GIPHY media. NullChat downloads the asset on the
sender's device and forwards a *copy* over an encrypted channel, precisely so
the recipient never appears at GIPHY.

Complying literally would mean sending links, which hands every recipient's IP
address and the time to a third party — the exact leak this design exists to
prevent. The project chooses the users' privacy over the provider's preference,
and whoever operates a fork should know that this is the trade being made.

## What was rejected

| Idea | Why not |
|---|---|
| Send the GIF URL, recipient fetches it | Hands every recipient's IP to the provider. This is the common implementation and it is the wrong one here. |
| Bundle a GIF library in the app | A large library cannot fit in an installer; it would be a token gesture. |
| Proxy searches through a NullChat server | There is no server. Adding one would create the single point of surveillance the whole project exists to avoid — it would see every search from every user — and it would still need the same API key. |
| A keyless open source (Openverse, Wikimedia Commons) | Keyless and licence-clean, but not a GIF keyboard: measured 2026-07-30, "facepalm" returns 1 result and "excited" 43. |
| Put the shipped key in the source | Public repo, scraped within days, disabled by the provider — GIF search then breaks for everyone until the next release. |
| Make every user register their own key | The only feature in NullChat with a setup step, for something every other messenger does by pressing a button. |
| Cache GIFs on disk for speed | A list of what someone searched for, sitting outside the encrypted database. |
