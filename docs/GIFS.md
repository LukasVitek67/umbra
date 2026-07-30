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

**6. The Tenor key is the user's own.**

Tenor's v2 API has no shared or demo key: every client authenticates with one
its developer registered in Google Cloud. (The v1 public key `LIVDSRZULELA` that
old tutorials mention is dead — measured 2026-07-30: v1 with it returns 403, v1
without a key 401, v2 with it 400.)

That leaves two options, and neither is "it just works":

- **ship the author's key** — then every user's searches count against one quota
  belonging to one person, and the key sits in a public repository until Google
  disables it. It would also make every NullChat search attributable to the same
  application identity.
- **ask the user for theirs** — free, five minutes, and their searches are
  billed to nobody but them.

The second was chosen. The key is stored in the encrypted account like any other
secret, and the picker explains how to get one instead of surfacing whatever
status code Tenor returned. A key that is missing means no request is made at
all; a key Tenor rejects sends the user back to the same explanation with
Tenor's own words attached.

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
| Ship one Tenor key for everybody | One quota, one person's account, published in a public repo — and every search made under the same identity. |
