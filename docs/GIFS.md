<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# GIF search — built, then removed

NullChat had a GIF picker in 2.0.0–2.1.1. It is gone as of 2.1.2. This document
stays because *why* it is gone is more useful than the feature was, and because
anyone proposing to add it back should have to answer what is below.

GIFs can still be sent: a `.gif` is a file, and files go through the encrypted
attachment channel like anything else. What is gone is *searching* somebody
else's library from inside the app.

## What it did

A large uncensored GIF library means querying somebody else's search service —
nobody can carry millions of animations inside a messenger. The design tried to
pay as little as possible for that:

- **The recipient never contacted the service.** The sender downloaded the GIF
  and transmitted the bytes over the existing end-to-end encrypted file channel.
  The obvious implementation — send a link — makes *every recipient's device*
  fetch from the provider, handing over their IP address, the time, and which
  GIF they were sent.
- **Searching went through Tor on its own circuit**, so the exit that saw a
  search term was not the exit carrying anything else.
- **Off until switched on**, with the explanation on screen first.
- **Nothing cached on disk**, so there was no record of what was searched.
- **Hard limits before decoding**: 8 MB, 2000 px, and a real `GIF87a`/`GIF89a`
  header, because image decoders are a long-standing source of memory-corruption
  bugs (CVE-2023-4863 needed no interaction at all).

## Why it was removed

**1. Tenor is discontinued.** Google's own documentation, read 2026-07-30:
"Tenor API Service Discontinuation" and "As of Jan 2026, we are no longer
accepting new API clients." The API cannot be enabled on a new Cloud project —
it is not in the API Library and its enablement page does not load. So the
feature could not work for anyone setting up NullChat today, and would stop
working for everyone else when the service closes.

**2. There is no keyless provider.** Measured the same day:

| endpoint | result |
|---|---|
| Tenor v1 with the old public `LIVDSRZULELA` | 403 |
| Tenor v1 with no key | 401 |
| Tenor v2 with that key | 400 |
| Giphy with the public beta key `dc6zaTOxFJmzC` | 403 |
| Giphy with no key | 401 |

**3. The obvious replacement forbids the part that made it safe.** GIPHY is the
natural successor — it even offers Tenor-compatible endpoints — but its API
terms require that requests come directly from the client and prohibit
proxying, caching, or storing copies of GIPHY media. NullChat's whole design is
that the sender fetches the asset and hands a *copy* to the recipient so that
the recipient never appears at the provider. Complying means sending links,
which reintroduces exactly the leak the design existed to prevent.

So the choice was: break a provider's terms, leak every recipient's IP, or drop
the feature. For a messenger whose reason to exist is that no third party learns
who talks to whom, dropping it is the only one of the three that is consistent
with the rest of the app.

## If it ever comes back

The bar it has to clear:

1. A provider whose terms permit the sender to download an asset and forward a
   copy over an encrypted channel — in writing, not by omission.
2. No credential that has to be shipped inside a public application, and no
   setup step for the user.
3. Everything in "What it did" above, unchanged: own Tor circuit, opt-in, no
   disk cache, hard limits before any decoder sees a byte.

Self-hosting an index would satisfy (1) and (2) and fail the project's other
rule: NullChat has no server, and adding one for GIFs would create the single
point of surveillance the design exists to avoid.
