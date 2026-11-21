# IDN and lookalike names in the resolver cache

A Cyrillic "і" is a different character from an ASCII "i", so `mіcrosoft.com` is a different domain. It does not match a
name-based block, and it may not appear on any reputation list yet. `DomainConfusables` already decoded and folded those
names, but nothing in the product used it. Since 0.1.34 the DNS route does, as context only.

## What happens now

1. `DnsInventoryProvider` captures the Windows resolver cache exactly as before.
2. For each cached name it calls `DomainConfusables.Describe`. That is a bounded wrapper around the tested `Assess`:
   empty input, whitespace, a name over 253 characters or an unparseable name returns `null` instead of throwing, so a
   hostile cache entry can never fail the capture.
3. A name is included only when its decoded form contains a non-ASCII character, mixes writing systems, or resembles one
   of the protected brands. Every plain ASCII name carries no extra payload.
4. `DnsCacheEntry.Lookalike` is optional; `DnsInventoryClient` accepts a missing block, bounds the decoded name, scripts
   and verdict to 1,024 characters each and the brand list to 8, and rejects anything else.
5. The DNS page shows an **IDN and Lookalike Names** panel: how many names resemble a protected brand, how many decoded
   in total, the original name, the decoded form and the Core verdict. The row badge is `BRAND`, `MIXED` or `IDN`.

## What it deliberately does not do

- It does not block, resolve, flush or reroute anything. There is no action broker call on this path.
- It does not raise an alert or a finding, and it does not change the DGA risk score. A lookalike in the cache is
  context for a person, not a confirmed compromise: shared hosting, IDN registrars and international sites all produce
  legitimate non-ASCII names.
- It does not persist decoded names. Nothing new is written to disk; the assessment lives in the pipe snapshot only.
- It does not replace the brand list with a registry feed. The protected brands are a fixed, small list in Core, so an
  unlisted brand is not covered.

## Verification

- 9 new tests in `DnsInventoryTests`: plain ASCII names stay unlabelled; `münchen.de`, `xn--80ak6aa92e.com` and
  `mіcrosoft.com` decode; the protected brand is named with mixed-script detection; null, whitespace, 254-character and
  non-domain input return `null`; the client accepts the bounded block and rejects nine brands, a 1,025-character
  verdict and a null brand list; a live capture's entries agree with `Describe`.
- `dotnet build Downpour.slnx -c Debug`: 0 warnings, 0 errors. Full Debug suite: 1,508 passed, 0 failed.
- Not checked by hand: the panel has not been viewed at any width, and no real cached IDN name was confirmed on screen.
  The development machine's resolver cache was not inspected for lookalikes, so the empty state is the likely one here.
