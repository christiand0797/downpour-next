# Alert replay gate

`AlertReplayDiff` (Core) compares an expected alert set with what the current code produces. Until DN-072 nothing
produced a corpus, so a rule change could only be caught by a person noticing different alerts. This gate closes that:

- `tests/Downpour.Tests/replay/alert-replay-corpus.json` holds synthetic Windows event records and the alert set the
  built-in rules graded them into. It contains no host names, user paths, addresses, captured events or file contents.
- `AlertReplayRunner` (Core) loads the corpus, looks every case up in `SecurityEventCatalog`/`SysmonCatalog`, and
  builds the same dedup identity the service uses (`AlertProjection.DedupKey`). No event log, network, signature
  check or service pipe is touched, so the gate runs offline and unelevated.
- `AlertReplayDiff.Compare` reports a missing alert, an unexpected alert, or a severity change by dedup key.
  `tools/ci/run-gates.ps1` runs `AlertReplayGateTests` as its own step and stops the gate on any difference.
- `AlertReplayGateTests` also refuses a corpus case no current rule grades, refuses malformed or oversized corpora,
  and scans the corpus text for drive paths, UNC paths, profile paths, e-mail addresses and IPv4 literals.

## Updating the corpus

Only update it together with an intentional rule, severity or identity change, and review the expected diff as part of
that change. Never paste captured events into it. The corpus covers catalog grading and dedup identity; it does not
replay Sigma/AMSI matches, feed parsers or the service-install signature re-grade, which have their own tests.

Run only the gate:

```powershell
dotnet test Downpour.slnx -c Debug --filter "FullyQualifiedName~AlertReplayGateTests"
```
