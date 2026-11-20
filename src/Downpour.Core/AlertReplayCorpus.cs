using System.Globalization;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

/// <summary>One synthetic event record replayed through the current built-in grading rules.</summary>
public sealed record AlertReplayCase(
    string LogName,
    string Provider,
    int EventId,
    long? RecordId,
    DateTimeOffset CreatedAtUtc,
    int Occurrences = 1);

public sealed record AlertReplayCorpus(
    int SchemaVersion,
    string Description,
    IReadOnlyList<AlertReplayCase> Cases,
    IReadOnlyList<ReplayedAlert> Expected);

/// <summary>
/// Loads a recorded, synthetic-only replay corpus and projects it through the same rule catalog and dedup identity the
/// live service uses. The corpus is deliberately offline: no event log, network, signature check or host data.
/// </summary>
public static class AlertReplayRunner
{
    public const int CurrentSchemaVersion = 1;
    public const int MaximumCases = 512;
    public const int MaximumExpectedAlerts = 10_000;
    public const int MaximumTextLength = 512;
    public const int MaximumCorpusBytes = 1_000_000;

    public static AlertReplayCorpus Parse(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        if (json.Length > MaximumCorpusBytes)
            throw new InvalidDataException("The replay corpus is larger than the allowed bound.");

        CorpusFile? file;
        try
        {
            file = JsonConvert.DeserializeObject<CorpusFile>(json, new JsonSerializerSettings
            {
                MaxDepth = 32,
                MissingMemberHandling = MissingMemberHandling.Error,
                DateParseHandling = DateParseHandling.None,
                Culture = CultureInfo.InvariantCulture,
            });
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The replay corpus is not valid JSON.", exception);
        }
        if (file is null) throw new InvalidDataException("The replay corpus is empty.");

        if (file.SchemaVersion != CurrentSchemaVersion)
            throw new InvalidDataException($"Unsupported replay corpus schema version {file.SchemaVersion}.");
        if (file.Description is not { Length: > 0 and <= MaximumTextLength })
            throw new InvalidDataException("The replay corpus needs a bounded description.");
        if (file.Cases is not { Count: > 0 and <= MaximumCases })
            throw new InvalidDataException($"The replay corpus needs between 1 and {MaximumCases:N0} cases.");
        if (file.Expected is not { Count: > 0 and <= MaximumExpectedAlerts })
            throw new InvalidDataException($"The replay corpus needs between 1 and {MaximumExpectedAlerts:N0} expected alerts.");

        var cases = new List<AlertReplayCase>(file.Cases.Count);
        for (var index = 0; index < file.Cases.Count; index++)
        {
            var item = file.Cases[index] ?? throw new InvalidDataException($"Replay case {index} is missing.");
            if (item.LogName is not { Length: > 0 and <= 128 } || item.Provider is not { Length: > 0 and <= 128 })
                throw new InvalidDataException($"Replay case {index} has an invalid log or provider name.");
            if (item.EventId is < 1 or > 65_535)
                throw new InvalidDataException($"Replay case {index} has an invalid event id.");
            if (item.RecordId is <= 0)
                throw new InvalidDataException($"Replay case {index} has an invalid record id.");
            if (item.Occurrences is < 1 or > 1_000_000_000)
                throw new InvalidDataException($"Replay case {index} has an invalid occurrence count.");
            if (item.CreatedAtUtc == default || item.CreatedAtUtc.Offset != TimeSpan.Zero)
                throw new InvalidDataException($"Replay case {index} needs an explicit UTC event time.");
            cases.Add(new AlertReplayCase(item.LogName, item.Provider, item.EventId, item.RecordId,
                item.CreatedAtUtc, item.Occurrences ?? 1));
        }

        var expected = new List<ReplayedAlert>(file.Expected.Count);
        for (var index = 0; index < file.Expected.Count; index++)
        {
            var item = file.Expected[index] ?? throw new InvalidDataException($"Expected alert {index} is missing.");
            if (item.DedupKey is not { Length: > 0 and <= MaximumTextLength } ||
                item.RuleId is not { Length: > 0 and <= MaximumTextLength } ||
                item.Severity is not { Length: > 0 } || !SecurityFindingCatalog.Severities.Contains(item.Severity))
            {
                throw new InvalidDataException($"Expected alert {index} did not pass its contract validation.");
            }
            expected.Add(new ReplayedAlert(item.DedupKey, item.Severity, item.RuleId));
        }

        return new AlertReplayCorpus(file.SchemaVersion, file.Description, cases, expected);
    }

    /// <summary>Projects every case through the current rules; an event no rule grades makes the corpus stale.</summary>
    public static IReadOnlyList<ReplayedAlert> Replay(IReadOnlyList<AlertReplayCase> cases)
    {
        ArgumentNullException.ThrowIfNull(cases);
        if (cases.Count is < 1 or > MaximumCases)
            throw new InvalidDataException($"A replay needs between 1 and {MaximumCases:N0} cases.");

        var alerts = new List<ReplayedAlert>(cases.Count);
        for (var index = 0; index < cases.Count; index++)
        {
            var item = cases[index] ?? throw new InvalidDataException($"Replay case {index} is missing.");
            if (!SecurityEventCatalog.TryGetRule(item.LogName, item.EventId, out var rule))
                throw new InvalidDataException(
                    $"Replay case {index} names {item.LogName} event {item.EventId}, which no current rule grades.");
            var observation = new SecurityEventObservation(item.LogName, item.Provider, item.EventId, item.RecordId,
                item.CreatedAtUtc, rule.Severity, rule.Technique, rule.Summary, item.Occurrences);
            alerts.Add(new ReplayedAlert(AlertProjection.DedupKey(observation), rule.Severity, $"{item.LogName}/{item.EventId}"));
        }
        return alerts;
    }

    public static IReadOnlyList<ReplayDifference> Evaluate(AlertReplayCorpus corpus)
    {
        ArgumentNullException.ThrowIfNull(corpus);
        return AlertReplayDiff.Compare(corpus.Expected, Replay(corpus.Cases));
    }

    private sealed class CorpusFile
    {
        public int SchemaVersion { get; set; }
        public string? Description { get; set; }
        public List<CaseFile?>? Cases { get; set; }
        public List<ExpectedFile?>? Expected { get; set; }
    }

    private sealed class CaseFile
    {
        public string? LogName { get; set; }
        public string? Provider { get; set; }
        public int EventId { get; set; }
        public long? RecordId { get; set; }
        public DateTimeOffset CreatedAtUtc { get; set; }
        public int? Occurrences { get; set; }
    }

    private sealed class ExpectedFile
    {
        public string? DedupKey { get; set; }
        public string? Severity { get; set; }
        public string? RuleId { get; set; }
    }
}
