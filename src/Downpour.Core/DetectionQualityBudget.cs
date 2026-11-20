using System.Text.Json;

namespace Downpour.Core;

/// <summary>
/// Reads the scanner's recorded clean-corpus measurements and decides whether a rule stays within its recorded
/// noise budget. A rule that matched clean Windows files before may not match more of them without review, and any
/// rule absent from the file has a budget of zero unless it is explicitly below the reporting floor. This turns
/// "108 of 179 rules are noisy" from a note into a gate a build can enforce.
/// </summary>
public sealed class DetectionQualityBudget
{
    public const int SchemaVersion = 1;
    private readonly Dictionary<string, int> _cleanMatches;

    private DetectionQualityBudget(Dictionary<string, int> cleanMatches, int ruleCount, string corpus)
    {
        _cleanMatches = cleanMatches;
        RuleCount = ruleCount;
        Corpus = corpus;
    }

    public int RuleCount { get; }
    public string Corpus { get; }
    public IReadOnlyDictionary<string, int> CleanFileMatches => _cleanMatches;

    public static DetectionQualityBudget Load(Stream json)
    {
        ArgumentNullException.ThrowIfNull(json);
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException("The rule-quality file is not an object.");
        var schema = root.TryGetProperty("schemaVersion", out var schemaElement) && schemaElement.TryGetInt32(out var value) ? value : 0;
        if (schema != SchemaVersion) throw new InvalidDataException($"Unsupported rule-quality schema {schema}.");
        var ruleCount = root.TryGetProperty("ruleCount", out var countElement) && countElement.TryGetInt32(out var count) ? count : 0;
        var corpus = root.TryGetProperty("corpus", out var corpusElement) && corpusElement.ValueKind == JsonValueKind.String
            ? corpusElement.GetString() ?? "" : "";
        var matches = new Dictionary<string, int>(StringComparer.Ordinal);
        if (root.TryGetProperty("lowConfidence", out var low) && low.ValueKind == JsonValueKind.Object)
            foreach (var property in low.EnumerateObject())
                if (property.Value.TryGetInt32(out var hits) && hits > 0)
                    matches[property.Name] = hits;
        return new(matches, ruleCount, corpus);
    }

    public bool IsLowConfidence(string rule) => _cleanMatches.ContainsKey(rule);

    /// <summary>True when the measured clean-file matches stay within the recorded budget for that rule.</summary>
    public bool WithinBudget(string rule, int cleanMatches) =>
        !_cleanMatches.TryGetValue(rule, out var recorded) ? cleanMatches == 0 : cleanMatches <= recorded;
}
