using System.Text.Json;

namespace Downpour.Scanner;

/// <summary>Reads rule_quality.json. A missing or unreadable file marks every rule low confidence (fail quiet, not loud).</summary>
public static class RuleQuality
{
    public const string AllRules = "*";

    public static IReadOnlySet<string> Load(string path)
    {
        try
        {
            if (!File.Exists(path) || new FileInfo(path).Length > 1024 * 1024) return new HashSet<string> { AllRules };
            using var document = JsonDocument.Parse(File.ReadAllBytes(path));
            if (!document.RootElement.TryGetProperty("lowConfidence", out var rules) || rules.ValueKind != JsonValueKind.Object)
                return new HashSet<string> { AllRules };
            return rules.EnumerateObject().Select(rule => rule.Name).ToHashSet(StringComparer.Ordinal);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return new HashSet<string> { AllRules };
        }
    }
}
