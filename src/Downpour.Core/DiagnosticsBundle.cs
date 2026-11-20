using System.Text;
using System.Text.RegularExpressions;

namespace Downpour.Core;

public sealed record DiagnosticSection(string Name, IReadOnlyList<string> Lines);

/// <summary>
/// Builds a local-only support artefact. Everything stays on the machine until the person chooses where to save it;
/// nothing is uploaded. Lines are redacted before they are placed in the bundle: profile paths, key material and
/// long token-like strings never leave the app, and each section is bounded so a runaway error cannot create a
/// multi-megabyte file.
/// </summary>
public static class DiagnosticsBundle
{
    public const int MaximumLinesPerSection = 50;
    public const int MaximumTotalLines = 400;

    public static IReadOnlyList<DiagnosticSection> Build(IEnumerable<DiagnosticSection> sections)
    {
        ArgumentNullException.ThrowIfNull(sections);
        var result = new List<DiagnosticSection>();
        var total = 0;
        foreach (var section in sections)
        {
            if (total >= MaximumTotalLines) break;
            if (string.IsNullOrWhiteSpace(section.Name)) continue;
            var take = Math.Min(section.Lines.Count, Math.Min(MaximumLinesPerSection, MaximumTotalLines - total));
            var lines = section.Lines.Take(take).Select(Redact).ToArray();
            if (section.Lines.Count > take) lines = [.. lines, $"... truncated at {take} lines."];
            result.Add(new DiagnosticSection(Redact(section.Name), lines));
            total += take;
        }
        return result;
    }

    private static readonly Regex ProfilePathPattern = new(@"[A-Za-z]:\\Users\\[^\\\s""']+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex KeyHeaderPattern = new(@"(Auth-Key|Authorization|X-Api-Key)\s*[:=]\s*\S+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex LongTokenPattern = new(@"\b[A-Za-z0-9+/_-]{40,}\b", RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static string Redact(string value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        var text = value.Length > 600 ? value[..600] : value;
        text = ProfilePathPattern.Replace(text, @"%USERPROFILE%");
        text = KeyHeaderPattern.Replace(text, "[redacted header]");
        text = LongTokenPattern.Replace(text, "[redacted token]");
        return text;
    }

    public static string Render(IReadOnlyList<DiagnosticSection> sections, string appVersion)
    {
        ArgumentNullException.ThrowIfNull(sections);
        var builder = new StringBuilder();
        builder.AppendLine($"Downpour Next diagnostics · {appVersion} · generated {DateTimeOffset.UtcNow:O} UTC");
        builder.AppendLine("Local-only file. Review before sharing; nothing has been uploaded.");
        foreach (var section in sections)
        {
            builder.AppendLine().AppendLine($"[{section.Name}]");
            foreach (var line in section.Lines) builder.AppendLine(line);
        }
        return builder.ToString();
    }


}
