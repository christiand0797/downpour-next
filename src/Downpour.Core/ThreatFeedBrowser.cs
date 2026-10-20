using Downpour.Contracts;

namespace Downpour.Core;

public sealed record ThreatFeedBrowsePage(IReadOnlyList<ThreatBrowseRow> Rows, int Total, int Offset, int? NextOffset);

/// <summary>Searches the complete local feed while allocating response rows only for the requested page.</summary>
public static class ThreatFeedBrowser
{
    public const int PageSize = 500;
    public const int MaximumOffset = 3_000_000;

    public static ThreatFeedBrowsePage Read(ParsedThreatFeed parsed, string? query, int offset = 0,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(parsed);
        if (offset is < 0 or > MaximumOffset) throw new ArgumentOutOfRangeException(nameof(offset));
        if (query is { Length: > 128 } || query?.Any(char.IsControl) == true)
            throw new ArgumentException("The search must contain at most 128 printable characters.", nameof(query));
        if ((long)parsed.Indicators.Count + parsed.Lolbins.Count > MaximumOffset)
            throw new InvalidDataException("The feed exceeds the supported browse budget.");
        query = query?.Trim() ?? "";
        cancellationToken.ThrowIfCancellationRequested();
        var rows = new List<ThreatBrowseRow>(PageSize);
        var total = 0;
        Collect(countAll: true);
        // A refresh or a narrower query may make an old offset out of range. Return the last real page.
        if (offset >= total && offset != 0)
        {
            offset = total == 0 ? 0 : ((total - 1) / PageSize) * PageSize;
            rows.Clear();
            Collect(countAll: false);
        }
        return new(rows, total, offset, offset + rows.Count < total ? offset + rows.Count : null);

        void Collect(bool countAll)
        {
            var matches = 0;
            var scanned = 0;
            foreach (var indicator in parsed.Indicators)
            {
                if ((scanned++ & 1023) == 0) cancellationToken.ThrowIfCancellationRequested();
                if (!Matches(indicator.Value, indicator.Label)) continue;
                if (matches++ >= offset && rows.Count < PageSize)
                    rows.Add(new(indicator.Value, TypeName(indicator.Type), indicator.Label));
                if (!countAll && rows.Count == PageSize) return;
            }
            foreach (var lolbin in parsed.Lolbins)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var label = $"{lolbin.Categories} ({lolbin.Techniques})";
                if (!Matches(lolbin.Name, label)) continue;
                if (matches++ >= offset && rows.Count < PageSize)
                    rows.Add(new(lolbin.Name, "built-in tool", label));
                if (!countAll && rows.Count == PageSize) return;
            }
            if (countAll) total = matches;
        }

        bool Matches(string value, string label) => query.Length == 0 ||
            value.Contains(query, StringComparison.OrdinalIgnoreCase) || label.Contains(query, StringComparison.OrdinalIgnoreCase);
    }

    private static string TypeName(IndicatorType type) => type switch
    {
        IndicatorType.Ip => "IP address", IndicatorType.Network => "network", IndicatorType.Domain => "domain",
        IndicatorType.Sha256 => "SHA-256", IndicatorType.Sha1 => "SHA-1", IndicatorType.Md5 => "MD5", _ => "entry",
    };
}
