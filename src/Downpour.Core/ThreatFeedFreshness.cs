using System.Globalization;
using System.Text;
using Downpour.Contracts;

namespace Downpour.Core;

public sealed record ThreatFeedFreshnessResult(string State, DateTimeOffset? PublishedAtUtc,
    DateTimeOffset? SourceExpiresAtUtc, bool MatchingEnabled, string Note);

/// <summary>Publication timestamps describe a source snapshot, never when every indicator was last seen.</summary>
public static class ThreatFeedFreshness
{
    private static readonly DateTimeOffset EarliestPublication = new(2000, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public static ThreatFeedFreshnessResult Evaluate(ThreatFeedDefinition feed, ParsedThreatFeed? parsed,
        DateTimeOffset? retrievedAtUtc, DateTimeOffset now)
    {
        if (parsed is null || retrievedAtUtc is null)
            return new(ThreatSourceFreshness.Unknown, null, null, false, "No local copy is loaded.");
        var published = parsed.SourcePublishedAtUtc;
        var fileEvidence = feed.Kind is ThreatFeedKinds.Hash or ThreatFeedKinds.Driver;
        if (parsed.PublicationError is not null || published is { } date &&
            (date < EarliestPublication || date > retrievedAtUtc.Value.AddMinutes(5) || date > now.AddMinutes(5)))
            return new(ThreatSourceFreshness.Unknown, null, null, false,
                "Source publication metadata is missing, invalid or future-dated; excluded from matching.");

        DateTimeOffset? expires = published is { } at && feed.MaximumSourceAge is { } maximumAge
            ? at + maximumAge : null;
        var oldPublication = expires is { } until && now >= until;
        var historical = feed.Historical || fileEvidence && oldPublication;
        var state = historical ? ThreatSourceFreshness.Historical : oldPublication ? ThreatSourceFreshness.Expired
            : published is not null ? ThreatSourceFreshness.Fresh : ThreatSourceFreshness.Unknown;
        var enabled = !(historical && !fileEvidence) && !(oldPublication && !fileEvidence);
        var note = state switch
        {
            ThreatSourceFreshness.Historical when fileEvidence => "Historical file hashes remain useful; this is not a current threat snapshot.",
            ThreatSourceFreshness.Historical => "Historical network locations are available to browse and excluded from matching.",
            ThreatSourceFreshness.Expired => "Publication exceeds this source's age policy; excluded from matching until a newer snapshot arrives.",
            ThreatSourceFreshness.Fresh => "Within the configured publication-age policy; individual indicators can still be outdated.",
            _ => "The source supplies no supported publication timestamp; a recent download does not prove recent threat data.",
        };
        if (now - retrievedAtUtc.Value > ThreatFeedCache.MaximumAge || retrievedAtUtc > now.AddMinutes(5))
        {
            enabled = false;
            note = "The local copy exceeds its 30-day cache lifetime or has an invalid download time; excluded from matching.";
        }
        return new(state, published, expires, enabled, note);
    }

    /// <summary>Only fixed provider header formats are recognized; arbitrary dates in IOC rows are never publication dates.</summary>
    internal static (DateTimeOffset? Published, string? Error) ReadHeader(ThreatFeedDefinition feed, ReadOnlySpan<byte> payload)
    {
        var prefix = feed.Id.StartsWith("blp-", StringComparison.Ordinal) || feed.Id == "hagezi-tif" ? "# Last modified:"
            : feed.Id is "feodo" or "urlhaus" or "malwarebazaar" ? "# Last updated:" : null;
        if (prefix is null) return (null, null);
        var header = Encoding.UTF8.GetString(payload[..Math.Min(payload.Length, 8192)]);
        using var reader = new StringReader(header);
        DateTimeOffset? result = null;
        for (var lineNumber = 0; lineNumber < 32 && reader.ReadLine() is { } line; lineNumber++)
        {
            line = line.Trim();
            if (line.Length == 0) continue;
            if (!line.StartsWith('#')) break;
            if (!line.StartsWith(prefix, StringComparison.Ordinal)) continue;
            if (line.Length > 256 || result is not null) return (null, "Invalid or duplicate publication header.");
            var value = line[prefix.Length..].Trim().TrimEnd('#').TrimEnd();
            string[] formats = feed.Id == "hagezi-tif" ? ["dd MMM yyyy HH:mm 'UTC'"]
                : ["yyyy-MM-dd HH:mm:ss 'UTC'", "yyyy-MM-dd HH:mm:ss '(UTC)'"];
            if (!DateTimeOffset.TryParseExact(value, formats, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
                return (null, "Invalid publication header.");
            result = parsed;
        }
        return result is null ? (null, "Expected publication header is missing.") : (result, null);
    }

    internal static DateTimeOffset? ParseUtc(string? value) => value is { Length: 19 } &&
        DateTimeOffset.TryParseExact(value, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed) ? parsed : null;
}
