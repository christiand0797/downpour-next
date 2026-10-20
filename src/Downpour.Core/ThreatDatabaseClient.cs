using System.Buffers.Binary;
using System.IO.Pipes;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

/// <summary>Desktop side of the threat database pipe. Returns null when the service is unreachable or replies invalidly.</summary>
public sealed class ThreatDatabaseClient(string pipeName = ThreatDatabaseClient.PipeName)
{
    public const string PipeName = "Downpour.ThreatDatabases.v1";
    public const int MaximumFeedProvenanceLength = 64 * 33 - 1;

    /// <summary>Why the last request returned null, in words a person can act on; null after a success.</summary>
    public string? LastFailure { get; private set; }

    /// <summary>The page message for a failed request.</summary>
    public string FailureMessage => LastFailure ?? "The local sensor service did not answer.";

    public Task<ThreatDatabaseResponse?> GetSnapshotAsync(CancellationToken token = default) =>
        SendAsync(new ThreatDatabaseRequest(1, ThreatDatabaseOperations.Snapshot, null), token);

    public Task<ThreatDatabaseResponse?> RefreshAsync(CancellationToken token = default) =>
        SendAsync(new ThreatDatabaseRequest(1, ThreatDatabaseOperations.Refresh, null), token);

    public Task<ThreatDatabaseResponse?> LookupAsync(string value, CancellationToken token = default) =>
        value.Length is 0 or > 2048 ? Task.FromResult<ThreatDatabaseResponse?>(null) : SendAsync(new ThreatDatabaseRequest(1, ThreatDatabaseOperations.Lookup, value), token);

    public Task<ThreatDatabaseResponse?> BrowseAsync(string feedId, string? query, CancellationToken token = default, int offset = 0) =>
        feedId.Length is 0 or > 32 || query?.Length > 128 || offset is < 0 or > 3_000_000 ? Task.FromResult<ThreatDatabaseResponse?>(null)
            : SendAsync(new ThreatDatabaseRequest(1, ThreatDatabaseOperations.Browse, string.IsNullOrWhiteSpace(query) ? null : query.Trim(), feedId, offset), token);

    private async Task<ThreatDatabaseResponse?> SendAsync(ThreatDatabaseRequest request, CancellationToken cancellationToken)
    {
        var connected = false;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            // Slower PCs need longer to answer while databases load; the service replies from memory once ready.
            timeout.CancelAfter(TimeSpan.FromSeconds(20));
            await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            connected = true;
            var body = BoundedJson.Serialize(request);
            var length = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(length, body.Length);
            await pipe.WriteAsync(length, timeout.Token);
            await pipe.WriteAsync(body, timeout.Token);
            await pipe.FlushAsync(timeout.Token);
            var response = await BoundedJson.DeserializeFramedAsync<ThreatDatabaseResponse>(pipe, timeout.Token);
            if (!IsValid(response))
            {
                LastFailure = "The sensor service answered, but its reply did not pass validation and was discarded. Restart Downpour; if it continues, export a case file and report it.";
                return null;
            }
            LastFailure = null;
            return response;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            LastFailure = connected
                ? "The sensor service is busy (it may still be loading the databases after starting). It will be retried automatically."
                : "The sensor service is not running or not reachable. Downpour starts it automatically; if this stays, check the service log in %LOCALAPPDATA%\\DownpourNext\\logs.";
            return null;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonReaderException or JsonSerializationException or EndOfStreamException)
        {
            LastFailure = ex is UnauthorizedAccessException
                ? "Windows denied access to the sensor service. Run Downpour and its service as the same Windows user."
                : $"The connection to the sensor service failed ({ex.GetType().Name}). It will be retried automatically.";
            return null;
        }
    }

    public static bool IsValid(ThreatDatabaseResponse? r) =>
        r is { SchemaVersion: 1 } && Text(r.ResultCode, 32)
        && (r.Snapshot is null || IsValid(r.Snapshot))
        && (r.LookupHits is null || r.LookupHits.Count <= 32 && r.LookupHits.All(h => h is not null && Text(h.FeedId, 32) && Text(h.FeedName, 64) && Text(h.Label, 96)))
        && (r.LookupKind is null || Text(r.LookupKind, 16)) && (r.LookupValue is null || Text(r.LookupValue, 253))
        && (r.LookupOrigin is null || Origin(r.LookupOrigin.Ip, r.LookupOrigin.CountryCode, r.LookupOrigin.Network))
        && r.BrowseTotal is >= 0 and <= 3_000_000 && r.BrowseOffset >= 0 && r.BrowseOffset <= r.BrowseTotal
        && (r.BrowseNextOffset is null || r.Browse is not null && r.BrowseNextOffset == r.BrowseOffset + r.Browse.Count && r.BrowseNextOffset > r.BrowseOffset && r.BrowseNextOffset < r.BrowseTotal)
        && (r.Browse is null || r.Browse.Count <= 500 && r.BrowseOffset + r.Browse.Count <= r.BrowseTotal && r.Browse.All(b => b is not null && Text(b.Value, 253) && Text(b.Type, 16) && Text(b.Label, 200)));

    public static bool IsValid(ThreatDatabaseSnapshot s) =>
        s is { SchemaVersion: 1 } && s.Feeds is { Count: <= 64 } && s.Matches is { Count: <= 300 } && s.Lolbins is { Count: <= 64 }
        && s.Connections is { Count: <= 400 } && s.Warnings is { Count: <= 32 } && s.Coverage is not null && s.TotalIndicators >= 0
        && s.Feeds.All(f => f is not null && Text(f.Id, 32) && Text(f.Name, 64) && Text(f.Provider, 64) && Text(f.Kind, 16) && Text(f.Purpose, 300)
            && Text(f.License, 64) && Text(f.Homepage, 128) && Text(f.State, 16) && f.Entries >= 0 && f.Bytes >= 0 && (f.Error is null || Text(f.Error, 300))
            && ValidFreshness(f, s.CapturedAtUtc))
        && s.Matches.All(m => m is not null && Text(m.Where, 32) && Text(m.Indicator, 128) && Text(m.Subject, 300) && ValidProvenance(m.FeedId)
            && Text(m.FeedName, 200) && Text(m.Label, 96) && Text(m.Severity, 16) && Text(m.Technique, 16) && Text(m.Verdict, 32)
            && m.Confidence is >= 0 and <= 100 && (m.Reasons is null || m.Reasons.Count <= 12 && m.Reasons.All(r => Text(r, 300))))
        && s.Lolbins.All(l => l is not null && Text(l.Name, 64) && Text(l.Categories, 96) && Text(l.Techniques, 96) && l.Instances > 0)
        && s.Connections.All(c => c is not null && Text(c.Program, 128) && Text(c.RemoteAddress, 64) && c.RemotePort is >= 0 and <= 65535
            && Origin(c.RemoteAddress, c.CountryCode, c.Network))
        && s.Warnings.All(w => Text(w, 512));

    private static bool Origin(string ip, string? country, string? network) =>
        Text(ip, 64) && (country is null || country.Length == 2 && country.All(char.IsAsciiLetterUpper)) && (network is null || Text(network, 80));

    private static bool ValidFreshness(ThreatFeedStatus feed, DateTimeOffset captured) =>
        feed.SourceFreshness is null or ThreatSourceFreshness.Unknown or ThreatSourceFreshness.Fresh or ThreatSourceFreshness.Expired or ThreatSourceFreshness.Historical
        && (feed.FreshnessNote is null || Text(feed.FreshnessNote, 300))
        && (feed.SourcePublishedAtUtc is null || feed.SourcePublishedAtUtc >= new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero)
            && feed.SourcePublishedAtUtc.Value - captured <= TimeSpan.FromMinutes(5))
        && (feed.SourceExpiresAtUtc is null || feed.SourcePublishedAtUtc is not null && feed.SourceExpiresAtUtc > feed.SourcePublishedAtUtc)
        && (feed.SourceFreshness != ThreatSourceFreshness.Fresh || feed.SourcePublishedAtUtc is not null)
        && (feed.SourceFreshness != ThreatSourceFreshness.Expired || feed.SourcePublishedAtUtc is not null && feed.SourceExpiresAtUtc <= captured && feed.MatchingEnabled == false)
        && (feed.SourceFreshness != ThreatSourceFreshness.Historical || feed.MatchingEnabled != true || feed.Kind is ThreatFeedKinds.Hash or ThreatFeedKinds.Driver);

    private static bool Text(string? value, int max) => value is not null && value.Length <= max && !value.Any(char.IsControl);

    private static bool ValidProvenance(string? value)
    {
        if (!Text(value, MaximumFeedProvenanceLength)) return false;
        var ids = value!.Split(',');
        return ids.Length <= 64 && ids.All(id => id.Length is > 0 and <= 32 && id.All(c => char.IsAsciiLetterOrDigit(c) || c == '-'))
            && ids.Distinct(StringComparer.Ordinal).Count() == ids.Length;
    }
}
