using System.IO.Pipes;
using System.Text.Json;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

public sealed class SecurityAlertClient(string pipeName = SecurityAlertClient.PipeName)
{
    public const string PipeName = "Downpour.SecurityAlerts.v1";
    private const int MaximumAlerts = 512;
    private const int MaximumWarnings = 32;
    private readonly string _pipeName = pipeName;
    private static readonly HashSet<string> States = new(StringComparer.Ordinal) { "Open", "Acknowledged", "Suppressed" };

    public async Task<SecurityAlertSnapshot?> TryGetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            await using var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            var snapshot = await BoundedJson.DeserializeAsync<SecurityAlertSnapshot>(pipe, timeout.Token);
            return IsValidSnapshot(snapshot) ? snapshot : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return null; }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
        catch (JsonReaderException) { return null; }
        catch (JsonSerializationException) { return null; }
        catch (InvalidDataException) { return null; }
    }

    public static bool IsValidSnapshot(SecurityAlertSnapshot? snapshot)
    {
        if (snapshot is null || snapshot.SchemaVersion != 1 || snapshot.TotalCount < 0 ||
            snapshot.TotalCount > 10_000 || snapshot.Alerts is not { Count: <= MaximumAlerts } ||
            snapshot.Warnings is not { Count: <= MaximumWarnings } ||
            snapshot.CapturedAtUtc < DateTimeOffset.UtcNow.AddMinutes(-10) ||
            snapshot.CapturedAtUtc > DateTimeOffset.UtcNow.AddMinutes(1) || snapshot.TotalCount < snapshot.Alerts.Count)
            return false;
        if (snapshot.Hourly is { } hourly && (hourly.Count > 7 * 24 + 2 || hourly.Any(h => h is null || h.HourUtc.Offset != TimeSpan.Zero
                || h.Count is < 0 or > 1_000_000 || h.Serious < 0 || h.Serious > h.Count)))
            return false;

        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var alert in snapshot.Alerts)
        {
            if (alert is null || !SecurityAlertRepositoryId.IsValid(alert.AlertId) || !ids.Add(alert.AlertId) ||
                !Bounded(alert.Title, 160) || !Bounded(alert.Severity, 16) || !Bounded(alert.Technique, 32) ||
                !Bounded(alert.LogName, 128) || !Bounded(alert.Provider, 128) || alert.EventId is < 0 or > ushort.MaxValue ||
                alert.RecordId is < 0 || alert.Occurrences is < 1 or > 100 || !States.Contains(alert.State) ||
                alert.FirstSeenUtc.Offset != TimeSpan.Zero || alert.LastSeenUtc.Offset != TimeSpan.Zero || alert.EventTimeUtc.Offset != TimeSpan.Zero ||
                alert.FirstSeenUtc > snapshot.CapturedAtUtc.AddMinutes(1) || alert.LastSeenUtc > snapshot.CapturedAtUtc.AddMinutes(1) ||
                alert.FirstSeenUtc > alert.LastSeenUtc || alert.EventTimeUtc > snapshot.CapturedAtUtc.AddMinutes(1) ||
                !(IsValidEventAlert(alert) || IsValidFindingAlert(alert)) ||
                (alert.IndicatorKind is null) != (alert.Indicator is null) ||
                (alert.IndicatorKind is not null && (!AlertIndicatorKinds.All.Contains(alert.IndicatorKind) || !Bounded(alert.Indicator!, 512))))
                return false;
        }
        return snapshot.Warnings.All(warning => Bounded(warning, 512, allowEmpty: true));
    }

    private static bool IsValidEventAlert(SecurityAlert alert) =>
        SecurityEventCatalog.TryGetRule(alert.LogName, alert.EventId, out var rule) && rule.Technique == alert.Technique &&
        (rule.Severity == alert.Severity && rule.Summary == alert.Title || IsGradedServiceInstall(alert, rule.Summary));

    /// <summary>
    /// Service installs (7045/4697) are re-graded by signer and titled "rule summary: name · verdict · path"; only those
    /// two events may differ from their rule, and only in that shape.
    /// </summary>
    private static bool IsGradedServiceInstall(SecurityAlert alert, string ruleSummary) =>
        ServiceInstallAnalyzer.Applies(alert.LogName, alert.EventId) && SecurityFindingCatalog.Severities.Contains(alert.Severity) &&
        (alert.Title == ruleSummary || alert.Title.StartsWith(ruleSummary + ": ", StringComparison.Ordinal));

    /// <summary>Finding alerts (hardening, firewall, persistence) carry free-text titles but a fixed source, identity shape and event ID 0.</summary>
    private static bool IsValidFindingAlert(SecurityAlert alert) =>
        SecurityFindingCatalog.IsFinding(alert.LogName) && SecurityFindingCatalog.IsValidIdentity(alert.Provider) &&
        alert.EventId == 0 && alert.RecordId is null && SecurityFindingCatalog.Severities.Contains(alert.Severity);

    public async Task<AlertStateChangeResponse?> ChangeStateAsync(AlertStateChangeRequest request, CancellationToken cancellationToken = default)
    {
        if (!IsValidRequest(request)) return new AlertStateChangeResponse(1, request.RequestId, false, "invalid-request");
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            await using var pipe = new NamedPipeClientStream(".", _pipeName + ".Control", PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            var json = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(request, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            if (json.Length > 1024) return null;
            await pipe.WriteAsync(json, timeout.Token);
            await pipe.WriteAsync(new byte[] { (byte)'\n' }, timeout.Token);
            await pipe.FlushAsync(timeout.Token);
            var response = await ReadResponseAsync(pipe, timeout.Token);
            return IsValidResponse(response, request.RequestId) ? response : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return null; }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
        catch (System.Text.Json.JsonException) { return null; }
    }

    public static bool IsValidRequest(AlertStateChangeRequest? request)
    {
        if (request is null || request.SchemaVersion != 1 || request.RequestId == Guid.Empty ||
            !SecurityAlertRepositoryId.IsValid(request.AlertId) || !States.Contains(request.ExpectedState))
            return false;
        if (request.State == "FalsePositive") return request.ExpectedState is "Open" or "Acknowledged";
        if (request.State == "RearmFalsePositive") return States.Contains(request.ExpectedState);
        if (request.State == "Verify") return request.ExpectedState is "Open" or "Acknowledged";
        if (request.State == "Unverify") return States.Contains(request.ExpectedState);
        if (!States.Contains(request.State)) return false;
        return request.ExpectedState == request.State || (request.ExpectedState, request.State) is
            ("Open", "Acknowledged") or ("Open", "Suppressed") or ("Acknowledged", "Open") or
            ("Acknowledged", "Suppressed") or ("Suppressed", "Open");
    }

    internal static bool IsValidResponse(AlertStateChangeResponse? response, Guid expectedRequest) => response is not null &&
        response.SchemaVersion == 1 && response.RequestId == expectedRequest &&
        (response.ResultCode is "updated" or "replayed" or "unchanged" or "confirmed-1" or "confirmed-2" or "fingerprint-suppressed" or "rearmed" or "verified" or "unverified" or "invalid-request" or "alert-not-found" or "state-conflict" or "transition-denied" or "request-id-conflict") &&
        (response.Accepted == (response.ResultCode is "updated" or "replayed" or "unchanged" or "confirmed-1" or "confirmed-2" or "fingerprint-suppressed" or "rearmed" or "verified" or "unverified"));

    private static async Task<AlertStateChangeResponse?> ReadResponseAsync(Stream pipe, CancellationToken token)
    {
        using var buffer = new MemoryStream();
        var one = new byte[1];
        while (buffer.Length <= 512)
        {
            var read = await pipe.ReadAsync(one, token);
            if (read == 0) break;
            if (one[0] == (byte)'\n')
            {
                if (buffer.Length == 0) return null;
                return System.Text.Json.JsonSerializer.Deserialize<AlertStateChangeResponse>(buffer.ToArray(), new JsonSerializerOptions(JsonSerializerDefaults.Web));
            }
            buffer.WriteByte(one[0]);
        }
        return null;
    }

    private static bool Bounded(string? value, int max, bool allowEmpty = false) => value is not null && value.Length <= max &&
        (allowEmpty || !string.IsNullOrWhiteSpace(value)) && !value.Any(char.IsControl);
}

internal static class SecurityAlertRepositoryId
{
    public static bool IsValid(string? value) => value is { Length: 64 } && value.All(ch => ch is >= '0' and <= '9' or >= 'a' and <= 'f');
}
