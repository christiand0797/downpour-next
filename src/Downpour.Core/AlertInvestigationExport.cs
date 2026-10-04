using System.Text;
using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

/// <summary>Builds a bounded, metadata-only point-in-time alert investigation document.</summary>
public static class AlertInvestigationExport
{
    public const int MaximumExportBytes = 1_048_576;

    public static string CreateJson(SecurityAlertSnapshot snapshot)
    {
        if (!SecurityAlertClient.IsValidSnapshot(snapshot))
            throw new InvalidDataException("The alert snapshot did not pass its data contract validation.");

        var document = new AlertInvestigationDocument(
            SchemaVersion: 2,
            Product: "Downpour Next",
            GeneratedAtUtc: DateTimeOffset.UtcNow,
            SnapshotCapturedAtUtc: snapshot.CapturedAtUtc,
            Scope: "Latest retained alert metadata returned by the local sensor. Event messages, usernames, command lines, and file contents are not included.",
            TotalRetainedAlerts: snapshot.TotalCount,
            IncludedAlerts: snapshot.Alerts.Count,
            Warnings: snapshot.Warnings.ToArray(),
            Alerts: snapshot.Alerts.Select(alert => new AlertInvestigationItem(
                alert.AlertId,
                alert.Title,
                alert.Severity,
                alert.Technique,
                alert.LogName,
                alert.Provider,
                alert.EventId,
                alert.RecordId,
                alert.EventTimeUtc,
                alert.FirstSeenUtc,
                alert.LastSeenUtc,
                alert.Occurrences,
                alert.State)).ToArray(),
            CorrelatedPatterns: AlertCorrelationEngine.Correlate(snapshot));

        var json = JsonConvert.SerializeObject(document, Formatting.Indented, new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.None,
            MaxDepth = 8,
            StringEscapeHandling = StringEscapeHandling.EscapeHtml
        });
        if (Encoding.UTF8.GetByteCount(json) > MaximumExportBytes)
            throw new InvalidDataException("The investigation export exceeds its 1 MiB size limit.");
        return json;
    }
}

public sealed record AlertInvestigationDocument(
    int SchemaVersion,
    string Product,
    DateTimeOffset GeneratedAtUtc,
    DateTimeOffset SnapshotCapturedAtUtc,
    string Scope,
    int TotalRetainedAlerts,
    int IncludedAlerts,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<AlertInvestigationItem> Alerts,
    IReadOnlyList<CorrelatedAlertFinding> CorrelatedPatterns);

public sealed record AlertInvestigationItem(
    string AlertId,
    string Title,
    string Severity,
    string Technique,
    string LogName,
    string Provider,
    int EventId,
    long? RecordId,
    DateTimeOffset EventTimeUtc,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    int Occurrences,
    string State);
