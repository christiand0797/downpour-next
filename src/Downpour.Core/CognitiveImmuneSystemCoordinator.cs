using System.Text;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>Projects validated measurements; never invents detector counts, confidence or containment.</summary>
public static class CognitiveImmuneSystemCoordinator
{
    public static CisAssessment Assess(SecurityAlertSnapshot? alerts, SystemHealthSnapshot? system,
        SensorSettingsSnapshot? settings)
    {
        var warnings = new List<string>();
        var sources = new List<CisSourceMeasurement>();
        if (!SecurityAlertClient.IsValidSnapshot(alerts)) alerts = null;
        if (system is not null && !SystemSnapshotClient.IsValidSnapshot(system)) system = null;
        if (settings is not { SchemaVersion: 1 }) settings = null;

        sources.Add(new("Alert store", alerts is null ? "Unavailable" : alerts.Warnings.Count > 0 ? "Partial" : "Available",
            alerts is null ? "No fresh validated snapshot. Counts are unknown." :
            $"{alerts.Alerts.Count} returned of {alerts.TotalCount} stored; captured {alerts.CapturedAtUtc:O}."));
        sources.Add(new("System sensor", system is null ? "Unavailable" : system.Warnings.Count > 0 ? "Partial" : "Available",
            system is null ? "No fresh validated snapshot." : $"{system.ProcessCount} processes; captured {system.CapturedAtUtc:O}."));
        sources.Add(new("PowerShell content analysis", settings is null ? "Unknown" : settings.ScriptBlockAnalysis ? "Permitted" : "Disabled",
            "Consent setting only; alert-source warnings describe collection and AMSI failures."));
        sources.Add(new("Response policies", settings is null ? "Unknown" : "Configured",
            settings is null ? "Service settings could not be read." :
            $"Quarantine: {OnOff(settings.QuarantineActions)}; process: {OnOff(settings.ProcessTerminationActions)}; " +
            $"firewall: {OnOff(settings.FirewallActions)}; USB: {OnOff(settings.UsbActions)}. Each request still needs confirmation and Windows permission."));
        if (alerts is null) warnings.Add("Alert measurements unavailable; absence of data is not absence of threats.");
        else
        {
            warnings.AddRange(alerts.Warnings);
            if (alerts.TotalCount > alerts.Alerts.Count)
                warnings.Add("Alert window is truncated. All counts, techniques and correlations below cover returned rows only.");
        }
        if (system is null) warnings.Add("System telemetry unavailable.");
        else warnings.AddRange(system.Warnings);
        if (settings is null) warnings.Add("Sensor/action settings unavailable.");
        var rows = alerts?.Alerts;
        var status = alerts is null ? "Unavailable" : warnings.Count > 0 ? "Partial" : "Measured";
        return new(1, DateTimeOffset.UtcNow, status, alerts?.CapturedAtUtc, alerts?.TotalCount, rows?.Count,
            rows?.Count(a => a.State == "Open"),
            rows?.Count(a => a.State == "Open" && a.Severity is "HIGH" or "CRITICAL"),
            rows?.Count(a => a.State != "Suppressed" && a.IsVerified),
            rows?.Count(a => a.State == "Suppressed"),
            rows?.Where(a => a.State != "Suppressed" && a.Technique != "N/A").Select(a => a.Technique).Distinct(StringComparer.Ordinal).Count(),
            sources, rows?.OrderByDescending(a => a.LastSeenUtc).ThenBy(a => a.AlertId, StringComparer.Ordinal).Take(32).ToArray() ?? [],
            alerts is null ? [] : AlertCorrelationEngine.Correlate(alerts).Select(c => new CisCorrelationMeasurement(c.Title, c.EvidenceSummary, c.Limitation)).ToArray(),
            warnings.Distinct(StringComparer.Ordinal).Take(64).ToArray());
    }

    /// <summary>Formats the measurements captured with this review; it never fetches newer live state.</summary>
    public static string CreateReport(CisAssessment assessment, PackageIntegrityAssessment? integrity,
        LocalLearningSnapshot? learning = null)
    {
        var text = new StringBuilder();
        text.AppendLine("# Downpour measured defense review");
        text.AppendLine($"Captured UTC: {assessment.CapturedAtUtc:O}; status: {assessment.Status}.");
        text.AppendLine($"Returned alerts: {Count(assessment.ReviewedAlerts)} of {Count(assessment.StoredAlerts)} stored.");
        text.AppendLine($"Open: {Count(assessment.OpenAlerts)}; urgent open: {Count(assessment.UrgentOpenAlerts)}; user-verified active: {Count(assessment.VerifiedActiveAlerts)}; suppressed: {Count(assessment.SuppressedAlerts)}.");
        text.AppendLine("Counts cover the returned window. User verification is a review decision, not a malware verdict. This report does not measure containment, immunity or future threats.");
        foreach (var source in assessment.Sources) text.AppendLine($"- {Escape(source.Name)}: {Escape(source.Status)}. {Escape(source.Detail)}");
        foreach (var warning in assessment.Warnings) text.AppendLine($"- Warning: {Escape(warning)}");
        foreach (var alert in assessment.RecentAlerts)
            text.AppendLine($"- {alert.LastSeenUtc:O} {Escape(alert.Severity)} {Escape(alert.State)} {Escape(alert.Title)} [{alert.AlertId}]");
        foreach (var correlation in assessment.Correlations)
            text.AppendLine($"- Correlation: {Escape(correlation.Title)}. {Escape(correlation.Limitation)}");
        AppendLocalLearning(text, assessment.CapturedAtUtc, learning);
        if (integrity is null) text.AppendLine("Package integrity: not checked.");
        else
        {
            text.AppendLine($"Package integrity: {integrity.Status}; captured {integrity.CapturedAtUtc:O}; matching {integrity.MatchingFiles}/{integrity.ExpectedFiles}; checked {integrity.CheckedFiles}; bytes hashed {integrity.BytesHashed}.");
            text.AppendLine($"Manifest SHA-256: {integrity.ManifestSha256 ?? "unavailable"}; source: {integrity.SourceCommit ?? "unknown"}.");
            text.AppendLine(Escape(integrity.Scope));
            foreach (var finding in integrity.Findings) text.AppendLine($"- {Escape(finding.RelativePath)}: {Escape(finding.Status)}");
        }
        return text.ToString();
    }

    private static void AppendLocalLearning(StringBuilder text, DateTimeOffset reviewedAt, LocalLearningSnapshot? learning)
    {
        text.AppendLine();
        text.AppendLine("## Local learning at review time");
        text.AppendLine("Read-only aggregate context from this PC: CPU, memory, TCP connection count and process count. No API/LLM or automatic fixes. Baselines are not a protection score; temporal co-occurrence does not prove causation.");
        // Validate relative to the captured review, not the later time when someone copies it.
        // A newer snapshot must not silently be spliced into an older assessment.
        if (!LocalLearningClient.IsValid(learning, reviewedAt) || learning!.CapturedAtUtc > reviewedAt
            || learning.LastObservationUtc > learning.CapturedAtUtc)
        {
            text.AppendLine("Local learning: unavailable. No fresh validated learning snapshot was captured with this review; readings and recommendations are unknown.");
            return;
        }
        text.AppendLine($"Captured UTC: {learning.CapturedAtUtc:O}; state: {learning.State}; last observation UTC: {learning.LastObservationUtc?.ToString("O") ?? "none"}.");
        text.AppendLine($"Completed observed five-minute buckets: {learning.HistoryBuckets}; a baseline needs at least {LocalLearningEngine.MinimumBaselineBuckets} completed observed buckets per metric within seven days. Missing time is not filled with zeroes.");
        if (learning.State == "paused")
            text.AppendLine("Learning was paused in Settings at review time. Retained baselines are historical; there are no current readings or recommendations.");
        else if (learning.State is "unavailable" or "partial")
            text.AppendLine("Some or all current aggregate readings were unavailable; missing readings must not be interpreted as healthy or quiet.");
        foreach (var metric in learning.Metrics)
        {
            var unit = metric.Id is "cpu" or "memory" ? "%" : "";
            string Value(double? value) => value is { } number
                ? number.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) + unit : "unknown";
            var maturity = metric.Normal is null ? "collecting baseline" : "baseline available";
            text.AppendLine($"- {metric.Id}: {metric.State}; current {Value(learning.State == "paused" ? null : metric.Current)}; normal {Value(metric.Normal)}; unusual above {Value(metric.Threshold)}; {metric.BaselineBuckets} observed buckets ({maturity}).");
        }
        foreach (var warning in learning.Warnings) text.AppendLine($"- Learning warning: {Escape(warning)}");
        if (learning.State == "paused") return;
        foreach (var recommendation in learning.Recommendations)
            text.AppendLine($"- Investigation: {Escape(recommendation.Title)}. {Escape(recommendation.Explanation)} Open: {recommendation.Route}.");
        if (learning.Recommendations.Count == 0)
            text.AppendLine("No investigation was recommended by this limited model at review time; this is not a protection guarantee.");
    }

    private static string Count(int? value) => value?.ToString() ?? "unknown";
    private static string OnOff(bool value) => value ? "on" : "off";
    private static string Escape(string value) => value.Replace("\\", "\\\\").Replace("`", "\\`").Replace("[", "\\[").Replace("]", "\\]").Replace("<", "&lt;").Replace(">", "&gt;");
}
