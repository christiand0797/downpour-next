using System.Collections.Concurrent;
using System.Text;
using Downpour.Contracts;
using Microsoft.Extensions.Logging;

namespace Downpour.Service;

using AmsiVerdict = AmsiIntegration.AmsiVerdict;

/// <summary>Processes Windows security events through Sigma rules and AMSI for alert generation.</summary>
public sealed class SigmaAmsiEventProcessor
{
    private readonly ILogger<SigmaAmsiEventProcessor> _logger;
    private readonly List<SigmaRule> _sigmaRules;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recentAlerts = new();

    public SigmaAmsiEventProcessor(ILogger<SigmaAmsiEventProcessor> logger)
    {
        _logger = logger;
        
        var builtin = SigmaEngine.GetBuiltinRules();
        var rulesDir = SigmaEngine.GetDefaultRulesDirectory();
        List<SigmaRule> bundled = [];

        if (Directory.Exists(rulesDir))
        {
            var files = Directory.GetFiles(rulesDir, "*.yml", SearchOption.TopDirectoryOnly)
                .Concat(Directory.GetFiles(rulesDir, "*.yaml", SearchOption.TopDirectoryOnly))
                .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
                .ToList();

            bundled = SigmaEngine.LoadFromYamlFiles(files, out var report);

            if (report.UnsupportedRulesCount > 0)
            {
                _logger.LogWarning("Loaded {ValidCount} bundled Sigma rules from {RulesDir} ({UnsupportedCount} unsupported: {Issues}).",
                    report.ValidRulesLoaded, rulesDir, report.UnsupportedRulesCount, string.Join("; ", report.Issues));
            }
            else
            {
                _logger.LogInformation("Loaded {ValidCount} bundled Sigma rules from {RulesDir}.",
                    report.ValidRulesLoaded, rulesDir);
            }
        }
        else
        {
            _logger.LogWarning("Bundled Sigma rules directory not found at {RulesDir}.", rulesDir);
        }

        _sigmaRules = [..builtin, ..bundled];
        
        // Initialize AMSI
        if (!AmsiIntegration.Initialize("DownpourNext-SigmaAmsi"))
        {
            _logger.LogWarning("AMSI initialization failed; script content scanning will be unavailable.");
        }
    }

    /// <summary>Processes a security event observation through Sigma rules and AMSI.</summary>
    /// <returns>Generated alerts, or empty if no matches.</returns>
    public IReadOnlyList<SecurityAlert> ProcessEvent(SecurityEventObservation observation)
    {
        var alerts = new List<SecurityAlert>();

        // Only process PowerShell 4104 script block events for Sigma/AMSI analysis
        if (observation.LogName.Equals("Microsoft-Windows-PowerShell/Operational", StringComparison.OrdinalIgnoreCase) &&
            observation.EventId == 4104)
        {
            // The observation summary contains the script block text
            var scriptContent = observation.Summary;
            if (!string.IsNullOrWhiteSpace(scriptContent))
            {
                // Run Sigma rule matching against all loaded rules
                var sigmaMatches = SigmaEngine.Match(scriptContent, _sigmaRules);
                foreach (var match in sigmaMatches)
                {
                    var alert = CreateAlertFromSigmaMatch(observation, match, scriptContent);
                    if (alert != null) alerts.Add(alert);
                }

                // Run AMSI scan
                var amsiResult = AmsiIntegration.ScanString(scriptContent, $"PowerShell-4104-{observation.RecordId}");
                var amsiVerdict = AmsiIntegration.InterpretResult(amsiResult);
                
                if (amsiVerdict == AmsiIntegration.AmsiVerdict.Detected || amsiVerdict == AmsiVerdict.BlockedByAdmin)
                {
                    var alert = CreateAlertFromAmsiDetection(observation, scriptContent, amsiVerdict);
                    if (alert != null) alerts.Add(alert);
                }
                else if (amsiVerdict == AmsiIntegration.AmsiVerdict.Detected)
                {
                    _logger.LogInformation("AMSI detected malicious content in PowerShell script block (RecordId: {RecordId})", observation.RecordId);
                }
            }
        }

        return alerts;
    }

    private SecurityAlert? CreateAlertFromSigmaMatch(SecurityEventObservation observation, SigmaMatch match, string scriptContent)
    {
        // Deduplicate: don't generate duplicate alerts for the same rule/script within 5 minutes
        var dedupKey = $"sigma-{match.RuleId}-{observation.RecordId}";
        if (_recentAlerts.TryGetValue(dedupKey, out var lastAlert) && 
            DateTimeOffset.UtcNow - lastAlert < TimeSpan.FromMinutes(5))
        {
            return null;
        }
        _recentAlerts[dedupKey] = DateTimeOffset.UtcNow;

        var alertId = ComputeAlertId("sigma", match.RuleId, observation.RecordId ?? 0);
        var matchedSnippet = match.MatchedText.Length > 200 ? match.MatchedText[..200] + "..." : match.MatchedText;

        return new SecurityAlert(
            AlertId: alertId,
            Title: $"Sigma Match: {match.RuleTitle}",
            Severity: match.Level switch
            {
                "critical" => "CRITICAL",
                "high" => "HIGH",
                "medium" => "MEDIUM",
                "low" => "LOW",
                _ => "MEDIUM"
            },
            Technique: "T1059.001",
            LogName: observation.LogName,
            Provider: observation.Provider,
            EventId: observation.EventId,
            RecordId: observation.RecordId,
            EventTimeUtc: observation.CreatedAtUtc ?? DateTimeOffset.UtcNow,
            FirstSeenUtc: DateTimeOffset.UtcNow,
            LastSeenUtc: DateTimeOffset.UtcNow,
            Occurrences: 1,
            State: "Open");
    }

    private SecurityAlert? CreateAlertFromAmsiDetection(SecurityEventObservation observation, string scriptContent, AmsiIntegration.AmsiVerdict verdict)
    {
        var dedupKey = $"amsi-{observation.RecordId}";
        if (_recentAlerts.TryGetValue(dedupKey, out var lastAlert) && 
            DateTimeOffset.UtcNow - lastAlert < TimeSpan.FromMinutes(5))
        {
            return null;
        }
        _recentAlerts[dedupKey] = DateTimeOffset.UtcNow;

        var alertId = ComputeAlertId("amsi", observation.RecordId?.ToString() ?? "unknown", observation.RecordId ?? 0);
        
        return new SecurityAlert(
            AlertId: ComputeAlertId("amsi", observation.RecordId?.ToString() ?? "unknown", observation.RecordId ?? 0),
            Title: $"AMSI Detection: {verdict}",
            Severity: verdict == AmsiIntegration.AmsiVerdict.BlockedByAdmin ? "CRITICAL" : "HIGH",
            Technique: "T1059.001",
            LogName: observation.LogName,
            Provider: observation.Provider,
            EventId: observation.EventId,
            RecordId: observation.RecordId,
            EventTimeUtc: observation.CreatedAtUtc ?? DateTimeOffset.UtcNow,
            FirstSeenUtc: DateTimeOffset.UtcNow,
            LastSeenUtc: DateTimeOffset.UtcNow,
            Occurrences: 1,
            State: "Open");
    }

    private static string ComputeAlertId(string prefix, string identifier, long recordId)
    {
        var input = $"{prefix}-{identifier}-{recordId}";
        using var sha = System.Security.Cryptography.SHA256.Create();
        var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hash);
    }

    /// <summary>Cleans up old deduplication entries.</summary>
    public void CleanupOldEntries(TimeSpan maxAge)
    {
        var cutoff = DateTimeOffset.UtcNow - maxAge;
        var keysToRemove = _recentAlerts
            .Where(kvp => kvp.Value < cutoff)
            .Select(kvp => kvp.Key)
            .ToList();
        
        foreach (var key in keysToRemove)
        {
            _recentAlerts.TryRemove(key, out _);
        }
    }
}