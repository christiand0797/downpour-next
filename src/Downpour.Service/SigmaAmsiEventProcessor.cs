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
    private readonly object _dedupGate = new();
    private readonly Func<string, string, AmsiScanOutcome> _scan;
    private readonly TimeProvider _time;
    internal const int MaximumDedupEntries = 4096;
    internal int DedupEntryCount => _recentAlerts.Count;
    internal string? AmsiWarning { get; private set; }

    public SigmaAmsiEventProcessor(ILogger<SigmaAmsiEventProcessor> logger) : this(logger, null, null) { }

    internal SigmaAmsiEventProcessor(ILogger<SigmaAmsiEventProcessor> logger,
        Func<string, string, AmsiScanOutcome>? scan, TimeProvider? timeProvider = null)
    {
        _logger = logger;
        _scan = scan ?? ((text, name) => AmsiIntegration.ScanStringWithStatus(text, name));
        _time = timeProvider ?? TimeProvider.System;
        
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

        // Bundled v29 rules win over built-ins with the same title, so one script block does not raise two alerts.
        var bundledTitles = new HashSet<string>(bundled.Select(rule => rule.Title), StringComparer.OrdinalIgnoreCase);
        _sigmaRules = [..builtin.Where(rule => !bundledTitles.Contains(rule.Title)), ..bundled];
        
        // Initialize AMSI
        if (scan is null && !AmsiIntegration.Initialize("DownpourNext-SigmaAmsi"))
        {
            AmsiWarning = "AMSI is unavailable: " + AmsiIntegration.DescribeInitializeFailure(AmsiIntegration.LastInitializeResult) + ". Sigma analysis remains active.";
            _logger.LogWarning("AMSI is unavailable: {Reason}. PowerShell script blocks are still checked with Sigma rules; AMSI verdicts are skipped.",
                AmsiIntegration.DescribeInitializeFailure(AmsiIntegration.LastInitializeResult));
        }
    }

    /// <summary>Runs Sigma and AMSI over one script-block part. The text is used in memory only.</summary>
    internal IReadOnlyList<SecurityAlert> ProcessScriptBlock(ScriptBlock block) =>
        ProcessEvent(new SecurityEventObservation("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", 4104,
            block.RecordId, block.CreatedAtUtc, "LOW", "T1059.001", block.Text, 1));

    /// <summary>
    /// Processes a 4104 observation whose Summary carries script text. Observations from SecurityEventProvider are
    /// metadata-only (Summary is the catalog text), so live analysis goes through <see cref="ProcessScriptBlock"/>.
    /// </summary>
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
            if (scriptContent.Length > ScriptBlockSource.MaximumTextChars)
                scriptContent = scriptContent[..ScriptBlockSource.MaximumTextChars];
            if (!string.IsNullOrWhiteSpace(scriptContent))
            {
                // Run Sigma rule matching against all loaded rules
                var sigmaMatches = SigmaEngine.Match(scriptContent, _sigmaRules);
                foreach (var match in sigmaMatches)
                {
                    var alert = CreateAlertFromSigmaMatch(observation, match);
                    if (alert != null) alerts.Add(alert);
                }

                // Run AMSI scan
                var scanOutcome = _scan(scriptContent, $"PowerShell-4104-{observation.RecordId}");
                AmsiWarning = scanOutcome.Succeeded ? null : "AMSI scan is unavailable: " +
                    AmsiIntegration.DescribeInitializeFailure(scanOutcome.HResult) + ". Sigma analysis remains active.";
                var amsiVerdict = scanOutcome.Verdict;
                
                if (amsiVerdict == AmsiIntegration.AmsiVerdict.Detected || amsiVerdict == AmsiVerdict.BlockedByAdmin)
                {
                    var alert = CreateAlertFromAmsiDetection(observation, amsiVerdict);
                    if (alert != null) alerts.Add(alert);
                }
            }
        }

        return alerts;
    }

    private SecurityAlert? CreateAlertFromSigmaMatch(SecurityEventObservation observation, SigmaMatch match)
    {
        // Deduplicate: don't generate duplicate alerts for the same rule/script within 5 minutes
        var dedupKey = $"sigma-{match.RuleId}-{observation.RecordId}-{observation.CreatedAtUtc?.UtcTicks}";
        if (!Remember(dedupKey)) return null;

        var alertId = ComputeAlertId("sigma", $"{match.RuleId}-{observation.CreatedAtUtc?.UtcTicks}", observation.RecordId ?? 0);

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

    private SecurityAlert? CreateAlertFromAmsiDetection(SecurityEventObservation observation, AmsiIntegration.AmsiVerdict verdict)
    {
        var dedupKey = $"amsi-{observation.RecordId}-{observation.CreatedAtUtc?.UtcTicks}";
        if (!Remember(dedupKey)) return null;
        
        return new SecurityAlert(
            AlertId: ComputeAlertId("amsi", $"{observation.CreatedAtUtc?.UtcTicks}", observation.RecordId ?? 0),
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

    private bool Remember(string key)
    {
        lock (_dedupGate)
        {
            var now = _time.GetUtcNow();
            CleanupOldEntries(TimeSpan.FromMinutes(5));
            if (_recentAlerts.ContainsKey(key)) return false;
            if (_recentAlerts.Count >= MaximumDedupEntries)
            {
                var oldest = _recentAlerts.MinBy(item => item.Value).Key;
                _recentAlerts.TryRemove(oldest, out _);
            }
            _recentAlerts[key] = now;
            return true;
        }
    }

    /// <summary>Cleans up old deduplication entries.</summary>
    public void CleanupOldEntries(TimeSpan maxAge)
    {
        var cutoff = _time.GetUtcNow() - maxAge;
        var keysToRemove = _recentAlerts
            .Where(kvp => kvp.Value <= cutoff)
            .Select(kvp => kvp.Key)
            .ToList();
        
        foreach (var key in keysToRemove)
        {
            _recentAlerts.TryRemove(key, out _);
        }
    }
}
