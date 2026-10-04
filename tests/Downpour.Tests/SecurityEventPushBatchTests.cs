using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class SecurityEventPushBatchTests
{
    [Fact]
    public void MergeDeduplicatesRecordsBoundsHistoryAndReportsDroppedMetadata()
    {
        var now = DateTimeOffset.UtcNow;
        var existing = Event("System", 7045, 10, now.AddSeconds(-20));
        var current = new SecurityEventSnapshot(1, now, [existing], 7, []);
        var duplicate = Event("System", 7045, 10, now.AddSeconds(-20));
        var fresh = Event("Security", 4697, 11, now.AddSeconds(-2));
        var expired = Event("Security", 4697, 12, now.AddDays(-2));
        var future = Event("Security", 4697, 13, now.AddMinutes(2));

        var merged = SecurityEventPushBatch.Merge(current, [duplicate, fresh, expired, future], now, []);

        Assert.True(SecurityEventClient.IsValidSnapshot(merged));
        Assert.Equal(2, merged.Events.Count);
        Assert.Contains(merged.Events, item => item.RecordId == 10);
        Assert.Contains(merged.Events, item => item.RecordId == 11);
        Assert.Equal(7, merged.SourcesQueried);
    }

    [Fact]
    public void MergeKeepsNewestEventsWithinTheSnapshotBound()
    {
        var now = DateTimeOffset.UtcNow;
        var current = new SecurityEventSnapshot(1, now, [], 7, []);
        var pushed = Enumerable.Range(1, 300)
            .Select(id => Event("Security", 1102, id, now.AddSeconds(-id)))
            .ToArray();

        var merged = SecurityEventPushBatch.Merge(current, pushed, now, []);

        Assert.True(SecurityEventClient.IsValidSnapshot(merged));
        Assert.Equal(256, merged.Events.Count);
        Assert.Equal(1, merged.Events[0].RecordId);
        Assert.Equal(256, merged.Events[^1].RecordId);
    }

    [Fact]
    public void MergeIncludesSubscriptionWarningsWithoutUnboundedDuplicates()
    {
        var now = DateTimeOffset.UtcNow;
        var warning = "Live event subscription unavailable for Security; periodic polling remains active.";
        var current = new SecurityEventSnapshot(1, now, [], 6, [warning]);

        var merged = SecurityEventPushBatch.Merge(current, [], now, [warning, warning]);

        Assert.Single(merged.Warnings);
        Assert.Equal(warning, merged.Warnings[0]);
    }

    [Fact]
    public void PushStatusKeepsBoundedWarningsAndCumulativeQueueLossVisible()
    {
        var status = new SecurityEventPushStatus();
        for (var index = 0; index < 40; index++) status.ReportWarning($"source warning {index}");
        status.ReportWarning("line 1\r\nline 2");
        status.RecordDroppedEvent();
        status.RecordDroppedEvent();

        var warnings = status.GetWarnings();

        Assert.InRange(warnings.Count, 1, 33);
        Assert.Contains(warnings, warning => warning.Contains("dropped 2", StringComparison.Ordinal));
        Assert.All(warnings, warning => Assert.DoesNotContain(warning, char.IsControl));
        Assert.DoesNotContain(warnings, warning => warning.Contains("source warning 39", StringComparison.Ordinal));
    }

    private static SecurityEventObservation Event(string log, int id, long recordId, DateTimeOffset time)
    {
        Assert.True(SecurityEventCatalog.TryGetRule(log, id, out var rule));
        return new SecurityEventObservation(log, "Provider", id, recordId, time, rule.Severity, rule.Technique, rule.Summary);
    }
}
