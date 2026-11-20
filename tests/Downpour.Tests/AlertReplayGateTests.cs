using System.Text.RegularExpressions;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Tests;

/// <summary>
/// The offline gate for rule and dedup-identity changes: a synthetic corpus is replayed through the current rules and
/// must produce exactly the alert set recorded beside it.
/// </summary>
public sealed class AlertReplayGateTests
{
    private static string CorpusPath => Path.Combine(AppContext.BaseDirectory, "replay", "alert-replay-corpus.json");

    private static AlertReplayCorpus LoadCorpus() => AlertReplayRunner.Parse(File.ReadAllText(CorpusPath));

    [Fact]
    public void CorpusReplaysToTheRecordedExpectation()
    {
        var differences = AlertReplayRunner.Evaluate(LoadCorpus());
        Assert.True(differences.Count == 0,
            AlertReplayDiff.Summarize(differences) + Environment.NewLine +
            string.Join(Environment.NewLine, differences.Take(20).Select(item => $"{item.DedupKey}: {item.Problem}")));
    }

    [Fact]
    public void CorpusContainsOnlySyntheticRecords()
    {
        var text = File.ReadAllText(CorpusPath);
        Assert.False(text.Contains(@"C:\", StringComparison.OrdinalIgnoreCase));
        Assert.False(text.Contains(@"\\", StringComparison.Ordinal));
        Assert.False(text.Contains("%USERPROFILE%", StringComparison.OrdinalIgnoreCase));
        Assert.False(text.Contains("AppData", StringComparison.OrdinalIgnoreCase));
        Assert.False(text.Contains(@"Users\", StringComparison.OrdinalIgnoreCase));
        Assert.False(text.Contains('@'));
        Assert.DoesNotMatch(@"\b\d{1,3}(\.\d{1,3}){3}\b", text);

        var knownLogs = SecurityEventCatalog.WatchedEvents.Select(item => item.LogName)
            .Append(SysmonCatalog.LogName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.All(LoadCorpus().Cases, item => Assert.Contains(item.LogName, knownLogs));
    }

    [Fact]
    public void ReplayGateReportsTamperedExpectations()
    {
        var corpus = LoadCorpus();
        var first = corpus.Expected[0];
        var tampered = corpus with
        {
            Expected = [first with { Severity = first.Severity == "LOW" ? "HIGH" : "LOW" }, .. corpus.Expected.Skip(1)],
        };
        Assert.Contains(AlertReplayRunner.Evaluate(tampered),
            difference => difference.DedupKey == first.DedupKey && difference.Problem.Contains("Severity changed"));

        // Dropping an expectation leaves its actual alert unaccounted for, which the diff reports as unexpected.
        var missing = corpus with { Expected = corpus.Expected.Skip(1).ToArray() };
        Assert.Contains(AlertReplayRunner.Evaluate(missing),
            difference => difference.DedupKey == first.DedupKey && difference.Problem.Contains("Unexpected"));
    }

    [Fact]
    public void ACorpusCaseNoRuleGradesIsRefused()
    {
        var stale = new[] { LoadCorpus().Cases[0] with { EventId = 9999 } };
        var exception = Assert.Throws<InvalidDataException>(() => AlertReplayRunner.Replay(stale));
        Assert.Contains("9999", exception.Message);
    }

    [Fact]
    public void CorpusParserRefusesMalformedOrUnboundedInput()
    {
        Assert.Throws<InvalidDataException>(() => AlertReplayRunner.Parse("{"));
        Assert.Throws<InvalidDataException>(() => AlertReplayRunner.Parse("{}"));
        Assert.Throws<InvalidDataException>(() => AlertReplayRunner.Parse(new string('x', AlertReplayRunner.MaximumCorpusBytes + 1)));
    }
}
