using System.Text;
using Downpour.Core;
using Xunit;

namespace Downpour.Tests;

public sealed class DetectionAndBehaviorTests
{
    [Fact]
    public void BaselineNeedsSamplesAndScoresOutliers()
    {
        var baseline = new BehaviorBaseline(minimumSamples: 5, deviationFloor: 1);
        Assert.Null(baseline.Score("conns", 10));

        foreach (var value in new[] { 100d, 102, 98, 101, 99, 100, 101, 99 }) baseline.Observe("conns", value);

        Assert.Equal(8, baseline.SampleCount("conns"));
        Assert.InRange(baseline.Score("conns", 100)!.Value, 0, 2);
        Assert.True(baseline.Score("conns", 140) > 3);
        Assert.True(baseline.IsUnusual("conns", 140));
        Assert.False(baseline.IsUnusual("conns", 101));
        Assert.Null(baseline.Score("unknown", 1));
    }

    [Theory]
    [InlineData("dns.google", 443, true)]
    [InlineData("DNS.GOOGLE.", 443, true)]
    [InlineData("sub.dns.google", 443, true)]
    [InlineData("evildns.google", 443, false)]
    [InlineData("dns.google", 53, false)]
    [InlineData("anything.example", 853, true)]
    [InlineData(null, 443, false)]
    public void EncryptedDnsRecognisesKnownResolversAndDot(string? host, int port, bool expected)
    {
        Assert.Equal(expected, EncryptedDnsDetector.IsEncryptedDnsEndpoint(host, port));
    }

    [Fact]
    public void RuleQualityBudgetEnforcesRecordedNoise()
    {
        const string json = """
            {
              "schemaVersion": 1,
              "ruleCount": 179,
              "corpus": "test",
              "lowConfidence": { "rule:noisy": 12, "rule:slightly_noisy": 1 }
            }
            """;
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));
        var budget = DetectionQualityBudget.Load(stream);

        Assert.Equal(179, budget.RuleCount);
        Assert.True(budget.IsLowConfidence("rule:noisy"));
        Assert.True(budget.WithinBudget("rule:noisy", 12));
        Assert.False(budget.WithinBudget("rule:noisy", 13));
        Assert.True(budget.WithinBudget("rule:clean", 0));
        Assert.False(budget.WithinBudget("rule:clean", 1));
    }

    [Fact]
    public void RepositoryRuleQualityFileLoadsAndStaysConsistent()
    {
        var path = Path.Combine(RepositoryRoot(), "src", "Downpour.Scanner", "rule_quality.json");
        using var stream = File.OpenRead(path);
        var budget = DetectionQualityBudget.Load(stream);

        Assert.True(budget.RuleCount > 150);
        Assert.NotEmpty(budget.CleanFileMatches);
        Assert.All(budget.CleanFileMatches, pair =>
        {
            Assert.True(budget.IsLowConfidence(pair.Key));
            Assert.True(budget.WithinBudget(pair.Key, pair.Value));
        });
    }

    private static string RepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "Downpour.slnx"))) return directory.FullName;
        throw new InvalidOperationException("Could not find the repository root.");
    }
}
