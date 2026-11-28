using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class LocalAccountPersistenceTests
{
    private static PersistenceObservation Account(string name, string value) =>
        new(PersistenceCategories.LocalAccount, "Local users", name, value, "T1136.001");

    private static (IReadOnlyList<PersistenceEntry> Entries, PersistenceBaseline Baseline) Observe(
        PersistenceBaseline? baseline, DateTimeOffset now, params PersistenceObservation[] observations)
    {
        var (entries, updated, _) = PersistenceAnalyzer.Compare(observations, baseline, now);
        return (entries, updated);
    }

    [Theory]
    [InlineData("enabled, administrator", "CRITICAL")]
    [InlineData("enabled, standard user", "HIGH")]
    [InlineData("disabled, administrator", "MEDIUM")]
    public void NewLocalAccountIsReportedWithItsPrivilegeAndState(string value, string severity)
    {
        var now = DateTimeOffset.UtcNow;
        var (_, baseline) = Observe(null, now);
        var observations = new[] { Account("bob", value) };

        var (entries, _) = Observe(baseline, now.AddMinutes(1), observations);
        var finding = Assert.Single(PersistenceAnalyzer.Findings(entries, observations));

        Assert.Equal(severity, finding.Severity);
        Assert.Equal("T1136.001", finding.Technique);
        Assert.Equal(PersistenceCategories.LocalAccount, finding.Category);
        Assert.Contains("Local account new: bob", finding.Summary);
    }

    [Fact]
    public void AddingAnExistingAccountToAdministratorsIsACriticalModification()
    {
        var now = DateTimeOffset.UtcNow;
        var (_, first) = Observe(null, now.AddDays(-30), Account("bob", "enabled, standard user"));
        var observations = new[] { Account("bob", "enabled, administrator") };

        var (entries, _) = Observe(first, now, observations);
        var finding = Assert.Single(PersistenceAnalyzer.Findings(entries, observations));

        Assert.Equal(PersistenceChanges.Modified, entries[0].Change);
        Assert.Equal("CRITICAL", finding.Severity);
        Assert.Contains("Local account modified: bob (enabled, administrator)", finding.Summary);
    }

    [Fact]
    public void RepeatingASweepWithTheSameAccountStateIsNotAChange()
    {
        // The provider baselines enabled/administrator only, so a routine sign-in cannot look like a modification.
        var now = DateTimeOffset.UtcNow;
        var observations = new[] { Account("bob", "enabled, standard user") };
        var (_, first) = Observe(null, now, observations);

        var (repeated, _) = Observe(first, now.AddHours(1), observations);
        Assert.Equal(PersistenceChanges.Baseline, repeated[0].Change);

        var (later, _) = Observe(first, now.AddDays(8), observations);
        Assert.Equal(PersistenceChanges.Baseline, later[0].Change);
        Assert.Empty(PersistenceAnalyzer.Findings(later, observations));
    }

    [Fact]
    public void TheDesktopClientAcceptsTheNewCategory()
    {
        var snapshot = new PersistenceSnapshot(1, DateTimeOffset.UtcNow, null, true,
            [new PersistenceEntry(PersistenceCategories.LocalAccount, "Local users", "bob", "enabled, standard user",
                "T1136.001", PersistenceChanges.Baseline, null, [])],
            [], [], []);

        Assert.Contains(PersistenceCategories.LocalAccount, PersistenceCategories.All);
        Assert.True(PersistenceInventoryClient.IsValid(snapshot));
    }
}
