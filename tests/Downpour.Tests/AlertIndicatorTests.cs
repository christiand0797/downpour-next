using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class AlertIndicatorTests
{
    [Theory]
    [InlineData(SecurityFindingCatalog.Yara, @"C:\Users\Public\Downloads\evil.exe", AlertIndicatorKinds.File)]
    [InlineData(SecurityFindingCatalog.Yara, @"relative\evil.exe", null)]
    [InlineData(SecurityFindingCatalog.Yara, @"C:\a.exe:stream", null)]
    [InlineData(SecurityFindingCatalog.Intel, "203.0.113.9", AlertIndicatorKinds.Ip)]
    [InlineData(SecurityFindingCatalog.Intel, "2001:db8::1", AlertIndicatorKinds.Ip)]
    [InlineData(SecurityFindingCatalog.Intel, "44d88612fea8a8f36de82e1278abb02f", AlertIndicatorKinds.Hash)]
    [InlineData(SecurityFindingCatalog.Intel, "bad.example.com", AlertIndicatorKinds.Domain)]
    [InlineData(SecurityFindingCatalog.Dns, "xkqzjvbn.example.net", AlertIndicatorKinds.Domain)]
    [InlineData(SecurityFindingCatalog.Hardening, @"C:\Windows\System32\cmd.exe", null)] // not a known indicator source
    [InlineData(SecurityFindingCatalog.Intel, "", null)]
    public void ClassifiesOnlyKnownSourcesAndShapes(string source, string value, string? expected) =>
        Assert.Equal(expected, AlertIndicatorKinds.Classify(source, value));

    [Fact]
    public async Task RepositoryStoresAndReturnsTheIndicator()
    {
        var root = Path.Combine(Path.GetTempPath(), "DownpourAlertIndicators-" + Guid.NewGuid().ToString("N"));
        SecureJournalDirectory.Ensure(root);
        try
        {
            var repository = new SecurityAlertRepository(Path.Combine(root, "alerts.db"));
            await repository.InitializeAsync();
            var file = SecurityFindingMapper.Create(SecurityFindingCatalog.Yara, "YARA match", "CRITICAL", "T1486", "YARA rule x matched evil.exe", @"C:\Users\Public\evil.exe");
            var ip = SecurityFindingMapper.Create(SecurityFindingCatalog.Intel, "Intel", "HIGH", "T1071", "Malicious IP", "203.0.113.9");
            var posture = SecurityFindingMapper.Create(SecurityFindingCatalog.Hardening, "Hardening", "MEDIUM", "Posture", "SMBv1 enabled", "SMB1");
            await repository.IngestFindingsAsync([file, ip, posture], DateTimeOffset.UtcNow);

            var snapshot = await repository.ReadSnapshotAsync();
            Assert.True(SecurityAlertClient.IsValidSnapshot(snapshot));
            Assert.Contains(snapshot.Alerts, a => a.IndicatorKind == AlertIndicatorKinds.File && a.Indicator == @"C:\Users\Public\evil.exe");
            Assert.Contains(snapshot.Alerts, a => a.IndicatorKind == AlertIndicatorKinds.Ip && a.Indicator == "203.0.113.9");
            Assert.Contains(snapshot.Alerts, a => a.Title == "SMBv1 enabled" && a.IndicatorKind is null && a.Indicator is null);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try { Directory.Delete(root, true); } catch (IOException) { }
        }
    }

    [Fact]
    public void ClientRejectsInconsistentIndicators()
    {
        var now = DateTimeOffset.UtcNow;
        SecurityAlertSnapshot Snapshot(string? kind, string? value) => new(1, now, 1,
        [
            new SecurityAlert(new string('a', 64), "t", "HIGH", "T1071", SecurityFindingCatalog.Intel, new string('b', 32), 0, null,
                now, now, now, 1, "Open", false, kind, value),
        ], []);
        Assert.True(SecurityAlertClient.IsValidSnapshot(Snapshot(AlertIndicatorKinds.Ip, "203.0.113.9")));
        Assert.True(SecurityAlertClient.IsValidSnapshot(Snapshot(null, null)));
        Assert.False(SecurityAlertClient.IsValidSnapshot(Snapshot("registry", "HKLM")));
        Assert.False(SecurityAlertClient.IsValidSnapshot(Snapshot(AlertIndicatorKinds.Ip, null)));
        Assert.False(SecurityAlertClient.IsValidSnapshot(Snapshot(null, "203.0.113.9")));
    }
}
