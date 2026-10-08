using System.Text.Json;
using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class PersistenceInventoryTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 1, 12, 0, 0, TimeSpan.Zero);

    private static PersistenceObservation Run(string name, string value) =>
        new(PersistenceCategories.RegistryRun, @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", name, value, "T1547.001");

    private static PersistenceObservation Task(string name, string action, string runAs = "user") =>
        new(PersistenceCategories.ScheduledTask, @"\", name, action, "T1053.005", runAs);

    [Fact]
    public void FirstScanIsTrustOnFirstUseWithNoFindings()
    {
        var observations = new[] { Run("OneDrive", "onedrive.exe"), Task(@"\GoogleUpdateTaskMachineUA", @"C:\Program Files\Google\update.exe") };
        var (entries, baseline, first) = PersistenceAnalyzer.Compare(observations, null, T0);

        Assert.True(first);
        Assert.All(entries, entry => Assert.Equal(PersistenceChanges.Baseline, entry.Change));
        Assert.All(entries, entry => Assert.Empty(entry.Indicators));
        Assert.Empty(PersistenceAnalyzer.Findings(entries, observations));
        Assert.Equal(2, baseline.Items.Count);
        Assert.DoesNotContain(baseline.Items.Values, item => item.ValueSha256.Contains("onedrive", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void BaselineStoresHashesNotCommands()
    {
        var (_, baseline, _) = PersistenceAnalyzer.Compare([Run("Evil", "powershell -enc SECRET")], null, T0);
        var json = JsonSerializer.Serialize(baseline);
        Assert.DoesNotContain("SECRET", json);
        Assert.DoesNotContain("powershell", json);
    }

    [Fact]
    public void NewAndModifiedItemsAreReportedThenAgeOutAfterSevenDays()
    {
        var (_, baseline, _) = PersistenceAnalyzer.Compare([Run("Updater", "a.exe")], null, T0);

        var later = T0.AddDays(1);
        var observations = new[] { Run("Updater", "b.exe"), Run("Dropper", @"C:\Users\x\AppData\Roaming\d.exe") };
        var (entries, updated, first) = PersistenceAnalyzer.Compare(observations, baseline, later);

        Assert.False(first);
        Assert.Equal(PersistenceChanges.Modified, entries.Single(e => e.Name == "Updater").Change);
        Assert.Equal(PersistenceChanges.New, entries.Single(e => e.Name == "Dropper").Change);
        var findings = PersistenceAnalyzer.Findings(entries, observations);
        Assert.Contains(findings, f => f.Severity == "HIGH" && f.Technique == "T1574.011" && f.Summary.Contains("modified"));
        Assert.Contains(findings, f => f.Severity == "HIGH" && f.Summary.Contains("Dropper"));

        // Still highlighted on day 7, gone on day 9 without any acknowledgement step.
        var (week, _, _) = PersistenceAnalyzer.Compare(observations, updated, later.AddDays(7));
        Assert.Equal(PersistenceChanges.New, week.Single(e => e.Name == "Dropper").Change);
        var (aged, _, _) = PersistenceAnalyzer.Compare(observations, updated, later.AddDays(8));
        Assert.All(aged, entry => Assert.Equal(PersistenceChanges.Baseline, entry.Change));
    }

    [Theory]
    [InlineData(@"\a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", @"C:\Program Files\x.exe", "user", "CRITICAL")]
    [InlineData(@"\Backup", "powershell.exe -nop -w hidden", "user", "HIGH")]
    [InlineData(@"\Backup", @"C:\Users\a\AppData\Local\x.exe", "user", "HIGH")]
    [InlineData(@"\Backup", @"C:\Program Files\x.exe", "SYSTEM", "HIGH")]
    [InlineData(@"\Backup", @"C:\Program Files\x.exe", "user", "MEDIUM")]
    public void NewScheduledTaskSeverityMatchesV29(string name, string action, string runAs, string severity)
    {
        var (_, baseline, _) = PersistenceAnalyzer.Compare([], null, T0);
        var observations = new[] { Task(name, action, runAs) };
        var (entries, _, _) = PersistenceAnalyzer.Compare(observations, baseline, T0.AddHours(1));
        var finding = Assert.Single(PersistenceAnalyzer.Findings(entries, observations));
        Assert.Equal(severity, finding.Severity);
        Assert.Equal("T1053.005", finding.Technique);
    }

    [Fact]
    public void AlwaysOnChecksFireEvenForBaselineItems()
    {
        var observations = new[]
        {
            new PersistenceObservation(PersistenceCategories.DriverFile, @"C:\Windows\System32\drivers", "rtcore64.sys", "path", "T1068"),
            new PersistenceObservation(PersistenceCategories.DllShadow, @"C:\Tools", "version.dll", @"C:\Tools\version.dll", "T1574.001"),
            new PersistenceObservation(PersistenceCategories.WmiSubscription, @"root\subscription", "CommandLineEventConsumer:Updater", "cmd.exe /c x", "T1546.003"),
            new PersistenceObservation(PersistenceCategories.WmiSubscription, @"root\subscription", "__EventFilter:SCM Event Log Filter", "select", "T1546.003"),
            new PersistenceObservation(PersistenceCategories.DriverFile, @"C:\Windows\System32\drivers", "ntfs.sys", "path", "T1068"),
        };
        var (entries, _, _) = PersistenceAnalyzer.Compare(observations, null, T0);
        var findings = PersistenceAnalyzer.Findings(entries, observations);

        Assert.Contains(findings, f => f.Severity == "CRITICAL" && f.Summary.Contains("rtcore64.sys"));
        Assert.Contains(findings, f => f.Severity == "HIGH" && f.Summary.Contains("version.dll"));
        Assert.Contains(findings, f => f.Severity == "CRITICAL" && f.Summary.Contains("CommandLineEventConsumer"));
        Assert.Equal(3, findings.Count);
    }

    private static IReadOnlyList<PersistenceFinding> NewRunFindings(string value, PersistenceSignature? signature)
    {
        var (_, baseline, _) = PersistenceAnalyzer.Compare([], null, T0);
        var observations = new[] { new PersistenceObservation(PersistenceCategories.RegistryRun,
            @"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", "msedge_cleanup", value, "T1547.001") };
        var (entries, _, _) = PersistenceAnalyzer.Compare(observations, baseline, T0.AddHours(1));
        return PersistenceAnalyzer.Findings(entries, observations, _ => signature);
    }

    [Fact]
    public void MicrosoftSignedAutostartInProgramFilesIsLow()
    {
        var finding = Assert.Single(NewRunFindings(
            "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\141.0.3537.57\\Installer\\setup.exe\" --msedge --channel=stable --cleanup-old-versions",
            new(true, "Microsoft Corporation", true)));
        Assert.Equal("LOW", finding.Severity);
        Assert.Contains("signed by Microsoft Corporation", finding.Summary);
    }

    [Theory]
    [InlineData(@"C:\Users\a\AppData\Local\Discord\Update.exe --processStart Discord.exe", true, "MEDIUM")]
    [InlineData(@"C:\Users\a\AppData\Roaming\x\evil.exe", false, "HIGH")]
    [InlineData(@"C:\Windows\System32\rundll32.exe C:\Users\a\x.dll,Start", true, "HIGH")]
    public void SignerCheckNeverHidesUserWritableUnsignedOrLolbinTargets(string value, bool signed, string severity)
    {
        var finding = Assert.Single(NewRunFindings(value, new(signed, signed ? "CN=Vendor Inc, O=Vendor Inc, C=US" : null, false)));
        Assert.Equal(severity, finding.Severity);
    }

    [Fact]
    public void UnverifiableAutostartKeepsHighSeverity()
    {
        Assert.Equal("HIGH", Assert.Single(NewRunFindings(@"C:\Program Files\x\x.exe", null)).Severity);
    }

    [Theory]
    [InlineData(true, "MEDIUM", "legitimate but vulnerable, signed by Micro-Star International CO., LTD.")]
    [InlineData(false, "CRITICAL", "not validly signed")]
    public void ByovdSeverityFollowsTheDriverSignature(bool signed, string severity, string text)
    {
        var observations = new[] { new PersistenceObservation(PersistenceCategories.DriverFile, @"C:\Windows\System32\drivers", "msio64.sys", "path", "T1068") };
        var (entries, _, _) = PersistenceAnalyzer.Compare(observations, null, T0);
        PersistenceEntry? checkedEntry = null;
        var finding = Assert.Single(PersistenceAnalyzer.Findings(entries, observations, entry =>
        {
            checkedEntry = entry;
            return new(signed, signed ? "CN=\"Micro-Star International CO., LTD.\", O=x" : null, false);
        }));
        Assert.Equal(severity, finding.Severity);
        Assert.Contains(text, finding.Summary);
        Assert.Equal(@"C:\Windows\System32\drivers\msio64.sys", PersistenceAnalyzer.LaunchTarget(checkedEntry!));
    }

    [Fact]
    public void SignerIsNotCalledForQuietBaselineItems()
    {
        var observations = new[] { Run("OneDrive", "onedrive.exe"),
            new PersistenceObservation(PersistenceCategories.DriverFile, @"C:\Windows\System32\drivers", "ntfs.sys", "path", "T1068") };
        var (entries, _, _) = PersistenceAnalyzer.Compare(observations, null, T0);
        Assert.Empty(PersistenceAnalyzer.Findings(entries, observations, _ => throw new InvalidOperationException("should not verify")));
    }

    [Theory]
    [InlineData("\"C:\\Program Files\\A B\\a.exe\" --flag", @"C:\Program Files\A B\a.exe")]
    [InlineData(@"C:\Program Files\A B\a.exe --flag", @"C:\Program Files\A B\a.exe")]
    [InlineData(@"C:\Windows\system32\userinit.exe,", @"C:\Windows\system32\userinit.exe")]
    [InlineData("explorer.exe", "explorer.exe")]
    [InlineData(@"%ProgramFiles%\x\y.exe /background", @"%ProgramFiles%\x\y.exe")]
    [InlineData("   ", null)]
    public void CommandTargetFindsTheExecutable(string command, string? expected) =>
        Assert.Equal(expected, PersistenceAnalyzer.CommandTarget(command));

    [Theory]
    [InlineData(@"\\server\share\x.exe")]
    [InlineData(@"relative\x.exe")]
    [InlineData(@"C:\definitely\missing\file.exe")]
    [InlineData("")]
    public void ResolveTargetRejectsNetworkRelativeAndMissingPaths(string target) =>
        Assert.Null(PersistenceInventoryProvider.ResolveTarget(target));

    [Fact]
    public void ResolveTargetFindsBareSystemBinaries() =>
        Assert.EndsWith(@"\notepad.exe", PersistenceInventoryProvider.ResolveTarget("notepad.exe"), StringComparison.OrdinalIgnoreCase);

    [Fact]
    public void LegitimateWmiFilterIsNotReportedWhenNew()
    {
        var (_, baseline, _) = PersistenceAnalyzer.Compare([], null, T0);
        var observations = new[]
        {
            new PersistenceObservation(PersistenceCategories.WmiSubscription, @"root\subscription", "__EventFilter:BVTFilter", "q", "T1546.003"),
            new PersistenceObservation(PersistenceCategories.WmiSubscription, @"root\subscription", "__EventFilter:Persist", "q", "T1546.003"),
        };
        var (entries, _, _) = PersistenceAnalyzer.Compare(observations, baseline, T0.AddMinutes(5));
        var finding = Assert.Single(PersistenceAnalyzer.Findings(entries, observations));
        Assert.Contains("Persist", finding.Summary);
    }

    [Fact]
    public void WinlogonWatchesOnlyCodeLaunchingValues()
    {
        Assert.Contains("Shell", PersistenceInventoryProvider.WinlogonPersistenceValues);
        Assert.Contains("Userinit", PersistenceInventoryProvider.WinlogonPersistenceValues);
        Assert.DoesNotContain("LastUsedUsername", PersistenceInventoryProvider.WinlogonPersistenceValues);
    }

    [Fact]
    public void ProtectedSystemFolderIsNotWritableByStandardUsers()
    {
        Assert.False(PersistenceInventoryProvider.IsWritableByStandardUsers(Environment.GetFolderPath(Environment.SpecialFolder.System)));
        Assert.False(PersistenceInventoryProvider.IsWritableByStandardUsers(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)));
        // The user's own temp folder grants the current user write access.
        Assert.True(PersistenceInventoryProvider.IsWritableByStandardUsers(Path.GetTempPath()));
    }

    [Fact]
    public void LiveCaptureCreatesBaselineThenReusesIt()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"downpour-persistence-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var provider = new PersistenceInventoryProvider(Path.Combine(directory, "baseline.json"));
            var first = provider.Capture();
            Assert.True(first.IsFirstBaseline);
            Assert.True(PersistenceInventoryClient.IsValid(first), string.Join(" | ", first.Warnings));
            Assert.Contains(first.Entries, entry => entry.Category == PersistenceCategories.ScheduledTask);
            Assert.All(first.Entries, entry => Assert.Equal(PersistenceChanges.Baseline, entry.Change));
            Assert.True(JsonSerializer.SerializeToUtf8Bytes(first, new JsonSerializerOptions(JsonSerializerDefaults.Web)).Length < BoundedJson.MaximumPayloadBytes);

            var second = provider.Capture();
            Assert.False(second.IsFirstBaseline);
            Assert.Equal(first.BaselineCreatedAtUtc, second.BaselineCreatedAtUtc);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void CorruptBaselineIsRecreatedWithWarning()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"downpour-persistence-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var path = Path.Combine(directory, "baseline.json");
            File.WriteAllText(path, "{ not json");
            var snapshot = new PersistenceInventoryProvider(path).Capture();
            Assert.True(snapshot.IsFirstBaseline);
            Assert.Contains(snapshot.Warnings, warning => warning.Contains("recreated"));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void ClientRejectsUnknownCategoriesAndChanges()
    {
        var entry = new PersistenceEntry(PersistenceCategories.RegistryRun, "loc", "name", "value", "T1547.001", PersistenceChanges.Baseline, null, []);
        var good = new PersistenceSnapshot(1, T0, T0, false, [entry], [], [], []);
        Assert.True(PersistenceInventoryClient.IsValid(good));
        Assert.False(PersistenceInventoryClient.IsValid(good with { Entries = [entry with { Category = "Other" }] }));
        Assert.False(PersistenceInventoryClient.IsValid(good with { Entries = [entry with { Change = "Deleted" }] }));
        Assert.False(PersistenceInventoryClient.IsValid(good with { SchemaVersion = 2 }));
    }
}
