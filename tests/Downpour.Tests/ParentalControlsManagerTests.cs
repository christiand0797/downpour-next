using Downpour.Contracts;
using Downpour.Core;
using Xunit;

namespace Downpour.Tests;

public sealed class ParentalControlsManagerTests : IDisposable
{
    private readonly string _testDirectory;

    public ParentalControlsManagerTests()
    {
        _testDirectory = Path.Combine(Path.GetTempPath(), "DownpourTests_Parental_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testDirectory);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testDirectory))
            {
                Directory.Delete(_testDirectory, recursive: true);
            }
        }
        catch
        {
            // Ignore test cleanup errors
        }
    }

    [Fact]
    public void EvaluateScreenTime_Weekday_CalculatesRemainingAndExceededProperly()
    {
        var schedule = new ScreenTimeSchedule(
            Enabled: true,
            WeekdayLimitMinutes: 120,
            WeekendLimitMinutes: 240,
            BedtimeStart: "21:00",
            BedtimeEnd: "07:00");

        // Wednesday at 2:00 PM (14:00)
        var wednesday = new DateTimeOffset(2026, 10, 7, 14, 0, 0, TimeSpan.Zero);

        var normalUsage = ParentalControlsManager.EvaluateScreenTime(schedule, wednesday, 90);
        Assert.False(normalUsage.IsWithinCurfew);
        Assert.False(normalUsage.IsLimitExceeded);
        Assert.Equal(120, normalUsage.TodayLimitMinutes);
        Assert.Equal(90, normalUsage.TodayUsageMinutes);
        Assert.Equal(30, normalUsage.RemainingMinutes);
        Assert.Equal(75.0, normalUsage.WarningPercent);

        var exceededUsage = ParentalControlsManager.EvaluateScreenTime(schedule, wednesday, 130);
        Assert.True(exceededUsage.IsLimitExceeded);
        Assert.Equal(0, exceededUsage.RemainingMinutes);
    }

    [Fact]
    public void EvaluateScreenTime_Weekend_UsesWeekendLimit()
    {
        var schedule = new ScreenTimeSchedule(
            Enabled: true,
            WeekdayLimitMinutes: 120,
            WeekendLimitMinutes: 240,
            BedtimeStart: "21:00",
            BedtimeEnd: "07:00");

        // Saturday at 3:00 PM (15:00)
        var saturday = new DateTimeOffset(2026, 10, 10, 15, 0, 0, TimeSpan.Zero);

        var weekendUsage = ParentalControlsManager.EvaluateScreenTime(schedule, saturday, 180);
        Assert.False(weekendUsage.IsWithinCurfew);
        Assert.False(weekendUsage.IsLimitExceeded);
        Assert.Equal(240, weekendUsage.TodayLimitMinutes);
        Assert.Equal(60, weekendUsage.RemainingMinutes);
    }

    [Theory]
    [InlineData(22, 30, true)]   // 22:30 -> Inside 21:00-07:00 curfew
    [InlineData(5, 45, true)]    // 05:45 -> Inside 21:00-07:00 curfew
    [InlineData(12, 0, false)]   // 12:00 -> Outside curfew
    [InlineData(20, 59, false)]  // 20:59 -> Outside curfew
    [InlineData(7, 0, false)]    // 07:00 -> Outside curfew
    public void EvaluateScreenTime_BedtimeCurfew_TriggersCorrectly(int hour, int minute, bool expectedCurfew)
    {
        var schedule = new ScreenTimeSchedule(
            Enabled: true,
            WeekdayLimitMinutes: 120,
            WeekendLimitMinutes: 240,
            BedtimeStart: "21:00",
            BedtimeEnd: "07:00");

        var testTime = new DateTimeOffset(2026, 10, 7, hour, minute, 0, TimeSpan.Zero);
        var status = ParentalControlsManager.EvaluateScreenTime(schedule, testTime, 30);

        Assert.Equal(expectedCurfew, status.IsWithinCurfew);
        if (expectedCurfew)
        {
            Assert.Contains("Bedtime curfew is active", status.CurfewMessage);
        }
    }

    [Fact]
    public void GetDomainsToBlock_AggregatesAndCleansSelectedCategories()
    {
        var policy = new WebFilterPolicy(
            Enabled: true,
            BlockAdultContent: true,
            BlockGambling: true,
            BlockViolence: false,
            BlockWeapons: false,
            BlockDrugs: false,
            CustomBlockedDomains: ["https://example-bad.com/path", "anotherbadsite.net"],
            SafeSearchEnforced: true);

        var domains = ParentalControlsManager.GetDomainsToBlock(policy);

        Assert.NotEmpty(domains);
        Assert.Contains("pornhub.com", domains);
        Assert.Contains("bet365.com", domains);
        Assert.Contains("example-bad.com", domains);
        Assert.Contains("anotherbadsite.net", domains);
        Assert.DoesNotContain("bestgore.com", domains); // Violence was false
    }

    [Fact]
    public void FormatHostsFileWithFilter_InsertsMarkersAndIsIdempotent()
    {
        string original = "# Existing hosts header\n127.0.0.1 localhost\n::1 localhost\n";
        var domains = new List<string> { "blocked1.com", "blocked2.net" };

        string formatted = ParentalControlsManager.FormatHostsFileWithFilter(original, domains);

        Assert.Contains(ParentalControlsManager.HostsFilterMarkerStart, formatted);
        Assert.Contains(ParentalControlsManager.HostsFilterMarkerEnd, formatted);
        Assert.Contains("127.0.0.1 blocked1.com", formatted);
        Assert.Contains("127.0.0.1 www.blocked1.com", formatted);
        Assert.Contains("127.0.0.1 localhost", formatted);

        // Updating with new domain list should replace old block cleanly
        var newDomains = new List<string> { "blocked3.org" };
        string reformatted = ParentalControlsManager.FormatHostsFileWithFilter(formatted, newDomains);

        Assert.Contains("127.0.0.1 blocked3.org", reformatted);
        Assert.DoesNotContain("blocked1.com", reformatted);
    }

    [Fact]
    public void InspectHostsFile_ReadsActiveFilterEntriesCorrectly()
    {
        string hostsPath = Path.Combine(_testDirectory, "hosts");
        var domains = new List<string> { "site1.com", "site2.com" };
        string formatted = ParentalControlsManager.FormatHostsFileWithFilter("127.0.0.1 localhost", domains);
        File.WriteAllText(hostsPath, formatted);

        var manager = new ParentalControlsManager(hostsFilePath: hostsPath);
        var posture = manager.InspectHostsFile(hostsPath);

        Assert.True(posture.IsAccessible);
        Assert.True(posture.HasDownpourFilterMarker);
        Assert.Equal(4, posture.ActiveBlockedDomainsCount); // 2 domains * 2 (domain + www)
    }

    [Fact]
    public void CheckActiveRestrictedApps_DetectsSimulatedProcesses()
    {
        var policy = new AppRestrictionPolicy(
            Enabled: true,
            BlockedExecutableNames: ["discord.exe", "steam.exe", "roblox.exe"],
            MonitoredProfileUsername: "child");

        var simulated = new List<string> { "explorer.exe", "discord.exe", "chrome.exe", "Steam" };

        var detected = ParentalControlsManager.CheckActiveRestrictedApps(policy, simulated);

        Assert.Equal(2, detected.Count);
        Assert.Contains("discord.exe", detected);
        Assert.Contains("Steam", detected);
    }

    [Fact]
    public void GenerateParentalPostureReport_ProducesStructuredMarkdown()
    {
        var manager = new ParentalControlsManager();
        var snapshot = manager.CapturePostureSnapshot(
            currentUsageMinutes: 45,
            simulatedProcesses: ["discord.exe"]);

        var logs = new List<ParentalActivityLogEntry>
        {
            new(DateTimeOffset.UtcNow, "Policy", "Info", "Parental controls loaded successfully")
        };

        string report = manager.GenerateParentalPostureReport(snapshot, logs);

        Assert.Contains("# Parental Controls & Family Safety Posture Report", report);
        Assert.Contains("## 1. Screen Time Management", report);
        Assert.Contains("## 2. Web Content Filtering", report);
        Assert.Contains("## 3. Application Restrictions", report);
        Assert.Contains("discord.exe", report);
        Assert.Contains("Parental controls loaded successfully", report);
    }
}
