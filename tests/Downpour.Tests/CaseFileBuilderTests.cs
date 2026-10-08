using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class CaseFileBuilderTests
{
    [Fact]
    public void CaseFileCarriesInstructionsVerdictReasonsAndGaps()
    {
        var now = DateTimeOffset.UtcNow;
        var match = new ThreatMatch(now, ThreatMatchPlaces.Driver, "abc", "AmdTools64.sys (C:\\x)", "loldrivers", "LOLDrivers", "Vulnerable driver: AmdTools64.sys",
            "MEDIUM", "T1068", ThreatVerdicts.VulnerableLegitimate, 60, ["Validly signed by Advanced Micro Devices, Inc."]);
        var db = new ThreatDatabaseSnapshot(1, now, true, 10, [], [match], [], new ThreatDatabaseCoverage(1, 2, 3, 4, now, TimeSpan.FromSeconds(1)),
            [new RemoteConnectionOrigin("chrome.exe", 10, "1.1.1.1", 443, "US", 13335, "CLOUDFLARENET", false)], []);
        var alert = new SecurityAlert(new string('a', 64), "Bad\u0007thing", "HIGH", "T1059", "Downpour/ThreatDatabase", "p", 0, null, now, now, now, 3, "Open");
        var text = CaseFileBuilder.Build(new CaseFileInputs(now, "0.1.18", "Windows 10.0.26100", new SecurityAlertSnapshot(1, now, 1, [alert], []),
            db, null, null, null, null, ["{\"action\":\"quarantine\"}"], ["Anti-stalker monitor"]));

        Assert.Contains("Instructions for the reviewer", text);
        Assert.Contains("Prefer reversible actions", text);
        Assert.Contains("Legitimate but vulnerable (60%)", text);
        Assert.Contains("Validly signed by Advanced Micro Devices", text);
        Assert.Contains("Anti-stalker monitor", text);
        Assert.Contains("AS13335 CLOUDFLARENET", text);
        Assert.Contains("\"schema\": \"downpour-case-file/1\"", text);
        Assert.Contains("quarantine", text);
        Assert.DoesNotContain('\u0007', text);
    }

    [Fact]
    public void CaseFileIncludesAudioShieldAndAlertEvidence()
    {
        var now = DateTimeOffset.UtcNow;
        var alert = new SecurityAlert(new string('a', 64), "YARA rule ransom_note matched note.txt", "HIGH", "T1486", SecurityFindingCatalog.Yara,
            new string('b', 32), 0, null, now, now, now, 1, "Open", IndicatorKind: AlertIndicatorKinds.File, Indicator: @"C:\Users\a\Desktop\note.txt");
        var audio = new AudioSnapshot(1, now,
            [new("{0.0.1}.{n}", "Headset Microphone (AirPods)", "AirPods", AudioFlows.Recording, "active", AudioDeviceKinds.Bluetooth, true, null, 80, false, 0.1, true, now)],
            [new(AudioFlows.Recording, "Headset Microphone (AirPods)", AudioDeviceKinds.Bluetooth, 4242, "updater", @"C:\Users\a\AppData\Roaming\u\updater.exe", "active", 0.3, false, false, null)],
            [new("{1}", "Rogue APO", @"C:\Windows\System32\rogue.dll", false, null, false)],
            new AudioPosture(true, true, "Running", "Running", 2, @"C:\Windows\System32\audiodg.exe", true, 1, 0, 0),
            [new("HIGH", AudioIssueCategories.Listening, "Unsigned program is listening: updater", "detail", "T1123", "listen|updater|x")], []);

        var text = CaseFileBuilder.Build(new CaseFileInputs(now, "0.1.19", "Windows", new SecurityAlertSnapshot(1, now, 1, [alert], []),
            null, null, null, null, null, [], [], audio));

        Assert.Contains(@"file: `C:\Users\a\Desktop\note.txt`", text);
        Assert.Contains("## Audio Shield", text);
        Assert.Contains("Recording (active): updater (PID 4242)", text);
        Assert.Contains("NOT validly signed", text);
        Assert.Contains("Rogue APO", text);
        Assert.Contains("first seen", text);
        Assert.Contains("Unsigned program is listening", text);
        Assert.Contains("\"audio\":", text);
    }
}
