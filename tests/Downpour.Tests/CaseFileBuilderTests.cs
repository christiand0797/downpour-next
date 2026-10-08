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
}
