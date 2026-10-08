using Downpour.Contracts;

namespace Downpour.Core;

public sealed record DriverVerdict(string Severity, string Title, string Explanation);

/// <summary>
/// What a loaded driver is, from three independent signals: its signature (embedded or Windows catalog), where it loads
/// from, and whether the LOLDrivers database lists its exact hash as malicious or vulnerable (matched by the threat
/// database sweep). A known-malicious hash is critical regardless of signature; a vulnerable but validly signed vendor
/// driver is a real but lower risk (attackers with admin rights can abuse it); an unsigned driver or one in a folder
/// users can write to is high because Windows normally loads only signed drivers from protected folders.
/// </summary>
public static class DriverAssessment
{
    public static DriverVerdict Assess(DriverInventoryEntry driver, IReadOnlyList<ThreatMatch> matches)
    {
        var hits = matches.Where(m => m.Where == ThreatMatchPlaces.Driver
            && m.Subject.StartsWith(driver.Name + " (", StringComparison.OrdinalIgnoreCase)).ToArray();
        var malicious = hits.FirstOrDefault(m => m.Label.Contains("malicious", StringComparison.OrdinalIgnoreCase) || m.Verdict == ThreatVerdicts.Confirmed);
        if (malicious is not null)
            return new DriverVerdict("CRITICAL", "Known malicious driver",
                $"Its exact hash is listed as malicious in {malicious.FeedName} ({malicious.Label}). Investigate in Threat Databases and Triage before rebooting.");
        var vulnerable = hits.FirstOrDefault();
        if (vulnerable is not null)
            return driver.Signed == true
                ? new DriverVerdict("MEDIUM", "Legitimate but vulnerable",
                    $"Signed by {PersistenceAnalyzer.SignerDisplay(driver.Signer)}, but {vulnerable.FeedName} lists this exact version as vulnerable ({vulnerable.Label}). Attackers with admin rights can abuse it (BYOVD). Update or remove the software that installed it.")
                : new DriverVerdict("HIGH", "Vulnerable and not validly signed",
                    $"{vulnerable.FeedName} lists this driver as vulnerable ({vulnerable.Label}) and its signature did not verify.");
        if (driver.IsInUserWritableLocation)
            return new DriverVerdict("HIGH", "Loaded from a user-writable folder",
                "Kernel drivers normally load from protected Windows folders; one in Temp, AppData, Downloads or Public is a common rootkit technique.");
        return driver.Signed switch
        {
            false => new DriverVerdict("HIGH", "Not validly signed",
                "The driver's signature did not verify. Windows only loads unsigned drivers when signature enforcement is weakened (test signing, debug mode or an exploit)."),
            true when driver.MicrosoftSigned => new DriverVerdict("OK", "Windows driver", "Signed by Microsoft."),
            true => new DriverVerdict("OK", "Signed vendor driver", $"Signed by {PersistenceAnalyzer.SignerDisplay(driver.Signer)}; not listed in the driver threat databases."),
            _ => new DriverVerdict("INFO", "Signature not checked", "The file could not be read to check its signature (it may be protected or removed after loading)."),
        };
    }
}
