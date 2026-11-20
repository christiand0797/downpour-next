namespace Downpour.Core;

public sealed record RescueStep(string Title, string Detail, bool ChangesSystem);

/// <summary>
/// Plans an incident-response kit for a machine that may already be compromised. The portable build can run without an
/// installation, so the kit is deliberately read-only: triage, evidence export and a clear statement of what was not
/// changed. Anything that would alter the host is listed as unavailable here and must go through the action broker.
/// </summary>
public static class RescueKitPlan
{
    public static IReadOnlyList<RescueStep> Build(bool networkAvailable, bool caseExportAvailable)
    {
        var steps = new List<RescueStep>
        {
            new("Run from removable media", "Start the portable build from the USB device so nothing is installed on the suspect machine.", false),
            new("Read-only triage", "Review processes, autostarts, services, drivers and connections with the normal sensors; no remediation runs automatically.", false),
            new("Record the change digest", "Save the local change ledger so what appeared and disappeared during the response is preserved with timestamps.", false),
            new("Capture volatile evidence", "Export the forensic bundle and hash seal before anything else changes state.", false),
        };
        if (caseExportAvailable)
            steps.Add(new("Produce a verifiable case pack", "Export the case with a redaction preview and a detached signature so a second opinion can verify its origin.", false));
        if (networkAvailable)
            steps.Add(new("Check indicators only if intended", "Feed downloads are whole-file and send nothing about this PC; online lookups send indicators and stay off unless a key is configured.", false));
        else
            steps.Add(new("Work offline", "No network is available: saved threat databases and the local index still match, but no source will update.", false));
        steps.Add(new("Hand over, do not clean up", "Remediation is a separate, confirmed action after evidence is preserved; the kit never deletes files or disables services.", false));
        return steps;
    }

    /// <summary>Guards the promise above: a rescue plan containing a changing step is refused rather than shown as read-only.</summary>
    public static IReadOnlyList<string> ValidateReadOnly(IReadOnlyList<RescueStep> steps)
    {
        ArgumentNullException.ThrowIfNull(steps);
        return steps.Where(step => step.ChangesSystem)
            .Select(step => $"Rescue step '{step.Title}' changes the system and cannot run in a read-only kit.")
            .ToArray();
    }
}
