namespace Downpour.Core;

public sealed record AclPrincipal(string Name, string Sid);

/// <summary>
/// Refuses pipe or state ACLs that would widen local IPC beyond the intended principals. These SIDs are exactly the
/// shortcut that turns a local telemetry pipe into a local attack surface, so they are rejected by name rather than
/// merely documented as discouraged.
/// </summary>
public static class ServiceIdentityPolicy
{
    public static IReadOnlySet<string> ForbiddenSids { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-1-0",  // Everyone
        "S-1-5-11", // Authenticated Users
        "S-1-5-7",  // Anonymous
        "S-1-5-32-545", // Users
        "S-1-5-32-546", // Guests
    };

    public static IReadOnlyList<string> ValidatePipeAcl(IReadOnlyList<AclPrincipal> principals)
    {
        ArgumentNullException.ThrowIfNull(principals);
        var problems = new List<string>();
        if (principals.Count == 0) problems.Add("The pipe ACL names no principal.");
        if (principals.Count > 8) problems.Add("The pipe ACL names more than eight principals; each addition needs a recorded reason.");
        foreach (var principal in principals)
        {
            if (string.IsNullOrWhiteSpace(principal.Sid) || !principal.Sid.StartsWith("S-1-", StringComparison.Ordinal))
                problems.Add($"Principal {principal.Name} has no usable SID.");
            else if (ForbiddenSids.Contains(principal.Sid))
                problems.Add($"Principal {principal.Name} ({principal.Sid}) would grant the pipe to a broad local group.");
        }
        return problems;
    }

    /// <summary>
    /// Describes what an installed (least-privilege) deployment needs per sensor. Portable mode runs as the user and is
    /// explicitly weaker; this is the plan the installer must implement rather than a claim about today's build.
    /// </summary>
    public static IReadOnlyList<string> InstalledModeRequirements() =>
    [
        "A dedicated service identity with a SID-restricted pipe ACL; never Authenticated Users or Everyone.",
        "Protected event-log access granted by group membership during install, with an audit record and a documented removal path.",
        "Privileged reads performed by a broker that validates caller image path, process identity and request schema.",
        "State and evidence folders owned by the service identity with user read-only access, refusing pre-existing links.",
        "Uninstall that removes the identity, its ACLs and its state without deleting user-owned evidence.",
    ];
}
