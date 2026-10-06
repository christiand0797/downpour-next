using System.Security.AccessControl;
using System.Security.Principal;

namespace Downpour.Service;

/// <summary>Read-only ACL checks shared by sensors that look for plantable locations.</summary>
internal static class FileSystemExposure
{
    private static readonly SecurityIdentifier[] BroadPrincipals =
    [
        new(WellKnownSidType.WorldSid, null),
        new(WellKnownSidType.AuthenticatedUserSid, null),
        new(WellKnownSidType.BuiltinUsersSid, null),
        new(WellKnownSidType.InteractiveSid, null),
    ];

    /// <summary>
    /// True when the directory ACL lets ordinary users plant files: an allow rule granting CreateFiles/WriteData to
    /// Everyone, Authenticated Users, Users, INTERACTIVE or the current user, with no matching deny. This replaces
    /// v29's os.access(W_OK), which on Windows only checks the read-only attribute. Unreadable ACLs return false.
    /// </summary>
    public static bool IsWritableByStandardUsers(string directory)
    {
        try
        {
            if (!Directory.Exists(directory)) return false;
            var principals = new HashSet<SecurityIdentifier>(BroadPrincipals);
            if (WindowsIdentity.GetCurrent().User is { } current) principals.Add(current);
            var rules = new DirectoryInfo(directory).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier));
            const FileSystemRights plant = FileSystemRights.CreateFiles | FileSystemRights.WriteData;
            bool allowed = false, denied = false;
            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.IdentityReference is not SecurityIdentifier sid || !principals.Contains(sid) || (rule.FileSystemRights & plant) == 0) continue;
                if (rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly)) continue;
                if (rule.AccessControlType == AccessControlType.Deny) denied = true; else allowed = true;
            }
            return allowed && !denied;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException or SystemException)
        {
            return false;
        }
    }

    /// <summary>Caches answers within one capture so repeated folders are checked once.</summary>
    public static Func<string, bool> CachedChecker()
    {
        var cache = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        return directory =>
        {
            if (!cache.TryGetValue(directory, out var writable))
                cache[directory] = writable = IsWritableByStandardUsers(directory);
            return writable;
        };
    }
}
