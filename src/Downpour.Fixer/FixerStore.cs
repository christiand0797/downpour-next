using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Downpour.Core;

namespace Downpour.Fixer;

/// <summary>
/// The fixer's protected folder: SYSTEM and Administrators can write, users can only read. A folder that is a link, or
/// was created by a non-administrator (ProgramData lets users create folders), is refused rather than trusted.
/// </summary>
internal static class FixerStore
{
    public static void Prepare()
    {
        var parent = Path.GetDirectoryName(FixerProtocol.Root)!;
        foreach (var folder in new[] { parent, FixerProtocol.Root, Path.Combine(FixerProtocol.Root, "results"), Path.Combine(FixerProtocol.Root, "status"), Path.Combine(FixerProtocol.Root, "backups") })
        {
            if (Directory.Exists(folder))
            {
                var info = new DirectoryInfo(folder);
                if (info.Attributes.HasFlag(FileAttributes.ReparsePoint)) throw new InvalidOperationException($"{folder} is a link; refusing to use it.");
                var owner = info.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
                if (owner is null || !(owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) || owner.IsWellKnown(WellKnownSidType.LocalSystemSid)))
                    throw new InvalidOperationException($"{folder} was not created by an administrator. Delete it and try again.");
            }
            else
            {
                Directory.CreateDirectory(folder);
            }
            Protect(folder);
        }
    }

    private static void Protect(string folder)
    {
        var security = new DirectorySecurity();
        security.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(folder).SetAccessControl(security);
    }

    public static void Write<T>(string path, T value)
    {
        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(value, HardeningFixes.Json), new UTF8Encoding(false));
        File.Move(temp, path, overwrite: true);
    }

    /// <summary>Append-only audit log; each line carries the SHA-256 of the previous line so edits and deletions show.</summary>
    public static void Audit(string verb, string requestId, string detail)
    {
        var previous = "";
        if (File.Exists(FixerProtocol.AuditPath))
        {
            var last = File.ReadLines(FixerProtocol.AuditPath).LastOrDefault();
            if (last is not null) previous = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(last)));
        }
        var line = JsonSerializer.Serialize(new
        {
            at = DateTimeOffset.UtcNow,
            user = Environment.UserName,
            verb,
            request = requestId,
            detail = detail.Length > 2000 ? detail[..2000] : detail,
            previous,
        });
        File.AppendAllText(FixerProtocol.AuditPath, line + Environment.NewLine, new UTF8Encoding(false));
    }
}
