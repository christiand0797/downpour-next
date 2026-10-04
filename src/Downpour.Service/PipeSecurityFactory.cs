using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Downpour.Service;

internal static class PipeSecurityFactory
{
    public static PipeSecurity CreateCurrentUserReadSecurity()
    {
        var security = new PipeSecurity();
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var currentUser = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("The current Windows identity has no user SID; refusing to create a broadly accessible telemetry pipe.");
        security.AddAccessRule(new PipeAccessRule(system, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            currentUser,
            PipeAccessRights.ReadWrite | PipeAccessRights.ReadAttributes | PipeAccessRights.ReadPermissions | PipeAccessRights.Synchronize,
            AccessControlType.Allow));
        return security;
    }
}
