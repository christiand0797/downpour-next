using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Downpour.Service;

internal static class PipeSecurityFactory
{
    public static PipeSecurity CreateAuthenticatedReadSecurity()
    {
        var security = new PipeSecurity();
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var authenticatedUsers = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
        security.AddAccessRule(new PipeAccessRule(system, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            authenticatedUsers,
            PipeAccessRights.ReadWrite | PipeAccessRights.ReadAttributes | PipeAccessRights.ReadPermissions | PipeAccessRights.Synchronize,
            AccessControlType.Allow));
        return security;
    }
}
