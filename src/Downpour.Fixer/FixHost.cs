using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Downpour.Core;
using Microsoft.Win32;

namespace Downpour.Fixer;

/// <summary>Real system access for <see cref="HardeningFixes"/>: HKLM registry, local accounts, Windows Firewall and Microsoft Defender.</summary>
internal sealed class FixHost : IFixHost
{
    private const string DefenderScope = @"root\Microsoft\Windows\Defender";

    public RegistryReading? Read(string path, string name)
    {
        using var key = Registry.LocalMachine.OpenSubKey(path);
        if (key is null || !key.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase)) return null;
        return key.GetValueKind(name) switch
        {
            RegistryValueKind.DWord => new RegistryReading("dword", Convert.ToInt64(key.GetValue(name)), ""),
            RegistryValueKind.String or RegistryValueKind.ExpandString => new RegistryReading("string", 0, key.GetValue(name, "", RegistryValueOptions.DoNotExpandEnvironmentNames) as string ?? ""),
            _ => new RegistryReading("other", 0, ""),
        };
    }

    public void WriteDword(string path, string name, long value)
    {
        using var key = Registry.LocalMachine.CreateSubKey(path, writable: true);
        key.SetValue(name, unchecked((int)value), RegistryValueKind.DWord);
    }

    public void WriteString(string path, string name, string value)
    {
        using var key = Registry.LocalMachine.CreateSubKey(path, writable: true);
        key.SetValue(name, value, RegistryValueKind.String);
    }

    public void Delete(string path, string name)
    {
        using var key = Registry.LocalMachine.OpenSubKey(path, writable: true);
        key?.DeleteValue(name, throwOnMissingValue: false);
    }

    public IReadOnlyList<string> SubKeys(string path)
    {
        using var key = Registry.LocalMachine.OpenSubKey(path);
        return key?.GetSubKeyNames() ?? [];
    }

    public bool? AccountDisabled(int rid)
    {
        var name = AccountName(rid);
        if (name is null) return null;
        if (NetUserGetInfo(null, name, 1, out var buffer) != 0) return null;
        try { return (Marshal.PtrToStructure<UserInfo1>(buffer).Flags & UfAccountDisable) != 0; }
        finally { NetApiBufferFree(buffer); }
    }

    public void SetAccountDisabled(int rid, bool disabled)
    {
        var name = AccountName(rid) ?? throw new InvalidOperationException("The account was not found.");
        if (NetUserGetInfo(null, name, 1, out var buffer) != 0) throw new InvalidOperationException("The account could not be read.");
        uint flags;
        try { flags = Marshal.PtrToStructure<UserInfo1>(buffer).Flags; }
        finally { NetApiBufferFree(buffer); }
        var info = new UserInfo1008 { Flags = disabled ? flags | UfAccountDisable : flags & ~UfAccountDisable };
        var status = NetUserSetInfo(null, name, 1008, ref info, out _);
        if (status != 0) throw new InvalidOperationException($"Windows refused the account change (error {status}).");
    }

    public bool CurrentUserIs(int rid)
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User?.Value.EndsWith("-" + rid, StringComparison.Ordinal) == true;
    }

    /// <summary>Resolves the built-in account by its well-known RID on this machine (names are translated or renamed).</summary>
    private static string? AccountName(int rid)
    {
        using var searcher = new ManagementObjectSearcher("SELECT Name, SID FROM Win32_UserAccount WHERE LocalAccount = TRUE");
        foreach (ManagementObject item in searcher.Get())
            using (item)
                if (item["SID"] is string sid && sid.EndsWith("-" + rid, StringComparison.Ordinal)) return item["Name"] as string;
        return null;
    }

    public bool? FirewallEnabled(int profile)
    {
        dynamic policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!)!;
        try { return (bool)policy.FirewallEnabled[profile]; }
        finally { Marshal.FinalReleaseComObject(policy); }
    }

    public void SetFirewallEnabled(int profile, bool enabled)
    {
        dynamic policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!)!;
        try { policy.FirewallEnabled[profile] = enabled; }
        finally { Marshal.FinalReleaseComObject(policy); }
    }

    public long? DefenderPreference(string name)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(DefenderScope, $"SELECT {name} FROM MSFT_MpPreference");
            foreach (ManagementObject item in searcher.Get())
                using (item)
                    return item[name] switch { bool b => b ? 1 : 0, null => null, var v => Convert.ToInt64(v) };
        }
        catch (ManagementException) { }
        return null;
    }

    public void SetDefenderPreference(string name, long value)
    {
        using var preference = new ManagementClass(DefenderScope, "MSFT_MpPreference", null);
        using var input = preference.GetMethodParameters("Set");
        input[name] = input.Properties[name].Type == CimType.Boolean ? value != 0 : (object)Convert.ToByte(value);
        using var output = preference.InvokeMethod("Set", input, null);
        if (output?["ReturnValue"] is uint code && code != 0) throw new InvalidOperationException($"Defender refused the change (0x{code:X8}). Tamper protection or an organisation policy may lock it.");
    }

    public int? AsrRuleAction(string ruleId)
    {
        using var searcher = new ManagementObjectSearcher(DefenderScope, "SELECT AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions FROM MSFT_MpPreference");
        foreach (ManagementObject item in searcher.Get())
        {
            using (item)
            {
                if (item["AttackSurfaceReductionRules_Ids"] is not string[] ids || item["AttackSurfaceReductionRules_Actions"] is not byte[] actions) return null;
                var index = Array.FindIndex(ids, id => id.Equals(ruleId, StringComparison.OrdinalIgnoreCase));
                return index >= 0 && index < actions.Length ? actions[index] : null;
            }
        }
        return null;
    }

    public void SetAsrRule(string ruleId, int? action)
    {
        using var preference = new ManagementClass(DefenderScope, "MSFT_MpPreference", null);
        var method = action is null ? "Remove" : "Add";
        using var input = preference.GetMethodParameters(method);
        input["AttackSurfaceReductionRules_Ids"] = new[] { ruleId };
        if (action is { } a) input["AttackSurfaceReductionRules_Actions"] = new[] { (byte)a };
        using var output = preference.InvokeMethod(method, input, null);
        if (output?["ReturnValue"] is uint code && code != 0) throw new InvalidOperationException($"Defender refused the rule change (0x{code:X8}).");
    }

    public void UpdateDefenderSignatures()
    {
        using var signature = new ManagementClass(DefenderScope, "MSFT_MpSignature", null);
        using var input = signature.GetMethodParameters("Update");
        using var output = signature.InvokeMethod("Update", input, null);
        if (output?["ReturnValue"] is uint code && code != 0) throw new InvalidOperationException($"Definition update failed (0x{code:X8}).");
    }

    private const uint UfAccountDisable = 0x0002;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct UserInfo1
    {
        public string Name;
        public string Password;
        public uint PasswordAge;
        public uint Privilege;
        public string HomeDir;
        public string Comment;
        public uint Flags;
        public string ScriptPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UserInfo1008 { public uint Flags; }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserGetInfo(string? server, string user, int level, out IntPtr buffer);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserSetInfo(string? server, string user, int level, ref UserInfo1008 info, out int parameterError);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);
}
