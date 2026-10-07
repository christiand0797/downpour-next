using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Service;

public sealed record FirewallRuleSummary(
    string Name,
    string Description,
    string RemoteAddresses,
    string Direction,
    string Action,
    bool Enabled);

public interface IFirewallPolicyBackend
{
    void AddRule(string name, string description, int action, int direction, bool enabled, string remoteAddresses, int profiles, string grouping);
    void RemoveRule(string name);
    IReadOnlyList<FirewallRuleSummary> EnumerateRules();
}

/// <summary>
/// Production Windows Firewall policy backend communicating with HNetCfg.FwPolicy2 via COM.
/// </summary>
public sealed class WindowsFirewallPolicyBackend : IFirewallPolicyBackend
{
    public void AddRule(string name, string description, int action, int direction, bool enabled, string remoteAddresses, int profiles, string grouping)
    {
        var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: false);
        if (policyType is null) throw new InvalidOperationException("The Windows Firewall policy COM class (HNetCfg.FwPolicy2) is not registered.");

        var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: false);
        if (ruleType is null) throw new InvalidOperationException("The Windows Firewall rule COM class (HNetCfg.FWRule) is not registered.");

        object? policyObject = null;
        object? ruleObject = null;
        try
        {
            policyObject = Activator.CreateInstance(policyType);
            dynamic policy = policyObject!;

            // Remove existing rule with same name if already present to ensure idempotent add
            try
            {
                policy.Rules.Remove(name);
            }
            catch { }

            ruleObject = Activator.CreateInstance(ruleType);
            dynamic rule = ruleObject!;
            rule.Name = name;
            rule.Description = description;
            rule.Action = action;
            rule.Direction = direction;
            rule.Enabled = enabled;
            rule.RemoteAddresses = remoteAddresses;
            rule.Profiles = profiles;
            rule.Grouping = grouping;

            policy.Rules.Add(rule);
        }
        catch (COMException ex) when ((uint)ex.ErrorCode == 0x80070005)
        {
            throw new UnauthorizedAccessException("Access denied. Creating Windows Firewall rules requires administrator privileges.", ex);
        }
        finally
        {
            if (ruleObject is not null && Marshal.IsComObject(ruleObject)) Marshal.ReleaseComObject(ruleObject);
            if (policyObject is not null && Marshal.IsComObject(policyObject)) Marshal.FinalReleaseComObject(policyObject);
        }
    }

    public void RemoveRule(string name)
    {
        var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: false);
        if (policyType is null) throw new InvalidOperationException("The Windows Firewall policy COM class (HNetCfg.FwPolicy2) is not registered.");

        object? policyObject = null;
        try
        {
            policyObject = Activator.CreateInstance(policyType);
            dynamic policy = policyObject!;
            policy.Rules.Remove(name);
        }
        catch (COMException ex) when ((uint)ex.ErrorCode == 0x80070005)
        {
            throw new UnauthorizedAccessException("Access denied. Removing Windows Firewall rules requires administrator privileges.", ex);
        }
        catch (COMException ex) when ((uint)ex.ErrorCode == 0x80070002)
        {
            // Rule not found; treat as successfully absent
        }
        finally
        {
            if (policyObject is not null && Marshal.IsComObject(policyObject)) Marshal.FinalReleaseComObject(policyObject);
        }
    }

    public IReadOnlyList<FirewallRuleSummary> EnumerateRules()
    {
        var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: false);
        if (policyType is null) return [];

        object? policyObject = null;
        try
        {
            policyObject = Activator.CreateInstance(policyType);
            dynamic policy = policyObject!;
            var results = new List<FirewallRuleSummary>();
            object? rulesObject = policy.Rules;
            try
            {
                foreach (var ruleObj in (System.Collections.IEnumerable)rulesObject!)
                {
                    try
                    {
                        dynamic r = ruleObj;
                        string name = r.Name?.ToString() ?? "";
                        string desc = r.Description?.ToString() ?? "";
                        string remote = r.RemoteAddresses?.ToString() ?? "";
                        string dir = (int)r.Direction == 1 ? "Inbound" : "Outbound";
                        string act = (int)r.Action == 0 ? "Block" : "Allow";
                        bool en = (bool)r.Enabled;
                        results.Add(new FirewallRuleSummary(name, desc, remote, dir, act, en));
                    }
                    finally
                    {
                        if (ruleObj is not null && Marshal.IsComObject(ruleObj)) Marshal.ReleaseComObject(ruleObj);
                    }
                }
            }
            finally
            {
                if (rulesObject is not null && Marshal.IsComObject(rulesObject)) Marshal.ReleaseComObject(rulesObject);
            }
            return results;
        }
        catch
        {
            return [];
        }
        finally
        {
            if (policyObject is not null && Marshal.IsComObject(policyObject)) Marshal.FinalReleaseComObject(policyObject);
        }
    }
}

/// <summary>
/// Executes and validates firewall protection actions (DN-008 Phase 3).
/// Enforces remote IP deny-lists (loopback, unspecified, broadcast, link-local, local host, gateway, DNS),
/// Downpour rule naming verification for deletions, and automatic rule expiration tracking.
/// </summary>
public sealed class FirewallActionExecutor(IFirewallPolicyBackend? backend = null)
{
    private readonly IFirewallPolicyBackend _backend = backend ?? new WindowsFirewallPolicyBackend();

    public const string RulePrefix = "DownpourNext_Block_";
    public const int MaximumBlockMinutes = 7 * 24 * 60;
    public const string GroupingName = "Downpour Next Protection";

    public (bool Allowed, string? DenyReason, IPAddress? ValidatedIp) ValidateRemoteIp(string? ipString)
    {
        if (string.IsNullOrWhiteSpace(ipString))
            return (false, "A remote IP address is required.", null);

        var trimmed = ipString.Trim();
        if (!IPAddress.TryParse(trimmed, out var ip))
            return (false, $"'{trimmed}' is not a valid IPv4 or IPv6 address.", null);

        if (IPAddress.IsLoopback(ip))
            return (false, "Cannot block loopback IP address (would disrupt local system communication).", null);

        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any))
            return (false, "Cannot block wildcard / unspecified IP address.", null);

        if (ip.Equals(IPAddress.Broadcast))
            return (false, "Cannot block broadcast IP address.", null);

        var bytes = ip.GetAddressBytes();
        if (bytes.Length == 4)
        {
            // Link-local: 169.254.0.0/16
            if (bytes[0] == 169 && bytes[1] == 254)
                return (false, "Cannot block link-local IP address (169.254.0.0/16).", null);

            // Multicast: 224.0.0.0 to 239.255.255.255
            if (bytes[0] >= 224 && bytes[0] <= 239)
                return (false, "Cannot block IPv4 multicast IP address.", null);
        }
        else if (bytes.Length == 16)
        {
            if (ip.IsIPv6LinkLocal)
                return (false, "Cannot block IPv6 link-local IP address.", null);

            if (ip.IsIPv6Multicast)
                return (false, "Cannot block IPv6 multicast IP address.", null);
        }

        // Validate against local machine interface, gateway, and DNS addresses
        try
        {
            foreach (var iface in NetworkInterface.GetAllNetworkInterfaces())
            {
                var ipProps = iface.GetIPProperties();
                foreach (var unicast in ipProps.UnicastAddresses)
                {
                    if (unicast.Address.Equals(ip))
                        return (false, "Cannot block local host network adapter IP address.", null);
                }

                foreach (var gw in ipProps.GatewayAddresses)
                {
                    if (gw.Address.Equals(ip))
                        return (false, "Cannot block default network gateway IP address (would disrupt Internet connectivity).", null);
                }

                foreach (var dns in ipProps.DnsAddresses)
                {
                    if (dns.Equals(ip))
                        return (false, "Cannot block configured DNS server IP address (would disrupt domain name resolution).", null);
                }
            }
        }
        catch { }

        return (true, null, ip);
    }

    public (bool Allowed, string? DenyReason) ValidateRuleNameForRemoval(string? ruleName)
    {
        if (string.IsNullOrWhiteSpace(ruleName))
            return (false, "A rule name is required.");

        var trimmed = ruleName.Trim();
        if (trimmed.StartsWith("DownpourNext_", StringComparison.OrdinalIgnoreCase) || FirewallRuleAnalyzer.IsDownpourRule(trimmed))
            return (true, null);

        return (false, "Cannot remove non-Downpour firewall rule. Only rules created by Downpour Next or legacy Downpour may be removed.");
    }

    public (bool Succeeded, IReadOnlyList<string> CreatedRules, string? ErrorMessage) BlockRemoteIp(
        IPAddress ip,
        int durationMinutes,
        string? reason)
    {
        var sanitized = ip.ToString().Replace(':', '_');
        var ruleNameIn = $"{RulePrefix}{sanitized}_In";
        var ruleNameOut = $"{RulePrefix}{sanitized}_Out";

        if (durationMinutes is < 1 or > MaximumBlockMinutes)
            return (false, [], $"Blocks must expire within 1 minute to {MaximumBlockMinutes / 1440} days.");
        var expiryStr = DateTimeOffset.UtcNow.AddMinutes(durationMinutes).ToString("O");
        // The reason is free text; strip the field separator and the "Expiry:" marker so it cannot spoof the expiry.
        var safeReason = (reason ?? "Operator consent").Replace("|", "/").Replace("Expiry:", "Expiry -", StringComparison.OrdinalIgnoreCase);
        var desc = $"Downpour Next Remote IP Block | Target: {ip} | Reason: {safeReason} | Expiry: {expiryStr}";

        var created = new List<string>();
        try
        {
            _backend.AddRule(ruleNameOut, desc, action: 0, direction: 2, enabled: true, remoteAddresses: ip.ToString(), profiles: 0x7FFFFFFF, grouping: GroupingName);
            created.Add(ruleNameOut);

            _backend.AddRule(ruleNameIn, desc, action: 0, direction: 1, enabled: true, remoteAddresses: ip.ToString(), profiles: 0x7FFFFFFF, grouping: GroupingName);
            created.Add(ruleNameIn);

            return (true, created, null);
        }
        catch (Exception ex)
        {
            return (false, created, ex.Message);
        }
    }

    public (bool Succeeded, string? ErrorMessage) RemoveRule(string ruleName)
    {
        var validation = ValidateRuleNameForRemoval(ruleName);
        if (!validation.Allowed)
            return (false, validation.DenyReason);

        try
        {
            _backend.RemoveRule(ruleName.Trim());
            return (true, null);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    public (bool Succeeded, IReadOnlyList<string> RemovedRules, string? ErrorMessage) CleanupLegacyRules()
    {
        var removed = new List<string>();
        try
        {
            var rules = _backend.EnumerateRules();
            var legacy = rules
                .Where(r => FirewallRuleAnalyzer.IsDownpourRule(r.Name) && !r.Name.StartsWith("DownpourNext_", StringComparison.OrdinalIgnoreCase))
                .Select(r => r.Name)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (var ruleName in legacy)
            {
                try
                {
                    _backend.RemoveRule(ruleName);
                    removed.Add(ruleName);
                }
                catch { }
            }

            return (true, removed, null);
        }
        catch (Exception ex)
        {
            return (false, removed, ex.Message);
        }
    }

    public IReadOnlyList<string> CleanupExpiredRules()
    {
        var removed = new List<string>();
        try
        {
            var rules = _backend.EnumerateRules();
            var now = DateTimeOffset.UtcNow;

            foreach (var r in rules)
            {
                if (!r.Name.StartsWith("DownpourNext_", StringComparison.OrdinalIgnoreCase))
                    continue;

                // Check Description for "Expiry: <ISO>"
                var desc = r.Description;
                var expiryIndex = desc.LastIndexOf("Expiry: ", StringComparison.OrdinalIgnoreCase);
                if (expiryIndex >= 0)
                {
                    var expStr = desc[(expiryIndex + 8)..].Trim();
                    var endSpace = expStr.IndexOf(' ');
                    if (endSpace > 0) expStr = expStr[..endSpace];

                    if (expStr != "Permanent" && DateTimeOffset.TryParse(expStr, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var expiryUtc))
                    {
                        if (expiryUtc <= now)
                        {
                            try
                            {
                                _backend.RemoveRule(r.Name);
                                removed.Add(r.Name);
                            }
                            catch { }
                        }
                    }
                }
            }
        }
        catch { }

        return removed;
    }
}
