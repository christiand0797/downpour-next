using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Win32;

namespace Downpour.Service;

/// <summary>
/// Read-only Windows Firewall inventory: profile state, rules (HNetCfg.FwPolicy2 via IDispatch), service state,
/// and recent Security event 5157 (connection blocked by the Filtering Platform). Never modifies firewall state.
/// </summary>
public sealed class FirewallInventoryProvider(WindowsServiceInventoryProvider services)
{
    internal const int MaximumRules = 4096;
    internal const int MaximumBlockedEvents = 100;
    private const int MaximumText = 512;
    private static readonly (int Type, string Name)[] ProfileTypes = [(1, "Domain"), (2, "Private"), (4, "Public")];

    public FirewallSnapshot Capture()
    {
        var warnings = new List<string>();
        var serviceState = services.Capture().Services
            .FirstOrDefault(service => service.ServiceName.Equals("MpsSvc", StringComparison.OrdinalIgnoreCase))?.State ?? "Unknown";
        var (profiles, rules, ruleCount) = ReadPolicy(warnings);
        var (eventsStatus, blocked) = ReadBlockedConnections(warnings);
        var findings = FirewallRuleAnalyzer.Analyze(serviceState, profiles, rules);
        return new FirewallSnapshot(1, DateTimeOffset.UtcNow, serviceState, profiles, ruleCount, rules, eventsStatus, blocked, findings, warnings);
    }

    private static (IReadOnlyList<FirewallProfileState>, IReadOnlyList<FirewallRuleEntry>, int) ReadPolicy(List<string> warnings)
    {
        var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: false);
        if (policyType is null)
        {
            warnings.Add("The Windows Firewall policy COM class is not registered.");
            return ([], [], 0);
        }

        object? policyObject = null;
        try
        {
            policyObject = Activator.CreateInstance(policyType);
            dynamic policy = policyObject!;
            int current = policy.CurrentProfileTypes;
            var profiles = ProfileTypes.Select(profile =>
            {
                bool? enabled = null;
                string inbound = "Unknown", outbound = "Unknown";
                try
                {
                    // Parameterized COM properties are indexed through the IDispatch binder.
                    enabled = (bool)policy.FirewallEnabled[profile.Type];
                    inbound = MapAction((int)policy.DefaultInboundAction[profile.Type]);
                    outbound = MapAction((int)policy.DefaultOutboundAction[profile.Type]);
                }
                catch (Exception ex) when (ex is COMException or UnauthorizedAccessException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
                {
                    warnings.Add($"{profile.Name} profile state could not be read.");
                }
                return new FirewallProfileState(profile.Name, (current & profile.Type) != 0, enabled, inbound, outbound);
            }).ToArray();

            var rules = new List<FirewallRuleEntry>();
            var packageScopes = ReadPackageScopes();
            var total = 0;
            object? rulesObject = policy.Rules;
            try
            {
                foreach (var ruleObject in (System.Collections.IEnumerable)rulesObject!)
                {
                    try
                    {
                        total++;
                        if (rules.Count < MaximumRules) rules.Add(ToEntry(ruleObject, packageScopes));
                    }
                    finally
                    {
                        if (ruleObject is not null && Marshal.IsComObject(ruleObject)) Marshal.ReleaseComObject(ruleObject);
                    }
                }
            }
            finally
            {
                if (rulesObject is not null && Marshal.IsComObject(rulesObject)) Marshal.ReleaseComObject(rulesObject);
            }
            if (total > MaximumRules) warnings.Add($"Showing the first {MaximumRules:N0} of {total:N0} firewall rules.");
            return (profiles, rules, total);
        }
        catch (Exception ex) when (ex is COMException or UnauthorizedAccessException or InvalidCastException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
        {
            warnings.Add($"Firewall policy could not be read ({ex.GetType().Name}).");
            return ([], [], 0);
        }
        finally
        {
            if (policyObject is not null && Marshal.IsComObject(policyObject)) Marshal.FinalReleaseComObject(policyObject);
        }
    }

    private static FirewallRuleEntry ToEntry(object ruleObject, IReadOnlyDictionary<string, string> packageScopes)
    {
        dynamic rule = ruleObject;
        string name = Text(rule.Name);
        var direction = (int)rule.Direction == 1 ? "Inbound" : "Outbound";
        string package = ReadAppPackage(rule);
        if (package.Length == 0 && packageScopes.TryGetValue($"{direction}|{name}", out var family)) package = family;
        return new FirewallRuleEntry(
            Name: name,
            Direction: direction,
            Action: MapAction((int)rule.Action),
            Enabled: (bool)rule.Enabled,
            Protocol: MapProtocol((int)rule.Protocol),
            LocalPorts: Text(rule.LocalPorts),
            RemoteAddresses: Text(rule.RemoteAddresses),
            Profiles: MapProfiles((int)rule.Profiles),
            Application: Text(rule.ApplicationName),
            Service: Text(rule.serviceName),
            AppPackage: package,
            Grouping: Text(rule.Grouping),
            IsDownpourRule: FirewallRuleAnalyzer.IsDownpourRule(name));
    }

    private static (string, IReadOnlyList<FirewallBlockedConnection>) ReadBlockedConnections(List<string> warnings)
    {
        string[] fields = ["Direction", "Application", "SourceAddress", "DestAddress", "DestPort", "Protocol"];
        var selector = new EventLogPropertySelector(fields.Select(field => $"Event/EventData/Data[@Name='{field}']"));
        var results = new List<FirewallBlockedConnection>();
        try
        {
            var query = new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=5157)]]") { ReverseDirection = true };
            using var reader = new EventLogReader(query);
            while (results.Count < MaximumBlockedEvents && reader.ReadEvent(TimeSpan.FromSeconds(5)) is EventLogRecord record)
            {
                using (record)
                {
                    var values = record.GetPropertyValues(selector);
                    results.Add(new FirewallBlockedConnection(
                        record.TimeCreated is { } time ? new DateTimeOffset(time.ToUniversalTime(), TimeSpan.Zero) : DateTimeOffset.MinValue,
                        MapEventDirection(Text(values[0])),
                        Text(values[1]),
                        Text(values[2]),
                        Text(values[3]),
                        Text(values[4]),
                        Text(values[5]) switch { "6" => "TCP", "17" => "UDP", "1" => "ICMP", "58" => "ICMPv6", var other => other }));
                }
            }
            return (results.Count == 0 ? FirewallBlockedEventsStatuses.NoEvents : FirewallBlockedEventsStatuses.Available, results);
        }
        catch (UnauthorizedAccessException)
        {
            return (FirewallBlockedEventsStatuses.AccessDenied, []);
        }
        catch (Exception ex) when (ex is EventLogException or InvalidOperationException)
        {
            warnings.Add($"Security event log could not be queried ({ex.GetType().Name}).");
            return (FirewallBlockedEventsStatuses.Unavailable, []);
        }
    }

    private const string RuleStore = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
    private const int MaximumStoreValues = 8192;
    private const int MaximumStoreValueLength = 8192;

    /// <summary>
    /// Store app rules are scoped by package family name (PFN), which the firewall COM API does not expose.
    /// This reads the local rule store (an undocumented "v2.x|Key=Value|..." format) only to learn which
    /// direction+name pairs are package-scoped, so they are not reported as open to every program.
    /// Any read or parse failure leaves the scope empty; it never adds findings.
    /// </summary>
    internal static IReadOnlyDictionary<string, string> ReadPackageScopes()
    {
        var scopes = new Dictionary<string, string>(StringComparer.Ordinal);
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RuleStore);
            if (key is null) return scopes;
            foreach (var valueName in key.GetValueNames().Take(MaximumStoreValues))
            {
                if (key.GetValue(valueName) is string data && data.Length <= MaximumStoreValueLength
                    && ParseRuleStoreEntry(data) is { } entry)
                    scopes.TryAdd($"{entry.Direction}|{entry.Name}", entry.Package);
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            // Package scope stays unknown.
        }
        return scopes;
    }

    internal static (string Direction, string Name, string Package)? ParseRuleStoreEntry(string data)
    {
        string? direction = null, name = null, package = null;
        foreach (var field in data.Split('|'))
        {
            var equals = field.IndexOf('=');
            if (equals <= 0) continue;
            var value = field[(equals + 1)..];
            switch (field[..equals])
            {
                case "Dir": direction = value switch { "In" => "Inbound", "Out" => "Outbound", _ => null }; break;
                case "Name": name ??= value; break;
                case "PFN": package ??= value; break;
            }
        }
        return direction is not null && !string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(package)
            ? (direction, Text(name), Text(package))
            : null;
    }

    /// <summary>INetFwRule3.LocalAppPackageId scopes Store/UWP app rules; older rule objects lack it.</summary>
    private static string ReadAppPackage(dynamic rule)
    {
        try
        {
            return Text(rule.LocalAppPackageId);
        }
        catch (Exception ex) when (ex is Microsoft.CSharp.RuntimeBinder.RuntimeBinderException or COMException)
        {
            return "";
        }
    }

    internal static string MapAction(int action) => action switch { 0 => "Block", 1 => "Allow", _ => "Unknown" };

    internal static string MapProtocol(int protocol) => protocol switch
    {
        6 => "TCP", 17 => "UDP", 1 => "ICMPv4", 58 => "ICMPv6", 256 => "Any", _ => protocol.ToString()
    };

    internal static string MapProfiles(int mask)
    {
        if ((mask & 0x7) == 0x7 || mask == int.MaxValue) return "All";
        var names = ProfileTypes.Where(profile => (mask & profile.Type) != 0).Select(profile => profile.Name).ToArray();
        return names.Length == 0 ? "None" : string.Join(", ", names);
    }

    private static string MapEventDirection(string value) => value switch
    {
        "%%14592" => "Inbound",
        "%%14593" => "Outbound",
        _ => value
    };

    private static string Text(object? value)
    {
        var text = value?.ToString() ?? "";
        return text.Length <= MaximumText ? text : text[..MaximumText];
    }
}
