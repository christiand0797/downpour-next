using System.Net;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour_Desktop;

/// <summary>
/// Turns the records shown on each tab into <see cref="DetailEntity"/> values, so every list row opens the same details
/// window and action menu. What the entity refers to (file, process, address, domain) decides the extra lookups and actions.
/// </summary>
internal static class DetailDescriptions
{
    public static DetailEntity Alert(SecurityAlert a)
    {
        var (file, address, domain) = Indicator(a.IndicatorKind, a.Indicator);
        return new DetailEntity(a.Title, $"{a.Severity} · {a.State}{(a.IsVerified ? " · verified" : "")}",
        [
            new("Severity", a.Severity), new("State", a.State), new("MITRE technique", a.Technique),
            new("Source", SecurityFindingCatalog.IsFinding(a.LogName) ? $"Downpour finding ({a.LogName})" : $"{a.LogName} · {a.Provider} · event {a.EventId}"),
            new("Event record", a.RecordId?.ToString() ?? ""), new("Event time", a.EventTimeUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")),
            new("First seen", a.FirstSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")), new("Last seen", a.LastSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")),
            new("Occurrences", a.Occurrences.ToString("N0")), new("Evidence", a.Indicator is null ? "" : $"{a.IndicatorKind}: {a.Indicator}"),
            new("Alert ID", a.AlertId),
        ], FilePath: file, Address: address, Domain: domain, Kind: "alert");
    }

    public static (string? File, string? Address, string? Domain) Indicator(string? kind, string? value) => kind switch
    {
        AlertIndicatorKinds.File => (value, null, null),
        AlertIndicatorKinds.Ip => (null, value, null),
        AlertIndicatorKinds.Domain => (null, null, value),
        _ => (null, null, null),
    };

    /// <summary>Guesses what a free-text indicator is (path, IP, endpoint or domain).</summary>
    public static (string? File, string? Address, string? Domain) Guess(string? indicator)
    {
        if (string.IsNullOrWhiteSpace(indicator)) return (null, null, null);
        var value = indicator.Trim();
        if (value.Length > 3 && (value[1] == ':' || value.StartsWith(@"\\", StringComparison.Ordinal)) && !value.Contains('\n')) return (value, null, null);
        if (IPAddress.TryParse(value, out _)) return (null, value, null);
        if (IPEndPoint.TryParse(value, out var endpoint) && value.Contains(':')) return (null, endpoint.Address.ToString(), null);
        if (value.Contains('.') && !value.Contains(' ') && Uri.CheckHostName(value) == UriHostNameType.Dns) return (null, null, value.ToLowerInvariant());
        return (null, null, null);
    }

    public static DetailEntity Finding(string area, string severity, string technique, string summary, string indicator)
    {
        var (file, address, domain) = Guess(indicator);
        return new DetailEntity(summary, $"{area} finding · {severity}",
            [new("Severity", severity), new("MITRE technique", technique), new("Finding", summary), new("Indicator", indicator)],
            FilePath: file, Address: address, Domain: domain, Kind: "finding");
    }

    public static DetailEntity ThreatMatch(ThreatMatch m)
    {
        // Driver and program subjects are "name (path)"; connections carry the address as the indicator.
        string? path = null;
        var open = m.Subject.IndexOf(" (", StringComparison.Ordinal);
        if (open > 0 && m.Subject.EndsWith(')')) path = m.Subject[(open + 2)..^1];
        var address = m.Where == ThreatMatchPlaces.Connection && IPAddress.TryParse(m.Indicator, out _) ? m.Indicator : null;
        var domain = m.Where == ThreatMatchPlaces.Dns ? m.Indicator : null;
        return new DetailEntity($"{m.Label}: {m.Subject}", $"{ThreatVerdicts.Label(m.Verdict)} · {m.Confidence}% confidence",
        [
            new("Verdict", $"{ThreatVerdicts.Label(m.Verdict)} ({m.Confidence}% confidence)"), new("Severity", m.Severity),
            new("Where", m.Where), new("Subject", m.Subject), new("Indicator", m.Indicator), new("Database", $"{m.FeedName} ({m.FeedId})"),
            new("Listed as", m.Label), new("MITRE technique", m.Technique), new("Seen", m.SeenAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")),
            new("Why", string.Join("; ", m.Reasons ?? [])),
        ], FilePath: path, Address: address, Domain: domain, Kind: "threat match");
    }

    public static DetailEntity Connection(RemoteConnectionOrigin c) => new(
        $"{c.Program} → {c.RemoteAddress}:{c.RemotePort}", c.Listed ? "Listed in a threat database" : "Connection to a public address",
        [
            new("Program", c.Program), new("Process ID", c.ProcessId.ToString()), new("Remote address", c.RemoteAddress), new("Remote port", c.RemotePort.ToString()),
            new("Country", c.CountryCode is { } code ? $"{IpOriginDatabase.CountryName(code)} ({code})" : "Unknown"),
            new("Network", c.Asn is { } asn ? $"AS{asn} · {c.Network}" : c.Network ?? ""), new("In a threat database", c.Listed ? "Yes" : "No"),
        ], ProcessId: c.ProcessId, Address: c.RemoteAddress, Kind: "connection");

    public static DetailEntity FeedEntry(string value, string type, string label)
    {
        var (_, address, domain) = Guess(value);
        return new DetailEntity(value, $"{type} · {label}", [new("Value", value), new("Type", type), new("Listed as", label)],
            FilePath: null, Address: address, Domain: domain ?? (type.Equals("URL", StringComparison.OrdinalIgnoreCase) && Uri.TryCreate(value, UriKind.Absolute, out var uri) ? uri.Host : null),
            Kind: "indicator");
    }

    public static DetailEntity UsbDrive(UsbConnectedDevice d) => new(
        $"{d.DriveLetter} {d.VolumeLabel}".Trim(), $"{d.Vendor} {d.Product} · {d.DriveType}",
        [
            new("Drive", d.DriveLetter), new("Label", d.VolumeLabel), new("File system", d.FileSystem),
            new("Size", $"{Bytes(d.TotalSizeBytes)} ({Bytes(d.FreeSizeBytes)} free)"), new("Vendor and product", $"{d.Vendor} {d.Product}"),
            new("Serial number", d.SerialNumber), new("Autorun file", d.HasAutorun ? "Present: Windows no longer runs it automatically, but do not open it" : "None"),
            new("Suspicious files in the root", d.HasSuspiciousFiles ? "Yes: scan before opening anything" : "None"), new("Device ID", d.PnpDeviceId ?? ""),
        ], FilePath: d.DriveLetter.Length > 0 ? d.DriveLetter.TrimEnd('\\') + "\\" : null, Kind: "usb drive");

    public static DetailEntity UsbHistory(UsbDeviceHistoryEntry e) => new(
        string.IsNullOrWhiteSpace(e.FriendlyName) ? $"{e.Vendor} {e.Product}".Trim() : e.FriendlyName, "USB storage device seen on this PC",
        [
            new("Name", e.FriendlyName), new("Vendor", e.Vendor), new("Product", e.Product), new("Revision", e.Revision),
            new("Serial number", e.SerialNumber), new("Hardware ID", e.HardwareId), new("Device ID", e.DeviceId),
        ], Kind: "usb history");

    public static DetailEntity WifiNetwork(WifiNetworkEntry n) => new(
        string.IsNullOrWhiteSpace(n.Ssid) ? "(Hidden network)" : n.Ssid, n.IsConnected ? "Connected Wi-Fi network" : "Nearby Wi-Fi network",
        [
            new("Network name", n.Ssid), new("Access point (BSSID)", n.Bssid), new("Signal", $"{n.SignalPercent}%"),
            new("Security", $"{n.Authentication} · {n.Cipher}"), new("Channel", n.Channel.ToString()), new("Type", n.NetworkType),
            new("Assessment", WifiAdvice(n)),
        ], Kind: "wifi");

    private static string WifiAdvice(WifiNetworkEntry n)
    {
        var auth = n.Authentication.ToUpperInvariant();
        if (auth.Contains("OPEN") || auth.Contains("NONE")) return "Open network: anyone nearby can read unencrypted traffic. Use a VPN or avoid signing in to anything.";
        if (auth.Contains("WEP")) return "WEP is broken and can be cracked in minutes. Do not use it.";
        if (auth.Contains("WPA3")) return "WPA3: the strongest Wi-Fi security available.";
        if (auth.Contains("WPA2")) return "WPA2: secure with a strong password.";
        if (auth.Contains("WPA")) return "Original WPA is outdated; prefer WPA2 or WPA3.";
        return "Security type not recognised.";
    }

    public static DetailEntity Bluetooth(BluetoothDeviceEntry b) => new(
        string.IsNullOrWhiteSpace(b.Name) ? b.Address : b.Name, b.IsSuspicious ? "Paired Bluetooth device · needs review" : "Paired Bluetooth device",
        [new("Name", b.Name), new("Address", b.Address), new("Registry entry", b.RegistryPath), new("Needs review", b.IsSuspicious ? "Yes: unnamed or unexpected pairing" : "No")],
        Kind: "bluetooth");

    public static DetailEntity IoT(IoTDevice d) => new(
        string.IsNullOrWhiteSpace(d.HostName) ? d.IpAddress : $"{d.HostName} ({d.IpAddress})", $"{d.DeviceCategory} · {d.ThreatLevel} risk",
        [
            new("IP address", d.IpAddress), new("MAC address", d.MacAddress), new("Host name", d.HostName), new("Maker", d.Vendor),
            new("Category", d.DeviceCategory), new("Open ports", string.Join(", ", d.OpenPorts)), new("Services", string.Join(", ", d.IdentifiedServices)),
            new("Botnet indicators", d.BotnetIndicators.Count == 0 ? "None" : string.Join("; ", d.BotnetIndicators)),
            new("Risk", $"{d.ThreatLevel} ({d.RiskScore}/100)"), new("Discovered", d.DiscoveredAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")),
        ], Address: d.IpAddress, Kind: "network device");

    public static DetailEntity EmergencyProcess(EmergencyProcessInfo p) => new(
        p.ProcessName, $"Process {p.ProcessId}{(p.IsSuspicious ? " · suspicious" : "")}",
        [
            new("Process ID", p.ProcessId.ToString()), new("Program", p.ExecutablePath), new("Memory", Bytes(p.WorkingSetBytes)),
            new("Started", p.StartTimeUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? ""), new("Why it is suspicious", p.SuspicionReason),
            new("MITRE technique", p.MitreTechnique),
        ], FilePath: string.IsNullOrWhiteSpace(p.ExecutablePath) ? null : p.ExecutablePath, ProcessId: p.ProcessId, Kind: "process");

    public static DetailEntity Kev(KevSoftwareCandidate c) => new(
        $"{c.CveId}: {c.VulnerabilityName}", $"{c.Vendor} {c.Product} · actively exploited (CISA KEV)",
        [
            new("CVE", c.CveId), new("Vulnerability", c.VulnerabilityName), new("Affected product (CISA)", $"{c.Vendor} {c.Product}"),
            new("Added to KEV", c.DateAdded.ToString("yyyy-MM-dd")), new("Installed software", $"{c.InstalledName} {c.InstalledVersion}".Trim()),
            new("Publisher", c.InstalledPublisher), new("What to do", "Check the vendor advisory for affected versions and update the software; this is a name match, not proof the installed version is affected."),
            new("Advisory", $"https://nvd.nist.gov/vuln/detail/{c.CveId}"),
        ], Kind: "vulnerability");

    public static DetailEntity Software(string name, string version, string publisher, string scope) => new(
        name, $"Installed software · {scope}",
        [new("Name", name), new("Version", version), new("Publisher", publisher), new("Installed for", scope)], Kind: "software");

    public static string Bytes(long bytes) => bytes switch
    {
        >= 1L << 40 => $"{bytes / (double)(1L << 40):0.0} TB",
        >= 1L << 30 => $"{bytes / (double)(1L << 30):0.0} GB",
        >= 1L << 20 => $"{bytes / (double)(1L << 20):0.0} MB",
        >= 1L << 10 => $"{bytes / 1024.0:0.0} KB",
        _ => $"{bytes} B",
    };
}
