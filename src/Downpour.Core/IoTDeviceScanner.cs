using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// Strictly read-only local subnet IoT device scanner, MAC vendor fingerprinting engine,
/// and Mozi / Mirai / Kimwolf botnet indicator detector.
/// </summary>
public sealed class IoTDeviceScanner
{
    private static readonly Dictionary<string, string> OuiMap = new(StringComparer.OrdinalIgnoreCase)
    {
        // Espressif (ESP8266 / ESP32 — smart home IoT)
        ["C4:DD:57"] = "Espressif Systems (ESP8266/32)",
        ["CC:50:E3"] = "Espressif Systems (ESP8266/32)",
        ["A4:CF:12"] = "Espressif Systems (ESP8266/32)",
        ["84:F3:EB"] = "Espressif Systems (ESP8266/32)",
        ["8C:AA:B5"] = "Espressif Systems (ESP8266/32)",
        ["30:AE:A4"] = "Espressif Systems (ESP8266/32)",
        ["E8:DB:84"] = "Espressif Systems (ESP8266/32)",
        ["24:6F:28"] = "Espressif Systems (ESP8266/32)",
        ["EC:FA:BC"] = "Espressif Systems (ESP8266/32)",
        ["BC:DD:C2"] = "Espressif Systems (ESP8266/32)",
        ["10:52:1C"] = "Espressif Systems (ESP8266/32)",
        ["68:C6:3A"] = "Espressif Systems (ESP8266/32)",
        ["40:F5:20"] = "Espressif Systems (ESP8266/32)",

        // Gaoshengda Technology (IoT WiFi modules)
        ["94:B3:F7"] = "Gaoshengda Technology (IoT WiFi module)",
        ["DC:4F:22"] = "Gaoshengda Technology (IoT WiFi module)",
        ["B0:E4:D5"] = "Gaoshengda Technology (IoT WiFi module)",
        ["C8:47:8C"] = "Gaoshengda Technology (IoT WiFi module)",

        // Tuya Smart (smart home platform)
        ["50:02:91"] = "Tuya Smart (smart plug/bulb/thermostat)",
        ["D8:3F:27"] = "Tuya Smart (smart plug/bulb)",
        ["7C:01:0A"] = "Tuya Smart (smart device)",

        // TP-Link
        ["50:C7:BF"] = "TP-Link (router/smart plug)",
        ["E8:65:D4"] = "TP-Link Router",
        ["B0:BE:76"] = "TP-Link Router",
        ["F8:D1:11"] = "TP-Link (smart home)",
        ["14:CC:20"] = "TP-Link Router",

        // Netgear & ASUS
        ["A0:63:91"] = "Netgear Router",
        ["20:E5:2A"] = "Netgear Router",
        ["C4:04:15"] = "Netgear Router",
        ["F8:32:E4"] = "ASUS Router",
        ["2C:4D:54"] = "ASUS Router",

        // Xiaomi / Mijia
        ["28:6C:07"] = "Xiaomi (smart home device)",
        ["64:9E:F3"] = "Xiaomi (smart home device)",
        ["F4:F5:24"] = "Xiaomi (smart home device)",
        ["34:CE:00"] = "Xiaomi (smart home device)",

        // Realtek
        ["00:E0:4C"] = "Realtek Semiconductor (router/IoT)",

        // Ring / Amazon
        ["F0:81:73"] = "Ring / Amazon (doorbell/camera)",
        ["68:37:E9"] = "Amazon (Echo/FireTV)",
        ["FC:A6:67"] = "Amazon (Echo/FireTV)",

        // Google / Nest
        ["48:D6:D5"] = "Google (Nest/Chromecast)",
        ["F4:F5:D8"] = "Google (Nest/Chromecast)",

        // Apple & Samsung
        ["F8:FF:C2"] = "Apple (iPhone/iPad/Mac)",
        ["9C:8D:7C"] = "Apple (iPhone/iPad)",
        ["8C:79:F5"] = "Samsung (phone/TV)",
        ["5C:49:79"] = "Samsung SmartTV",

        // LG & Sony & Nintendo
        ["48:59:29"] = "LG Electronics (TV/appliance)",
        ["7C:B2:7D"] = "Sony (TV/PlayStation)",
        ["00:22:D7"] = "Nintendo (Switch/Wii)",
        ["E8:5B:5B"] = "Nintendo Clone (SUSPICIOUS)",

        // Cameras (Hikvision, Dahua, Reolink)
        ["E4:24:6C"] = "Hikvision IP Camera",
        ["A4:14:37"] = "Hikvision IP Camera",
        ["C4:2F:90"] = "Hikvision IP Camera",
        ["44:19:B6"] = "Hikvision IP Camera",
        ["E0:50:8B"] = "Dahua IP Camera",
        ["10:12:FB"] = "Dahua IP Camera",
        ["EC:71:DB"] = "Reolink Camera",

        // Network hardware
        ["F0:9F:C2"] = "Ubiquiti (network device)",
        ["78:8A:20"] = "Ubiquiti (network device)",
        ["CC:2D:E0"] = "MikroTik Router",
        ["B8:69:F4"] = "MikroTik Router",
        ["00:0F:23"] = "Cisco (networking)",
        ["00:17:94"] = "Cisco (networking)",

        // SBCs & Microcontrollers
        ["B8:27:EB"] = "Raspberry Pi Foundation",
        ["DC:A6:32"] = "Raspberry Pi 4",
        ["E4:5F:01"] = "Raspberry Pi",
        ["98:D3:31"] = "Arduino / HiLetgo (microcontroller)",
        ["00:12:1C"] = "TVT Digital (IP camera)"
    };

    private static readonly Dictionary<int, string> ServicePortHints = new()
    {
        [23] = "Telnet open (legacy management)",
        [80] = "HTTP web admin interface",
        [443] = "HTTPS secure web interface",
        [8080] = "HTTP alternate admin",
        [8443] = "HTTPS alternate admin",
        [554] = "RTSP video stream (camera)",
        [8554] = "RTSP alternate stream",
        [1883] = "MQTT IoT broker",
        [8883] = "MQTT over TLS",
        [502] = "Modbus (industrial IoT)",
        [37777] = "Dahua DVR remote access"
    };

    private static readonly Dictionary<int, string> BotnetPortHints = new()
    {
        [9999] = "Mozi botnet DHT C2 active",
        [5555] = "Kimwolf/botnet ADB exploitation exposed",
        [4444] = "Metasploit / RAT staging port open",
        [2323] = "Mirai Telnet spreader alternate active",
        [7547] = "TR-069 exposure (Mirai exploitation vector)",
        [37215] = "Huawei HG532 RCE (Mirai)",
        [52869] = "UPnP injection vector (Mirai)",
        [65116] = "Realtek RCE variant (Mozi)"
    };

    private static readonly int[] FastProbePorts = [23, 80, 443, 554, 1883, 2323, 5555, 7547, 8080, 9999];

    /// <summary>
    /// Enumerates local subnet devices by inspecting the native Windows ARP table directly via iphlpapi.
    /// </summary>
    public IoTSnapshot ScanLocalNetwork()
    {
        var rawEntries = ReadArpTableEntries();
        var devices = new List<IoTDevice>();
        var findings = new List<string>();

        foreach (var (ip, mac) in rawEntries)
        {
            var vendor = ResolveVendor(mac);
            var category = CategorizeDevice(vendor, []);
            
            // Build basic record for discovered ARP entry
            var dev = new IoTDevice(
                IpAddress: ip,
                MacAddress: mac,
                HostName: ResolveHostNameSafe(ip),
                Vendor: vendor,
                DeviceCategory: category,
                OpenPorts: [],
                IdentifiedServices: [],
                BotnetIndicators: [],
                ThreatLevel: "CLEAN",
                RiskScore: 0,
                IsSuspicious: false,
                DiscoveredAtUtc: DateTimeOffset.UtcNow);

            devices.Add(dev);
        }

        // Aggregate summary metrics
        var highRisk = devices.Count(d => d.ThreatLevel is "HIGH" or "CRITICAL");
        var botnets = devices.Count(d => d.BotnetIndicators.Count > 0);
        var smartHome = devices.Count(d => d.DeviceCategory.Contains("Smart Home"));
        var cameras = devices.Count(d => d.DeviceCategory.Contains("Camera"));

        if (devices.Count == 0)
        {
            findings.Add("No active devices found in local ARP cache.");
        }
        else
        {
            findings.Add($"Discovered {devices.Count} device(s) on local subnet.");
            if (botnets > 0) findings.Add($"ALERT: Detected {botnets} device(s) exhibiting botnet indicators.");
        }

        var summary = new IoTSummary(
            TotalDevices: devices.Count,
            HighRiskDevices: highRisk,
            BotnetThreats: botnets,
            SmartHomeDevices: smartHome,
            Cameras: cameras,
            ScanCompletedAtUtc: DateTimeOffset.UtcNow,
            ScanFindings: findings);

        return new IoTSnapshot(DateTimeOffset.UtcNow, summary, devices);
    }

    /// <summary>
    /// Probes a specific discovered device's common IoT and botnet ports safely with explicit timeouts.
    /// </summary>
    public async Task<IoTDevice> ProbeDeviceAsync(IoTDevice device, CancellationToken token = default)
    {
        var openPorts = new List<int>();
        var services = new List<string>();
        var botnetFlags = new List<string>();
        int score = 0;

        foreach (var port in FastProbePorts)
        {
            if (token.IsCancellationRequested) break;

            var isOpen = await ProbePortAsync(device.IpAddress, port, token).ConfigureAwait(false);
            if (isOpen)
            {
                openPorts.Add(port);
                if (ServicePortHints.TryGetValue(port, out var service))
                {
                    services.Add(service);
                }

                if (BotnetPortHints.TryGetValue(port, out var botnet))
                {
                    botnetFlags.Add(botnet);
                    score += port == 9999 || port == 4444 ? 75 : 45;
                }
                else if (port == 23)
                {
                    botnetFlags.Add("Open unencrypted Telnet: Mirai brute-force vector");
                    score += 35;
                }
            }
        }

        // Camera specific heuristic
        if (openPorts.Contains(554) || openPorts.Contains(8554))
        {
            if (!services.Contains("RTSP video stream (camera)"))
            {
                services.Add("RTSP video stream (camera)");
            }
        }

        var category = CategorizeDevice(device.Vendor, openPorts);
        score = Math.Min(100, score);
        var threatLevel = score >= 70 ? "CRITICAL" : score >= 40 ? "HIGH" : score >= 20 ? "MEDIUM" : score > 0 ? "LOW" : "CLEAN";

        return device with
        {
            OpenPorts = openPorts,
            IdentifiedServices = services,
            BotnetIndicators = botnetFlags,
            DeviceCategory = category,
            RiskScore = score,
            ThreatLevel = threatLevel,
            IsSuspicious = score >= 40
        };
    }

    /// <summary>
    /// Resolves hardware manufacturer from a MAC address string using embedded OUI database.
    /// </summary>
    public static string ResolveVendor(string macAddress)
    {
        if (string.IsNullOrWhiteSpace(macAddress) || macAddress.Length < 8)
        {
            return "Unknown Device";
        }

        var clean = macAddress.Replace("-", ":").ToUpperInvariant();
        var prefix = clean.Length >= 8 ? clean[..8] : clean;

        if (OuiMap.TryGetValue(prefix, out var vendor))
        {
            return vendor;
        }

        return "Unknown Manufacturer";
    }

    /// <summary>
    /// Classifies an IoT device category from its vendor name and discovered open ports.
    /// </summary>
    public static string CategorizeDevice(string vendor, IReadOnlyList<int> openPorts)
    {
        var vLower = vendor.ToLowerInvariant();

        if (vLower.Contains("camera") || vLower.Contains("dvr") || vLower.Contains("hikvision") ||
            vLower.Contains("dahua") || vLower.Contains("reolink") || openPorts.Contains(554) || openPorts.Contains(8554))
        {
            return "IP Camera / Surveillance";
        }

        if (vLower.Contains("espressif") || vLower.Contains("tuya") || vLower.Contains("smart") ||
            vLower.Contains("xiaomi") || openPorts.Contains(1883) || openPorts.Contains(8883))
        {
            return "Smart Home / IoT Controller";
        }

        if (vLower.Contains("router") || vLower.Contains("tp-link") || vLower.Contains("netgear") ||
            vLower.Contains("asus") || vLower.Contains("ubiquiti") || vLower.Contains("mikrotik") || vLower.Contains("cisco"))
        {
            return "Router / Network Infrastructure";
        }

        if (vLower.Contains("raspberry") || vLower.Contains("arduino"))
        {
            return "Embedded Single-Board Computer";
        }

        if (vLower.Contains("apple") || vLower.Contains("samsung") || vLower.Contains("google"))
        {
            return "Mobile / Smart Device";
        }

        return "Network Device";
    }

    /// <summary>
    /// Generates a comprehensive markdown report of discovered IoT devices and threat indicators.
    /// </summary>
    public static string GenerateReport(IoTSnapshot snapshot)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Downpour IoT Subnet Security Audit Report");
        sb.AppendLine($"Generated: {snapshot.CapturedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine();
        sb.AppendLine("## Subnet Summary");
        sb.AppendLine($"- **Total Devices Discovered**: {snapshot.Summary.TotalDevices}");
        sb.AppendLine($"- **Botnet Threats Detected**: {snapshot.Summary.BotnetThreats}");
        sb.AppendLine($"- **High / Critical Risk Devices**: {snapshot.Summary.HighRiskDevices}");
        sb.AppendLine($"- **Smart Home / Microcontrollers**: {snapshot.Summary.SmartHomeDevices}");
        sb.AppendLine($"- **Surveillance Cameras**: {snapshot.Summary.Cameras}");
        sb.AppendLine();

        sb.AppendLine("## Findings");
        foreach (var finding in snapshot.Summary.ScanFindings)
        {
            sb.AppendLine($"- {finding}");
        }
        sb.AppendLine();

        sb.AppendLine("## Discovered Devices");
        foreach (var dev in snapshot.Devices)
        {
            sb.AppendLine($"### {dev.IpAddress} ({dev.Vendor})");
            sb.AppendLine($"- **MAC**: {dev.MacAddress} | **Host**: {dev.HostName}");
            sb.AppendLine($"- **Category**: {dev.DeviceCategory}");
            sb.AppendLine($"- **Threat Level**: {dev.ThreatLevel} (Risk Score: {dev.RiskScore}/100)");

            if (dev.BotnetIndicators.Count > 0)
            {
                sb.AppendLine("- **Botnet Indicators**:");
                foreach (var b in dev.BotnetIndicators)
                {
                    sb.AppendLine($"  - [ALERT] {b}");
                }
            }

            if (dev.OpenPorts.Count > 0)
            {
                sb.AppendLine($"- **Open Ports**: {string.Join(", ", dev.OpenPorts)}");
                sb.AppendLine($"- **Services**: {string.Join("; ", dev.IdentifiedServices)}");
            }

            sb.AppendLine();
        }

        sb.AppendLine("---");
        sb.AppendLine("Downpour Next Native Security Platform | Read-Only IoT Subnet Inspector");
        return sb.ToString();
    }

    private static async Task<bool> ProbePortAsync(string ip, int port, CancellationToken token)
    {
        try
        {
            using var client = new TcpClient();
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeoutCts.CancelAfter(TimeSpan.FromMilliseconds(400));

            await client.ConnectAsync(ip, port, timeoutCts.Token).ConfigureAwait(false);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string ResolveHostNameSafe(string ip)
    {
        return ip;
    }

    private static List<(string Ip, string Mac)> ReadArpTableEntries()
    {
        var list = new List<(string, string)>();
        int bytesNeeded = 0;

        // Query buffer size needed
        GetIpNetTable(IntPtr.Zero, ref bytesNeeded, false);
        if (bytesNeeded <= 0) return list;

        IntPtr buffer = Marshal.AllocHGlobal(bytesNeeded);
        try
        {
            int result = GetIpNetTable(buffer, ref bytesNeeded, false);
            if (result == 0)
            {
                int numEntries = Marshal.ReadInt32(buffer);
                IntPtr current = IntPtr.Add(buffer, 4);

                for (int i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_IPNETROW>(current);
                    // Filter: Dynamic (3) or Static (4), valid IPv4 length, non-zero MAC
                    if (row.dwType is 3 or 4 && row.dwPhysAddrLen >= 6)
                    {
                        var ipBytes = BitConverter.GetBytes(row.dwAddr);
                        var ip = new IPAddress(ipBytes).ToString();

                        // Avoid broadcast, multicast, or loopback
                        if (!ip.StartsWith("127.") && !ip.StartsWith("224.") && !ip.EndsWith(".255"))
                        {
                            var mac = string.Join(":", row.bPhysAddr.Take(6).Select(b => b.ToString("X2")));
                            if (mac != "00:00:00:00:00:00" && mac != "FF:FF:FF:FF:FF:FF")
                            {
                                list.Add((ip, mac));
                            }
                        }
                    }

                    current = IntPtr.Add(current, Marshal.SizeOf<MIB_IPNETROW>());
                }
            }
        }
        catch
        {
            // Fallback for non-Windows or restricted environments
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return list;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_IPNETROW
    {
        public int dwIndex;
        public int dwPhysAddrLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] bPhysAddr;
        public int dwAddr;
        public int dwType;
    }
}
