using System.Text.RegularExpressions;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>Where a driver should come from: an official maker page (fixed, verified URL) and why.</summary>
public sealed record DriverSource(string Name, string Url, string Why, bool IsPcMaker);

public sealed record HardwareIdParts(string Bus, string? VendorId, string? DeviceId);

/// <summary>A third-party driver worth checking on the maker's site, with where to get it.</summary>
public sealed record DriverCheck(DeviceEntry Device, int? AgeYears, string Reason, IReadOnlyList<DriverSource> Sources, int DeviceCount = 1, string? Label = null);

/// <summary>
/// Not every driver comes through Windows Update: graphics, chipset, audio, peripheral and laptop-specific drivers are
/// often published only by the chip or PC maker. This reads the chip maker from the hardware ID (PCI VEN_, USB VID_,
/// HD Audio VEN_), knows the official driver page for makers that publish their own drivers, and otherwise points to
/// the PC or motherboard maker's support page (Realtek, Qualcomm, MediaTek and others ship drivers through them).
/// Every URL is fixed and was checked to resolve to the maker's own site; Downpour never downloads or runs installers.
/// </summary>
public static partial class DriverSourceAdvisor
{
    public static readonly TimeSpan GraphicsDriverStale = TimeSpan.FromDays(180);
    public const int ThirdPartyStaleYears = 3;

    private static readonly DriverSource Nvidia = new("NVIDIA", "https://www.nvidia.com/en-us/drivers/", "NVIDIA publishes GeForce and RTX drivers itself, usually newer than Windows Update.", false);
    private static readonly DriverSource Amd = new("AMD", "https://www.amd.com/en/support/download/drivers.html", "AMD publishes Radeon graphics and Ryzen chipset drivers itself.", false);
    private static readonly DriverSource Intel = new("Intel Driver & Support Assistant", "https://www.intel.com/content/www/us/en/support/detect.html", "Intel's own tool finds the right graphics, Wi-Fi, Bluetooth and chipset drivers.", false);

    /// <summary>PCI / HD Audio vendor IDs (PCI-SIG) and USB vendor IDs (USB-IF) for makers with their own driver pages.</summary>
    private static readonly Dictionary<string, (string Maker, DriverSource? Source)> PciVendors = new(StringComparer.OrdinalIgnoreCase)
    {
        ["10DE"] = ("NVIDIA", Nvidia),
        ["1002"] = ("AMD", Amd),
        ["1022"] = ("AMD", Amd),
        ["8086"] = ("Intel", Intel),
        ["8087"] = ("Intel", Intel),
        ["10EC"] = ("Realtek", null),
        ["14E4"] = ("Broadcom", null),
        ["168C"] = ("Qualcomm Atheros", null),
        ["17CB"] = ("Qualcomm", null),
        ["1969"] = ("Qualcomm Atheros (Killer)", null),
        ["14C3"] = ("MediaTek", null),
        ["1B21"] = ("ASMedia", null),
        ["1912"] = ("Renesas", null),
        ["144D"] = ("Samsung", new DriverSource("Samsung", "https://semiconductor.samsung.com/consumer-storage/support/tools/", "Samsung publishes SSD drivers and Magician itself.", false)),
        ["1179"] = ("Toshiba / Kioxia", null),
        ["15B7"] = ("Western Digital / SanDisk", null),
        ["1E0F"] = ("Kioxia", null),
        ["126F"] = ("Silicon Motion", null),
        ["1987"] = ("Phison", null),
        ["10B5"] = ("Broadcom (PLX)", null),
    };

    private static readonly Dictionary<string, (string Maker, DriverSource? Source)> UsbVendors = new(StringComparer.OrdinalIgnoreCase)
    {
        ["046D"] = ("Logitech", new DriverSource("Logitech", "https://www.logitech.com/en-us/software.html", "Logitech's own software adds features Windows' generic driver lacks.", false)),
        ["1532"] = ("Razer", new DriverSource("Razer Synapse", "https://www.razer.com/synapse-4", "Razer's own software configures and updates Razer devices.", false)),
        ["1B1C"] = ("Corsair", new DriverSource("Corsair", "https://www.corsair.com/us/en/s/downloads", "Corsair publishes iCUE and device firmware itself.", false)),
        ["0FD9"] = ("Elgato", new DriverSource("Elgato", "https://www.elgato.com/us/en/s/downloads", "Elgato publishes capture and Stream Deck software itself.", false)),
        ["1038"] = ("SteelSeries", new DriverSource("SteelSeries GG", "https://steelseries.com/gg", "SteelSeries publishes GG and device firmware itself.", false)),
        ["041E"] = ("Creative", new DriverSource("Creative", "https://support.creative.com/", "Creative publishes Sound Blaster drivers itself.", false)),
        ["1235"] = ("Focusrite", new DriverSource("Focusrite", "https://downloads.focusrite.com/", "Focusrite publishes audio-interface drivers itself; Windows' generic USB audio has higher latency.", false)),
        ["8087"] = ("Intel", Intel),
        ["8086"] = ("Intel", Intel),
        ["0BDA"] = ("Realtek", null),
        ["0CF3"] = ("Qualcomm Atheros", null),
        ["0E8D"] = ("MediaTek", null),
        ["13D3"] = ("AzureWave", null),
        ["0A5C"] = ("Broadcom", null),
        ["045E"] = ("Microsoft", null),
        ["054C"] = ("Sony", null),
        ["057E"] = ("Nintendo", null),
        ["28DE"] = ("Valve", null),
        ["0951"] = ("Kingston / HyperX", null),
        ["03F0"] = ("HP", null),
    };

    /// <summary>PC and motherboard makers' driver and support pages.</summary>
    private static readonly (string Match, DriverSource Source)[] Makers =
    [
        ("alienware", new DriverSource("Dell support", "https://www.dell.com/support/home/", "Dell publishes the drivers built for your exact model.", true)),
        ("dell", new DriverSource("Dell support", "https://www.dell.com/support/home/", "Dell publishes the drivers built for your exact model.", true)),
        ("hewlett", new DriverSource("HP drivers", "https://support.hp.com/us-en/drivers", "HP publishes the drivers built for your exact model.", true)),
        ("hp", new DriverSource("HP drivers", "https://support.hp.com/us-en/drivers", "HP publishes the drivers built for your exact model.", true)),
        ("lenovo", new DriverSource("Lenovo support", "https://pcsupport.lenovo.com/", "Lenovo publishes the drivers built for your exact model.", true)),
        ("asus", new DriverSource("ASUS download center", "https://www.asus.com/support/download-center/", "ASUS publishes chipset, audio, LAN and Wi-Fi drivers for your board or laptop.", true)),
        ("micro-star", new DriverSource("MSI downloads", "https://www.msi.com/support/download", "MSI publishes chipset, audio, LAN and Wi-Fi drivers for your board or laptop.", true)),
        ("msi", new DriverSource("MSI downloads", "https://www.msi.com/support/download", "MSI publishes chipset, audio, LAN and Wi-Fi drivers for your board or laptop.", true)),
        ("gigabyte", new DriverSource("GIGABYTE support", "https://www.gigabyte.com/Support", "GIGABYTE publishes chipset, audio, LAN and Wi-Fi drivers for your board or laptop.", true)),
        ("asrock", new DriverSource("ASRock support", "https://www.asrock.com/support/index.asp", "ASRock publishes chipset, audio, LAN and Wi-Fi drivers for your board.", true)),
        ("acer", new DriverSource("Acer drivers", "https://www.acer.com/us-en/support/drivers-and-manuals", "Acer publishes the drivers built for your exact model.", true)),
        ("razer", new DriverSource("Razer support", "https://mysupport.razer.com/", "Razer publishes the drivers built for your laptop.", true)),
        ("microsoft", new DriverSource("Surface drivers and firmware", "https://support.microsoft.com/en-us/surface/drivers-firmware/download-drivers-and-firmware-for-surface", "Microsoft publishes Surface driver and firmware packs.", true)),
    ];

    /// <summary>Official maker update apps worth suggesting when installed (matched on installed program names).</summary>
    public static readonly (string Match, string Tool)[] KnownTools =
    [
        ("NVIDIA App", "NVIDIA App"), ("GeForce Experience", "NVIDIA GeForce Experience"), ("AMD Software", "AMD Software: Adrenalin"),
        ("Driver & Support Assistant", "Intel Driver & Support Assistant"), ("Dell Command | Update", "Dell Command Update"), ("SupportAssist", "Dell SupportAssist"),
        ("Lenovo Vantage", "Lenovo Vantage"), ("Lenovo System Update", "Lenovo System Update"), ("HP Support Assistant", "HP Support Assistant"),
        ("MyASUS", "MyASUS"), ("Armoury Crate", "ASUS Armoury Crate"), ("MSI Center", "MSI Center"), ("GIGABYTE Control Center", "GIGABYTE Control Center"),
        ("Logi Options", "Logi Options+"), ("G HUB", "Logitech G HUB"), ("iCUE", "Corsair iCUE"), ("Razer Synapse", "Razer Synapse"),
        ("SteelSeries GG", "SteelSeries GG"), ("Samsung Magician", "Samsung Magician"),
    ];

    public static HardwareIdParts Parse(string? hardwareId)
    {
        if (string.IsNullOrWhiteSpace(hardwareId)) return new HardwareIdParts("", null, null);
        var bus = hardwareId.Split('\\', 2)[0].ToUpperInvariant();
        var vendor = VendorPattern().Match(hardwareId) is { Success: true } v ? v.Groups[2].Value.ToUpperInvariant() : null;
        var device = DevicePattern().Match(hardwareId) is { Success: true } d ? d.Groups[2].Value.ToUpperInvariant() : null;
        return new HardwareIdParts(bus, vendor, device);
    }

    /// <summary>The chip maker named by the hardware ID, with its own driver page when it has one.</summary>
    public static (string Maker, DriverSource? Source)? ChipMaker(DeviceEntry device)
    {
        var parts = Parse(device.HardwareId ?? device.InstanceId);
        if (parts.VendorId is null) return null;
        var table = parts.Bus is "USB" or "HID" ? UsbVendors : PciVendors;
        return table.TryGetValue(parts.VendorId, out var maker) ? maker : null;
    }

    public static DriverSource? MakerSource(string? manufacturer)
    {
        if (string.IsNullOrWhiteSpace(manufacturer) || manufacturer.Contains("To Be Filled", StringComparison.OrdinalIgnoreCase)
            || manufacturer.Contains("System manufacturer", StringComparison.OrdinalIgnoreCase)) return null;
        var lower = manufacturer.ToLowerInvariant();
        foreach (var (match, source) in Makers)
        {
            if (match == "hp" ? Regex.IsMatch(lower, @"\bhp\b") : match == "msi" ? Regex.IsMatch(lower, @"\bmsi\b") : lower.Contains(match)) return source;
        }
        return null;
    }

    /// <summary>
    /// Official places to get this device's driver, best first: the chip maker's own page when it publishes drivers,
    /// then the PC maker (laptops and branded PCs) or the motherboard maker (self-built desktops).
    /// </summary>
    public static IReadOnlyList<DriverSource> SourcesFor(DeviceEntry device, string? systemMaker, string? boardMaker)
    {
        var sources = new List<DriverSource>();
        if (ChipMaker(device) is { Source: { } chip }) sources.Add(chip);
        var pc = MakerSource(systemMaker) ?? MakerSource(boardMaker);
        if (pc is not null && sources.All(s => s.Url != pc.Url)) sources.Add(pc);
        var board = MakerSource(boardMaker);
        if (board is not null && sources.All(s => s.Url != board.Url)) sources.Add(board);
        return sources;
    }

    public static IReadOnlyList<string> MatchTools(IEnumerable<string> installedPrograms)
    {
        var names = installedPrograms.ToArray();
        return KnownTools.Where(t => names.Any(n => n.Contains(t.Match, StringComparison.OrdinalIgnoreCase))).Select(t => t.Tool).Distinct().ToArray();
    }

    /// <summary>
    /// Third-party drivers worth checking with the maker: graphics drivers older than six months (they update monthly
    /// for games and security) and other non-Microsoft drivers older than three years. Problem devices are listed
    /// separately.
    /// </summary>
    /// <summary>Device classes whose drivers makers actually update (ports, HID, software components and the like rarely change).</summary>
    private static readonly Dictionary<string, string> CheckedClasses = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Display"] = "graphics", ["Net"] = "network", ["Bluetooth"] = "Bluetooth", ["MEDIA"] = "audio", ["System"] = "chipset",
        ["HDC"] = "storage controller", ["SCSIAdapter"] = "storage controller", ["USB"] = "USB controller", ["Camera"] = "camera", ["Image"] = "camera",
    };

    public static IReadOnlyList<DriverCheck> Checks(IEnumerable<DeviceEntry> devices, string? systemMaker, string? boardMaker, DateTimeOffset now)
    {
        var single = SingleChecks(devices, systemMaker, boardMaker, now);
        // One package often drives many devices (chipset, multi-port network cards): show it once with a count.
        return single
            .GroupBy(c => (Provider: c.Device.DriverProvider!.ToUpperInvariant(), c.Device.Class.ToUpperInvariant(), c.Device.DriverVersion))
            .Select(g =>
            {
                var first = g.First();
                var count = g.Select(c => c.Device.InstanceId).Distinct().Count();
                var kind = CheckedClasses.GetValueOrDefault(first.Device.Class, "driver");
                return first with
                {
                    DeviceCount = count,
                    Label = count == 1 ? first.Device.Name : $"{first.Device.DriverProvider} {kind} drivers ({count} devices)",
                };
            })
            .OrderByDescending(c => c.Device.Class.Equals("Display", StringComparison.OrdinalIgnoreCase)).ThenByDescending(c => c.AgeYears)
            .Take(30)
            .ToArray();
    }

    private static List<DriverCheck> SingleChecks(IEnumerable<DeviceEntry> devices, string? systemMaker, string? boardMaker, DateTimeOffset now)
    {
        var checks = new List<DriverCheck>();
        foreach (var d in devices.Where(d => d.Present && d.ProblemCode == 0 && CheckedClasses.ContainsKey(d.Class)
                     && d.DriverProvider is { } p && !p.Equals("Microsoft", StringComparison.OrdinalIgnoreCase)))
        {
            if (d.DriverDate is not { } date || date.Year < 1995) continue;
            var age = now - date;
            var graphics = d.Class.Equals("Display", StringComparison.OrdinalIgnoreCase);
            string? reason = graphics && age > GraphicsDriverStale
                ? $"Graphics driver is {age.TotalDays / 30.4:0} months old; GPU makers release updates for new games and security fixes."
                : !graphics && age.TotalDays / 365.25 >= ThirdPartyStaleYears
                    ? $"Driver is {age.TotalDays / 365.25:0} years old; the maker may have a newer version."
                    : null;
            if (reason is null) continue;
            var sources = SourcesFor(d, systemMaker, boardMaker);
            if (sources.Count == 0) continue;
            checks.Add(new DriverCheck(d, DeviceAnalyzer.AgeYears(d, now), reason, sources));
        }
        return checks;
    }

    [GeneratedRegex(@"(VEN|VID)_([0-9A-F]{4})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex VendorPattern();

    [GeneratedRegex(@"(DEV|PID)_([0-9A-F]{4})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DevicePattern();
}
