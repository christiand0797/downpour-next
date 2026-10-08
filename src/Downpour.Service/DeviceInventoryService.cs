using System.Buffers.Binary;
using System.Globalization;
using System.IO.Pipes;
using System.Management;
using System.Runtime.InteropServices;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Service;

/// <summary>
/// Devices &amp; Drivers (owner request): every Plug and Play device with its status, problem code and driver
/// (Win32_PnPEntity joined to Win32_PnPSignedDriver), plus an on-demand search for driver updates through the Windows
/// Update Agent API ("IsInstalled=0 and Type='Driver'"). Read-only: the search downloads and installs nothing; installing,
/// rolling back or uninstalling is handed to Windows' own Optional updates page and Device Manager, which elevate
/// themselves. Served on Downpour.Devices.v1 (length-prefixed JSON, current-user ACL).
/// </summary>
public sealed class DeviceInventoryService(ILogger<DeviceInventoryService> logger, string pipeName = DeviceClient.PipeName,
    InstalledSoftwareInventoryProvider? installed = null) : BackgroundService
{
    private sealed record SystemIdentity(string? Manufacturer, string? Model, string? BoardManufacturer, string? BoardProduct, IReadOnlyList<string> Tools);

    public const int MaximumDevices = 1200;
    public const int MaximumUpdates = 200;
    private static readonly TimeSpan SearchTimeout = TimeSpan.FromMinutes(5);
    private readonly object _gate = new();
    private readonly SnapshotCache<IReadOnlyList<DeviceEntry>> _devices = new(ReadDevices, TimeSpan.FromSeconds(20));
    private SnapshotCache<SystemIdentity>? _identity;
    private IReadOnlyList<DriverUpdateOffer> _updates = [];
    private string _searchState = UpdateSearchStates.NotSearched;
    private DateTimeOffset? _searchedAt;
    private string? _searchError;

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _devices.Warm();
        Identity.Warm();
        return Task.Run(() => ServePipeAsync(stoppingToken), stoppingToken);
    }

    internal async Task<DeviceResponse> HandleAsync(DeviceRequest? request, CancellationToken token)
    {
        if (request is not { SchemaVersion: 1 }) return new DeviceResponse(1, false, "invalid-request", null);
        switch (request.Operation)
        {
            case DeviceOperations.Snapshot:
                return new DeviceResponse(1, true, "snapshot", await SnapshotAsync(token));
            case DeviceOperations.SearchUpdates:
                lock (_gate)
                {
                    if (_searchState == UpdateSearchStates.Searching) return new DeviceResponse(1, false, "already-searching", null);
                    _searchState = UpdateSearchStates.Searching;
                    _searchError = null;
                }
                var thread = new Thread(SearchUpdates) { IsBackground = true, Name = "Downpour driver update search" };
                thread.SetApartmentState(ApartmentState.STA);
                thread.Start();
                return new DeviceResponse(1, true, "search-started", await SnapshotAsync(token));
            default:
                return new DeviceResponse(1, false, "invalid-request", null);
        }
    }

    private async Task<DeviceInventorySnapshot> SnapshotAsync(CancellationToken token)
    {
        var warnings = new List<string>();
        IReadOnlyList<DeviceEntry> devices;
        try { devices = await _devices.GetAsync(token); }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException)
        {
            devices = [];
            warnings.Add($"Windows did not return the device list ({ex.GetType().Name}).");
        }
        SystemIdentity? identity = null;
        try { identity = await Identity.GetAsync(token); }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException or IOException) { }
        lock (_gate)
            return new DeviceInventorySnapshot(1, DateTimeOffset.UtcNow, devices, _updates, _searchState, _searchedAt, _searchError, warnings,
                identity?.Manufacturer, identity?.Model, identity?.BoardManufacturer, identity?.BoardProduct, identity?.Tools);
    }

    /// <summary>Windows Update driver search on an STA thread (the agent's preferred apartment). Never installs.</summary>
    private void SearchUpdates()
    {
        try
        {
            var found = new List<DriverUpdateOffer>();
            var type = Type.GetTypeFromProgID("Microsoft.Update.Session", throwOnError: true)!;
            dynamic session = Activator.CreateInstance(type)!;
            session.ClientApplicationID = "Downpour Next";
            dynamic searcher = session.CreateUpdateSearcher();
            var started = DateTime.UtcNow;
            dynamic result = searcher.Search("IsInstalled=0 and Type='Driver' and IsHidden=0");
            foreach (dynamic update in result.Updates)
            {
                if (found.Count >= MaximumUpdates || DateTime.UtcNow - started > SearchTimeout) break;
                DateTimeOffset? date = Try(() => (object?)update.DriverVerDate) is DateTime d ? new DateTimeOffset(DateTime.SpecifyKind(d, DateTimeKind.Utc)) : null;
                long? size = Try(() => (object?)update.MaxDownloadSize) is { } raw ? Convert.ToInt64(raw, CultureInfo.InvariantCulture) : null;
                found.Add(new DriverUpdateOffer(Clean((string?)update.Title, 300) ?? "Driver update", Clean(Try(() => (string?)update.DriverClass), 64),
                    Clean(Try(() => (string?)update.DriverModel), 200), Clean(Try(() => (string?)update.DriverProvider), 128),
                    Clean(Try(() => (string?)update.DriverManufacturer), 128), Clean(Try(() => (string?)update.DriverHardwareID), 256), date, size));
            }
            lock (_gate)
            {
                _updates = found;
                _searchState = UpdateSearchStates.Done;
                _searchedAt = DateTimeOffset.UtcNow;
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Windows Update driver search failed.");
            lock (_gate)
            {
                _searchState = UpdateSearchStates.Failed;
                _searchedAt = DateTimeOffset.UtcNow;
                _searchError = ex is COMException com
                    ? $"Windows Update returned 0x{com.HResult:X8}. Check that the Windows Update service is running and the PC is online."
                    : Clean($"The search failed: {ex.Message}", 300);
            }
        }
    }

    private static T? Try<T>(Func<T?> read)
    {
        try { return read(); }
        catch (Exception) { return default; }
    }

    private SnapshotCache<SystemIdentity> Identity => _identity ??= new SnapshotCache<SystemIdentity>(ReadIdentity, TimeSpan.FromMinutes(10));

    /// <summary>PC and motherboard maker (where model-specific drivers come from) and installed official maker update apps.</summary>
    private SystemIdentity ReadIdentity()
    {
        string? maker = null, model = null, board = null, product = null;
        using (var system = new ManagementObjectSearcher("SELECT Manufacturer, Model FROM Win32_ComputerSystem"))
            foreach (ManagementObject item in system.Get())
                using (item) { maker = Clean(item["Manufacturer"] as string, 128); model = Clean(item["Model"] as string, 128); }
        using (var baseboard = new ManagementObjectSearcher("SELECT Manufacturer, Product FROM Win32_BaseBoard"))
            foreach (ManagementObject item in baseboard.Get())
                using (item) { board = Clean(item["Manufacturer"] as string, 128); product = Clean(item["Product"] as string, 128); }
        IReadOnlyList<string> tools = [];
        try { if (installed is not null) tools = DriverSourceAdvisor.MatchTools(installed.Capture().Software.Select(s => s.Name)); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException) { }
        return new SystemIdentity(maker, model, board, product, tools);
    }

    internal static IReadOnlyList<DeviceEntry> ReadDevices()
    {
        var drivers = new Dictionary<string, (string? Provider, string? Version, DateTimeOffset? Date, string? Inf, bool? Signed, string? Signer)>(StringComparer.OrdinalIgnoreCase);
        using (var searcher = new ManagementObjectSearcher("SELECT DeviceID, DriverProviderName, DriverVersion, DriverDate, InfName, IsSigned, Signer FROM Win32_PnPSignedDriver"))
        {
            searcher.Options.Timeout = TimeSpan.FromSeconds(30);
            foreach (ManagementObject item in searcher.Get())
            {
                using (item)
                {
                    if (item["DeviceID"] is not string id || drivers.Count >= MaximumDevices * 2) continue;
                    drivers[id] = (Clean(item["DriverProviderName"] as string, 128), Clean(item["DriverVersion"] as string, 64), CimDate(item["DriverDate"] as string),
                        Clean(item["InfName"] as string, 128), item["IsSigned"] as bool?, Clean(item["Signer"] as string, 200));
                }
            }
        }

        var devices = new List<DeviceEntry>();
        using var entities = new ManagementObjectSearcher("SELECT DeviceID, Name, PNPClass, Manufacturer, Status, ConfigManagerErrorCode, Present, HardwareID FROM Win32_PnPEntity");
        entities.Options.Timeout = TimeSpan.FromSeconds(30);
        foreach (ManagementObject item in entities.Get())
        {
            using (item)
            {
                if (item["DeviceID"] is not string id || devices.Count >= MaximumDevices) continue;
                drivers.TryGetValue(id, out var driver);
                var hardware = item["HardwareID"] is string[] { Length: > 0 } ids ? Clean(ids[0], 256) : null;
                devices.Add(new DeviceEntry(Clean(id, 400) ?? "", Clean(item["Name"] as string, 200) ?? "Unknown device", Clean(item["PNPClass"] as string, 64) ?? "Other",
                    Clean(item["Manufacturer"] as string, 128) ?? "", Clean(item["Status"] as string, 32) ?? "Unknown",
                    item["ConfigManagerErrorCode"] is uint code ? (int)Math.Min(code, 999) : 0, item["Present"] as bool? ?? true,
                    driver.Provider, driver.Version, driver.Date, driver.Inf, driver.Signed, driver.Signer, hardware));
            }
        }
        return devices.OrderBy(d => d.Class, StringComparer.OrdinalIgnoreCase).ThenBy(d => d.Name, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    /// <summary>WMI CIM_DATETIME ("20230115000000.000000-000") to a date.</summary>
    internal static DateTimeOffset? CimDate(string? value) =>
        value is { Length: >= 8 } && DateTime.TryParseExact(value[..8], "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var date)
            ? new DateTimeOffset(date, TimeSpan.Zero) : null;

    private static string? Clean(string? value, int max)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var clean = new string(value.Where(c => !char.IsControl(c)).Take(max).ToArray()).Trim();
        return clean.Length == 0 ? null : clean;
    }

    private async Task ServePipeAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var pipe = NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.WriteThrough, 4096, 64 * 1024, PipeSecurityFactory.CreateCurrentUserReadSecurity());
                await pipe.WaitForConnectionAsync(stoppingToken);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(60));
                var lengthBytes = new byte[4];
                await pipe.ReadExactlyAsync(lengthBytes, timeout.Token);
                var length = BinaryPrimitives.ReadInt32LittleEndian(lengthBytes);
                if (length is <= 0 or > 1024) throw new InvalidDataException("The request length is outside its limit.");
                var body = new byte[length];
                await pipe.ReadExactlyAsync(body, timeout.Token);
                DeviceRequest? request;
                try { request = BoundedJson.Deserialize<DeviceRequest>(body); }
                catch (Exception ex) when (ex is Newtonsoft.Json.JsonException or InvalidDataException) { request = null; }
                var response = await HandleAsync(request, timeout.Token);
                var payload = BoundedJson.Serialize(response);
                BinaryPrimitives.WriteInt32LittleEndian(lengthBytes, payload.Length);
                await pipe.WriteAsync(lengthBytes, timeout.Token);
                await pipe.WriteAsync(payload, timeout.Token);
                await pipe.FlushAsync(timeout.Token);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex) when (ex is IOException or InvalidDataException or OperationCanceledException or InvalidOperationException or Newtonsoft.Json.JsonException)
            {
                logger.LogDebug(ex, "A device client disconnected or sent an invalid request.");
            }
        }
    }
}
