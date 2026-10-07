using Downpour.Core;
using Downpour.Service;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;

namespace Downpour.Tests;

/// <summary>
/// Real provider -> named pipe -> desktop client -> validation, for every read-only endpoint that lacked an end-to-end
/// test. Unit tests on hand-built snapshots cannot catch a framing or contract mismatch between the two sides (the DNS,
/// USB, and Wi-Fi pages were silently "offline" for that reason).
/// </summary>
public sealed class InventoryPipeEndToEndTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "downpour_e2e_" + Guid.NewGuid().ToString("N"));

    public InventoryPipeEndToEndTests() => Directory.CreateDirectory(_folder);

    public void Dispose()
    {
        try { Directory.Delete(_folder, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private static string Pipe(string name) => $"Downpour.Test.{name}.{Guid.NewGuid():N}";

    private static async Task<T?> WithWorker<T>(BackgroundService worker, Func<Task<T?>> call)
    {
        await worker.StartAsync(CancellationToken.None);
        try
        {
            // Some providers do real work on the first request; allow one retry before failing.
            var result = await call();
            if (result is null) { await Task.Delay(500); result = await call(); }
            return result;
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
            worker.Dispose();
        }
    }

    [Fact]
    public async Task Firewall()
    {
        var name = Pipe("Firewall");
        Assert.NotNull(await WithWorker(new FirewallInventoryPipeWorker(new FirewallInventoryProvider(new WindowsServiceInventoryProvider()), NullLogger<FirewallInventoryPipeWorker>.Instance, name),
            () => new FirewallInventoryClient(name).TryGetSnapshotAsync()));
    }

    [Fact]
    public async Task Hardening()
    {
        var name = Pipe("Hardening");
        Assert.NotNull(await WithWorker(new HardeningPosturePipeWorker(new HardeningPostureProvider(), NullLogger<HardeningPosturePipeWorker>.Instance, name),
            () => new HardeningPostureClient(name).TryGetSnapshotAsync()));
    }

    [Fact]
    public async Task Persistence()
    {
        var name = Pipe("Persistence");
        var provider = new PersistenceInventoryProvider(Path.Combine(_folder, "persistence-baseline.json"));
        Assert.NotNull(await WithWorker(new PersistenceInventoryPipeWorker(provider, NullLogger<PersistenceInventoryPipeWorker>.Instance, name),
            () => new PersistenceInventoryClient(name).TryGetSnapshotAsync()));
    }

    [Fact]
    public async Task RemoteAccess()
    {
        var name = Pipe("Remote");
        Assert.NotNull(await WithWorker(new RemoteAccessPipeWorker(new RemoteAccessProvider(), NullLogger<RemoteAccessPipeWorker>.Instance, name),
            () => new RemoteAccessClient(name).TryGetSnapshotAsync()));
    }

    [Fact]
    public async Task DriverPackages()
    {
        var name = Pipe("DriverPackages");
        Assert.NotNull(await WithWorker(new DriverPackageInventoryPipeWorker(new DriverPackageInventoryProvider(), NullLogger<DriverPackageInventoryPipeWorker>.Instance, name),
            () => new DriverPackageInventoryClient(name).TryGetSnapshotAsync()));
    }

    [Fact]
    public async Task IntelAndSensorSettings()
    {
        var settings = new SensorSettingsStore(Path.Combine(_folder, "settings.json"));
        var keys = new IntelKeyStore(Path.Combine(_folder, "keys.json"));
        var results = new IntelResultStore(Path.Combine(_folder, "intel.json"));

        var intelName = Pipe("Intel");
        Assert.NotNull(await WithWorker(new IntelPipeWorker(settings, keys, results, NullLogger<IntelPipeWorker>.Instance, intelName),
            () => new IntelClient(intelName).TryGetSnapshotAsync()));

        var settingsName = Pipe("Settings");
        var response = await WithWorker(new SensorSettingsPipeWorker(settings, keys, NullLogger<SensorSettingsPipeWorker>.Instance, settingsName),
            () => new SensorSettingsClient(settingsName).GetAsync());
        Assert.NotNull(response);
        Assert.True(response!.Accepted);
        Assert.NotNull(response.Settings);
    }
}
