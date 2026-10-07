using System.Diagnostics;
using System.IO.Pipes;
using Downpour.Core;
using Downpour.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace Downpour.Tests;

/// <summary>
/// Desktop client -> named pipe -> handler -> reply, for the action endpoints. Only previews are sent: they change
/// nothing, but they exercise the strict request parser, caller check, consent minting, and reply serialization.
/// </summary>
public sealed class ActionPipeEndToEndTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "downpour_action_e2e_" + Guid.NewGuid().ToString("N"));
    private readonly SensorSettingsStore _settings;
    private readonly ActionAuditLog _audit;

    public ActionPipeEndToEndTests()
    {
        Directory.CreateDirectory(_folder);
        _settings = new SensorSettingsStore(Path.Combine(_folder, "settings.json"));
        _audit = new ActionAuditLog(Path.Combine(_folder, "audit.jsonl"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_folder, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private sealed class AllowCaller : IActionCallerVerifier
    {
        public string? Verify(NamedPipeServerStream pipe) => null;
    }

    private static string Pipe(string name) => $"Downpour.Test.{name}.{Guid.NewGuid():N}";

    [Fact]
    public async Task ProcessTerminationPreviewRoundTrips()
    {
        var name = Pipe("Terminate");
        var handler = new ProcessTerminationActionHandler(new ProcessTerminationExecutor(), _settings, new ActionConsentStore(), _audit);
        using var worker = new ProcessTerminationActionPipeWorker(handler, new AllowCaller(), NullLogger<ProcessTerminationActionPipeWorker>.Instance, name);
        await worker.StartAsync(CancellationToken.None);
        using var target = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/c ping -n 30 127.0.0.1")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
        })!;
        try
        {
            var response = await new ProcessTerminationClient(name).PreviewTerminateAsync(target.Id, target.StartTime.ToUniversalTime());
            Assert.NotNull(response);
            Assert.True(response!.Accepted, response.Message);
            Assert.NotNull(response.Preview?.ConsentToken);
            Assert.False(target.HasExited); // a preview never ends anything
        }
        finally
        {
            target.Kill(entireProcessTree: true);
            await worker.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task FirewallPreviewRoundTrips()
    {
        var name = Pipe("Firewall");
        var executor = new FirewallActionExecutor(new InMemoryFirewallPolicyBackend());
        var handler = new FirewallActionHandler(executor, _settings, new ActionConsentStore(), _audit);
        using var worker = new FirewallActionPipeWorker(handler, executor, new AllowCaller(), NullLogger<FirewallActionPipeWorker>.Instance, name);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            var response = await new FirewallActionClient(name).PreviewBlockIpAsync("198.51.100.42", 60, "test");
            Assert.NotNull(response);
            Assert.True(response!.Accepted, response.Message);
            Assert.NotNull(response.Preview?.ConsentToken);
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task UsbPreviewRoundTrips()
    {
        var name = Pipe("Usb");
        var backend = new InMemoryUsbDeviceBackend();
        backend.AddDevice(@"USBSTOR\Disk&Ven_Test&Prod_Drive\1");
        var executor = new UsbActionExecutor(backend, Path.Combine(_folder, "usb.json"));
        var handler = new UsbActionHandler(executor, _settings, new ActionConsentStore(), _audit);
        using var worker = new UsbActionPipeWorker(handler, new AllowCaller(), NullLogger<UsbActionPipeWorker>.Instance, name);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            var response = await new UsbActionClient(name).PreviewBlockDeviceAsync(@"USBSTOR\Disk&Ven_Test&Prod_Drive\1", "Test drive");
            Assert.NotNull(response);
            Assert.True(response!.Accepted, response.Message);
            Assert.NotNull(response.Preview?.ConsentToken);
            Assert.False(backend.IsDeviceDisabled(@"USBSTOR\Disk&Ven_Test&Prod_Drive\1"));
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
        }
    }
}
