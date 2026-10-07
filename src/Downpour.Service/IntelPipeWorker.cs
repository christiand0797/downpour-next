using System.IO.Pipes;
using System.Text.Json;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Service;

/// <summary>Read-only view of intel lookup status, cached results, and the outbound log. Never includes API keys.</summary>
public sealed class IntelPipeWorker(
    SensorSettingsStore settings,
    IntelKeyStore keys,
    IntelResultStore store,
    ILogger<IntelPipeWorker> logger,
    string pipeName = IntelClient.PipeName) : BackgroundService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var pipe = NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.Out, 1, PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.WriteThrough, 0, 4096, PipeSecurityFactory.CreateCurrentUserReadSecurity());
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(5));
                await pipe.WaitForConnectionAsync(timeout.Token);
                var now = DateTimeOffset.UtcNow;
                var snapshot = new IntelSnapshot(1, now, settings.Current.IntelLookups, keys.ConfiguredServices, store.LastRunUtc, store.LastRunStatus,
                    store.Results(now).OrderByDescending(result => result.CheckedAtUtc).Take(IntelClient.MaximumResults).ToArray(),
                    store.RecentLookups(IntelClient.MaximumLog), []);
                await JsonSerializer.SerializeAsync(pipe, snapshot, JsonOptions, stoppingToken);
                await pipe.FlushAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested) { }
            catch (IOException exception) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogDebug(exception, "An intel status client disconnected before completion.");
            }
        }
    }
}
