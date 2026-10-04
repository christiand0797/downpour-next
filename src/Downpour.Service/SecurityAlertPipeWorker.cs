using System.IO.Pipes;
using System.Text.Json;
using Downpour.Core;

namespace Downpour.Service;

public sealed class SecurityAlertPipeWorker(
    SecurityAlertSnapshotStore store,
    ILogger<SecurityAlertPipeWorker> logger,
    string pipeName = SecurityAlertClient.PipeName) : BackgroundService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var pipe = NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.Out, 2,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.WriteThrough, 0, 4096,
                    PipeSecurityFactory.CreateCurrentUserReadSecurity());
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(5));
                await pipe.WaitForConnectionAsync(timeout.Token);
                await JsonSerializer.SerializeAsync(pipe, store.Current, JsonOptions, stoppingToken);
                await pipe.FlushAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested) { }
            catch (IOException exception) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogDebug(exception, "A local security-alert client disconnected before its response completed.");
            }
            catch (Exception exception) when (exception is not OperationCanceledException && !stoppingToken.IsCancellationRequested)
            {
                logger.LogWarning(exception, "The local security-alert snapshot could not be sent.");
            }
        }
    }
}
