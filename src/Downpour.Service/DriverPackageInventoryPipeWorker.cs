using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.Extensions.Logging;

namespace Downpour.Service;

public sealed class DriverPackageInventoryPipeWorker : BackgroundService
{
    private const string PipeName = "downpour.driver-package-inventory";
    private readonly DriverPackageInventoryProvider _provider;
    private readonly ILogger<DriverPackageInventoryPipeWorker> _logger;

    public DriverPackageInventoryPipeWorker(
        DriverPackageInventoryProvider provider,
        ILogger<DriverPackageInventoryPipeWorker> logger)
    {
        _provider = provider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Driver package inventory pipe worker started.");

        while (!stoppingToken.IsCancellationRequested)
        {
            using var server = new NamedPipeServerStream(
                PipeName,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);

            try
            {
                await server.WaitForConnectionAsync(stoppingToken);
                var snapshot = _provider.Capture();
                var payload = BoundedJson.Serialize(snapshot);

                var lengthBytes = new byte[4];
                BinaryPrimitives.WriteInt32LittleEndian(lengthBytes, payload.Length);
                await server.WriteAsync(lengthBytes, stoppingToken);
                await server.WriteAsync(payload, stoppingToken);
                await server.FlushAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException)
            {
                // Client disconnected or cancellation
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in driver package inventory pipe worker");
            }
        }
    }
}