using System.IO.Pipes;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class SystemSnapshotClientTests
{
    [Fact]
    public async Task OversizedLocalPipeMessageIsReportedAsUnavailable()
    {
        var pipeName = $"Downpour.SystemSnapshot.test-{Guid.NewGuid():N}";
        await using var server = new NamedPipeServerStream(pipeName, PipeDirection.Out, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        var serverTask = Task.Run(async () =>
        {
            await server.WaitForConnectionAsync();
            try
            {
                await server.WriteAsync(new byte[1_048_577]);
                await server.FlushAsync();
            }
            catch (IOException)
            {
                // The client closes the pipe as soon as it detects the configured size limit.
            }
        });

        var snapshot = await new SystemSnapshotClient(pipeName).TryGetSnapshotAsync();
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Null(snapshot);
    }
}
