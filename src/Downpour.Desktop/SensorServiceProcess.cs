using System.Diagnostics;
using System.ComponentModel;
using Downpour.Core;

namespace Downpour_Desktop;

/// <summary>Starts the bundled, read-only telemetry process when the desktop is launched directly.</summary>
internal sealed class SensorServiceProcess(Action<string> setStatus) : IDisposable
{
    private static readonly TimeSpan RetryDelay = TimeSpan.FromSeconds(5);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly SystemSnapshotClient _client = new();
    private Process? _ownedProcess;
    private DateTimeOffset _retryAfterUtc;
    private bool _disposed;

    public async Task EnsureRunningAsync(CancellationToken cancellationToken = default)
    {
        if (_disposed) return;
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (_disposed) return;
            if (_ownedProcess is { HasExited: false })
            {
                setStatus("The desktop app is running and its bundled sensor service is starting.");
                return;
            }

            _ownedProcess?.Dispose();
            _ownedProcess = null;

            if (await _client.TryGetSnapshotAsync(cancellationToken) is not null)
            {
                setStatus("The desktop app is running and connected to the local sensor service.");
                return;
            }

            if (DateTimeOffset.UtcNow < _retryAfterUtc) return;
            _retryAfterUtc = DateTimeOffset.UtcNow + RetryDelay;

            var servicePath = FindBundledService();
            if (servicePath is null)
            {
                setStatus("The desktop app is running, but its local sensor service is unavailable. Extract the complete portable package or start Downpour.Service from the development setup.");
                return;
            }

            try
            {
                _ownedProcess = Process.Start(new ProcessStartInfo
                {
                    FileName = servicePath,
                    WorkingDirectory = Path.GetDirectoryName(servicePath)!,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                });
                setStatus(_ownedProcess is null
                    ? "The desktop app is running, but Windows did not start the bundled sensor service."
                    : "The desktop app is running and its bundled sensor service is starting.");
            }
            catch (Exception exception) when (exception is Win32Exception or InvalidOperationException or IOException or UnauthorizedAccessException)
            {
                setStatus($"The desktop app is running, but Windows could not start its local sensor service ({exception.GetType().Name}).");
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        var process = _ownedProcess;
        _ownedProcess = null;
        if (process is null) return;
        try
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
        catch (Exception exception) when (exception is InvalidOperationException or Win32Exception)
        {
            // Shutdown is best-effort; the UI must still close if the child already exited.
        }
        finally
        {
            process.Dispose();
        }
    }

    private static string? FindBundledService()
    {
        var baseDirectory = Path.GetFullPath(AppContext.BaseDirectory);
        var candidates = new[]
        {
            Path.Combine(baseDirectory, "service", "Downpour.Service.exe"),
            Path.Combine(baseDirectory, "Downpour.Service.exe")
        };

        return candidates.Select(Path.GetFullPath)
            .FirstOrDefault(path => IsWithinDirectory(path, baseDirectory) && File.Exists(path));
    }

    private static bool IsWithinDirectory(string path, string directory)
    {
        var prefix = Path.TrimEndingDirectorySeparator(directory) + Path.DirectorySeparatorChar;
        return path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }
}
