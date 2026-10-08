namespace Downpour.Service;

/// <summary>
/// Warnings, errors and crashes of the sensor service in %LOCALAPPDATA%\DownpourNext\logs\service.log (1 MiB, one
/// rollover), so a failure on another PC can be diagnosed. Messages are what the service already logs: no file
/// contents, command lines or personal data are added here.
/// </summary>
public sealed class ServiceFileLoggerProvider(string path) : ILoggerProvider
{
    private const long MaximumBytes = 1024 * 1024;
    private readonly object _gate = new();

    public static string DefaultPath()
    {
        var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "logs");
        Directory.CreateDirectory(folder);
        return Path.Combine(folder, "service.log");
    }

    public ILogger CreateLogger(string categoryName) => new FileLogger(this, categoryName);

    public void Dispose() { }

    internal void Write(string level, string category, string message, Exception? exception)
    {
        var shortCategory = category[(category.LastIndexOf('.') + 1)..];
        var line = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz} {level} {shortCategory}: {message}";
        if (exception is not null) line += $" | {exception.GetType().Name}: {exception.Message}";
        line = new string(line.Where(c => c is '\t' || !char.IsControl(c)).Take(2000).ToArray());
        lock (_gate)
        {
            try
            {
                if (File.Exists(path) && new FileInfo(path).Length > MaximumBytes) File.Move(path, path + ".1", overwrite: true);
                File.AppendAllText(path, line + Environment.NewLine);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    /// <summary>Records an exception that is about to end the process.</summary>
    public static void RecordCrash(Exception exception)
    {
        try
        {
            var crash = Path.Combine(Path.GetDirectoryName(DefaultPath())!, "service-crash.log");
            File.AppendAllText(crash, $"{DateTimeOffset.Now:O} v{typeof(ServiceFileLoggerProvider).Assembly.GetName().Version}{Environment.NewLine}{exception}{Environment.NewLine}{Environment.NewLine}");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private sealed class FileLogger(ServiceFileLoggerProvider owner, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Warning && logLevel != LogLevel.None;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;
            owner.Write(logLevel switch { LogLevel.Warning => "WARN", LogLevel.Error => "ERROR", _ => "CRIT" }, category, formatter(state, exception), exception);
        }
    }
}
