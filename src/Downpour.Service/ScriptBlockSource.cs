using System.Diagnostics.Eventing.Reader;

namespace Downpour.Service;

/// <summary>
/// One PowerShell script-block part (Event 4104). Service-internal by design: this type must never be serialized,
/// logged, persisted, or sent over IPC (SECURITY.md "User-approved data handling").
/// </summary>
internal sealed record ScriptBlock(long? RecordId, DateTimeOffset? CreatedAtUtc, string Text, int MessageNumber, int MessageTotal)
{
    public override string ToString() => $"ScriptBlock(record {RecordId}, part {MessageNumber}/{MessageTotal}, {Text.Length} chars)";
}

/// <summary>Live subscription to Event 4104 script-block text, created only while script-block analysis is enabled.</summary>
internal static class ScriptBlockSource
{
    internal const int MaximumTextChars = 64 * 1024;
    private const string LogName = "Microsoft-Windows-PowerShell/Operational";

    public static IDisposable? Subscribe(Action<ScriptBlock> onBlock, Action<string> onWarning)
    {
        var selector = new EventLogPropertySelector(new[]
        {
            "Event/EventData/Data[@Name='MessageNumber']",
            "Event/EventData/Data[@Name='MessageTotal']",
            "Event/EventData/Data[@Name='ScriptBlockText']",
        });
        try
        {
            var watcher = new EventLogWatcher(new EventLogQuery(LogName, PathType.LogName, "*[System[(EventID=4104)]]"), null, readExistingEvents: false);
            watcher.EventRecordWritten += (_, args) =>
            {
                if (args.EventException is not null)
                {
                    onWarning("A PowerShell script-block event could not be read.");
                    return;
                }
                using var record = args.EventRecord as EventLogRecord;
                if (record is null) return;
                try
                {
                    var values = record.GetPropertyValues(selector);
                    var text = values[2] as string;
                    if (string.IsNullOrEmpty(text)) return;
                    if (text.Length > MaximumTextChars) text = text[..MaximumTextChars];
                    var created = record.TimeCreated is { } time ? new DateTimeOffset(time.ToUniversalTime(), TimeSpan.Zero) : (DateTimeOffset?)null;
                    onBlock(new ScriptBlock(record.RecordId, created, text, ToInt(values[0]), ToInt(values[1])));
                }
                catch (Exception exception) when (exception is EventLogException or InvalidOperationException or ArgumentException)
                {
                    onWarning("A PowerShell script-block event could not be parsed.");
                }
            };
            watcher.Enabled = true;
            return watcher;
        }
        catch (Exception exception) when (exception is EventLogNotFoundException or EventLogException or UnauthorizedAccessException
            or InvalidOperationException or System.Security.SecurityException)
        {
            onWarning($"PowerShell script-block subscription is unavailable ({exception.GetType().Name}).");
            return null;
        }
    }

    private static int ToInt(object? value) => value switch
    {
        int number => number,
        uint number => (int)number,
        string text when int.TryParse(text, out var parsed) => parsed,
        _ => 0
    };
}
