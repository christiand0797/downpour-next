using Downpour.Core;
using Newtonsoft.Json;

namespace Downpour.Service;

/// <summary>Bounded, local aggregate history. No names, file paths, addresses, event contents or credentials are stored.</summary>
public sealed class LocalLearningStore(string path)
{
    public const int MaximumBytes = 1_048_576;

    public static LocalLearningStore CreateForCurrentUser()
    {
        var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "state");
        SecureJournalDirectory.Ensure(folder);
        var path = Path.Combine(folder, "local-learning.v1.json");
        SecureJournalDirectory.RestrictExistingFile(path);
        return new(path);
    }

    public async Task<(LocalLearningHistory History, string? Warning)> LoadAsync(DateTimeOffset now, CancellationToken token)
    {
        try
        {
            if (!File.Exists(path)) return (LocalLearningEngine.Empty, null);
            CheckPath(path);
            if (new FileInfo(path).Length > MaximumBytes) throw new InvalidDataException("History exceeds limit.");
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
            var history = await BoundedJson.DeserializeAsync<LocalLearningHistory>(stream, token);
            if (!LocalLearningEngine.IsValidHistory(history, now)) throw new InvalidDataException("Invalid history.");
            return (history!, null);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonException)
        {
            return (LocalLearningEngine.Empty, "Saved learning history could not be trusted; learning starts with new observations.");
        }
    }

    public async Task<bool> SaveAsync(LocalLearningHistory history, DateTimeOffset now, CancellationToken token)
    {
        if (!LocalLearningEngine.IsValidHistory(history, now)) return false;
        var temporary = path + ".tmp";
        try
        {
            CheckPath(path);
            CheckPath(temporary);
            var payload = BoundedJson.Serialize(history);
            if (payload.Length > MaximumBytes) return false;
            await using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None, 4096,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(payload, token);
                await stream.FlushAsync(token);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    private static void CheckPath(string value)
    {
        var parent = Path.GetDirectoryName(Path.GetFullPath(value))!;
        if ((File.GetAttributes(parent) & FileAttributes.ReparsePoint) != 0
            || (File.Exists(value) && (File.GetAttributes(value) & FileAttributes.ReparsePoint) != 0))
            throw new IOException("Learning history cannot use links.");
    }
}
