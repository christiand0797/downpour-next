using System.Text.Json;
using System.Text.Json.Serialization;

namespace Downpour.Core;

/// <summary>
/// Persists <see cref="UpdateStagingJournal"/> transitions outside the install folder, so a crash or a failed apply
/// leaves a named state instead of an unknown one. The file is local state only: it holds no paths, account names or
/// package contents, and it is bounded so a damaged file cannot turn into an unbounded read.
/// </summary>
public static class UpdateJournalStore
{
    public const int SchemaVersion = 1;
    public const int MaximumRecords = 32;
    public const int MaximumFileBytes = 64 * 1024;
    public const int MaximumDetailLength = 300;

    private static readonly JsonSerializerOptions Options = new()
    {
        MaxDepth = 8,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    /// <summary>The per-user journal used by the desktop and the standalone update helper.</summary>
    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "DownpourNext", "updates", "update-journal.json");

    /// <summary>Reads the journal; a missing file is an empty journal, a damaged one is an error.</summary>
    public static IReadOnlyList<UpdateRecord> Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!File.Exists(path)) return [];
        var info = new FileInfo(path);
        if (info.Length is < 2 or > MaximumFileBytes)
            throw new InvalidDataException("The update journal is outside its size limits.");

        UpdateJournalDocument? document;
        try
        {
            document = JsonSerializer.Deserialize<UpdateJournalDocument>(File.ReadAllBytes(path), Options);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The update journal is not valid JSON.", exception);
        }

        if (document?.Records is null || document.SchemaVersion != SchemaVersion || document.Records.Count > MaximumRecords)
            throw new InvalidDataException("The update journal is outside its limits.");
        foreach (var record in document.Records)
        {
            if (record is null || !IsValidVersion(record.Version) || record.Detail is null ||
                record.Detail.Length > MaximumDetailLength || !Enum.IsDefined(record.State) || record.AtUtc == default)
                throw new InvalidDataException("An update journal record is invalid.");
        }
        return document.Records;
    }

    /// <summary>Starts a cycle after the package digest matched; an abandoned cycle is recorded as rolled back first.</summary>
    public static UpdateRecord Begin(string path, string version, DateTimeOffset now, string detail = "")
    {
        if (!IsValidVersion(version) || version.Any(char.IsControl))
            throw new ArgumentOutOfRangeException(nameof(version));
        var records = new List<UpdateRecord>(Load(path));
        if (records.Count > 0 && IsInProgress(records[^1].State))
            records[^1] = UpdateStagingJournal.Advance(records[^1], UpdateState.RolledBack, now,
                "Abandoned; a new update check started.");
        var started = new UpdateRecord(version, UpdateState.Downloaded, now, BoundDetail(detail));
        records.Add(started);
        Save(path, records);
        return started;
    }

    /// <summary>Appends one legal transition and returns the new record.</summary>
    public static UpdateRecord Advance(string path, UpdateState next, DateTimeOffset now, string detail = "")
    {
        var records = new List<UpdateRecord>(Load(path));
        if (records.Count == 0) throw new InvalidOperationException("No update is journaled.");
        var advanced = UpdateStagingJournal.Advance(records[^1], next, now, detail) with { Detail = BoundDetail(detail) };
        records.Add(advanced);
        Save(path, records);
        return advanced;
    }

    /// <summary>
    /// Best-effort failure record for a caller that is already unwinding. Returns null when there is nothing to mark or
    /// the journal cannot be written; it never masks the original failure.
    /// </summary>
    public static UpdateRecord? TryRecordFailure(string path, DateTimeOffset now, string detail)
    {
        try
        {
            var records = Load(path);
            if (records.Count == 0 || !IsInProgress(records[^1].State)) return null;
            return Advance(path, UpdateState.RolledBack, now, detail);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException
            or InvalidOperationException or ArgumentException)
        {
            return null;
        }
    }

    /// <summary>
    /// The gate the helper applies before touching any file: the newest record must say this exact version was staged.
    /// A downloaded or verified-only package is refused rather than applied from an unknown step.
    /// </summary>
    public static UpdateRecord RequireStaged(IReadOnlyList<UpdateRecord> records, string version)
    {
        ArgumentNullException.ThrowIfNull(records);
        if (!IsValidVersion(version)) throw new ArgumentOutOfRangeException(nameof(version));
        var latest = records.Count == 0 ? null : records[^1];
        if (latest is null || latest.State != UpdateState.Staged || !string.Equals(latest.Version, version, StringComparison.Ordinal))
            throw new InvalidDataException("The update journal has no staged record for this package. Check for updates again to restage it.");
        return latest;
    }

    private static void Save(string path, IReadOnlyList<UpdateRecord> records)
    {
        var bounded = records.Count > MaximumRecords ? records.Skip(records.Count - MaximumRecords).ToArray() : records.ToArray();
        var document = new UpdateJournalDocument(SchemaVersion,
            bounded.Select(record => record with { Detail = BoundDetail(record.Detail) }).ToList());
        var full = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        var temporary = full + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temporary, JsonSerializer.Serialize(document, Options));
            File.Move(temporary, full, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(temporary)) File.Delete(temporary); } catch { }
        }
    }

    private static bool IsInProgress(UpdateState state) =>
        state is UpdateState.Downloaded or UpdateState.Verified or UpdateState.Staged;

    private static bool IsValidVersion(string? version) =>
        version is { Length: >= 1 and <= 32 } && Version.TryParse(version, out var parsed) &&
        parsed.Build >= 0 && parsed.Revision == -1;

    private static string BoundDetail(string? detail)
    {
        var trimmed = (detail ?? "").Trim();
        return trimmed.Length > MaximumDetailLength ? trimmed[..MaximumDetailLength] : trimmed;
    }

    private sealed record UpdateJournalDocument(int SchemaVersion, List<UpdateRecord> Records);
}
