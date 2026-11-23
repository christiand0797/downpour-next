using System.Runtime.InteropServices;
using System.Text.Json;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Service;

public sealed class DnsInventoryProvider(string baselinePath)
{
    private const int MaximumCacheEntries = 4000;
    private const int MaximumBaselineEntries = DomainBaseline.DefaultCapacity;
    private const int MaximumFindings = 256;
    private readonly object _gate = new();

    public static DnsInventoryProvider CreateForCurrentUser()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "state");
        SecureJournalDirectory.Ensure(root);
        var path = Path.Combine(root, "dns-baseline.v1.json");
        SecureJournalDirectory.RestrictExistingFile(path);
        return new DnsInventoryProvider(path);
    }

    // DNS_CACHE_ENTRY as returned by the undocumented DnsGetCacheDataTable: { pNext, pszName, wType, wDataLength, dwFlags }.
    // An extra pointer field here previously shifted wType, so every record read as type 19788. Verified live: the layout
    // below yields A (1), AAAA (28), PTR (12), and TXT (16) records.
    [StructLayout(LayoutKind.Sequential)]
    private struct NativeDnsCacheEntry
    {
        public IntPtr pNext;
        public IntPtr pszName;
        public ushort wType;
        public ushort wDataLength;
        public uint dwFlags;
    }

    [DllImport("dnsapi.dll", EntryPoint = "DnsGetCacheDataTable", SetLastError = true)]
    private static extern int DnsGetCacheDataTable(out IntPtr pHead);

    public DnsCacheSnapshot Capture()
    {
        var warnings = new List<string>();
        var rawEntries = ReadResolverCache(warnings);
        var now = DateTimeOffset.UtcNow;

        var scored = new List<(string Name, int RecordType, int Score, bool IsDga, IReadOnlyList<string> Factors, DomainLookalike? Lookalike)>();
        var hashes = new List<string>(rawEntries.Count);
        foreach (var (name, recordType) in rawEntries)
        {
            var result = DgaDetector.ScoreDomain(name);
            scored.Add((name, recordType, result.Score, result.IsDga, result.Factors, DomainConfusables.Describe(name)));
            hashes.Add(HashDomain(name));
        }

        // The baseline is the only persisted DNS state, and it holds hashes plus two dates — never a name.
        DomainBaselineUpdate update;
        lock (_gate)
        {
            update = LoadBaseline().Observe(hashes, now, MaximumBaselineEntries);
            if (update.FirstRun || update.NewHashes.Count > 0 || update.Evicted > 0) SaveBaseline(update.Baseline);
        }
        if (update.Evicted > 0)
            warnings.Add($"{update.Evicted} older name(s) left the local baseline because it reached {MaximumBaselineEntries:N0} entries. The least recently resolved go first, so a name resolved today is kept.");
        var newSet = update.NewHashes.ToHashSet(StringComparer.Ordinal);

        var entries = new List<DnsCacheEntry>(scored.Count);
        var findings = new List<DnsFinding>();
        var highRiskCount = 0;
        var mediumRiskCount = 0;
        var newlyObserved = 0;

        for (var index = 0; index < scored.Count; index++)
        {
            var (name, recordType, score, isDga, factors, lookalike) = scored[index];
            var hash = hashes[index];
            // A first capture is a baseline, so no name in it has a meaningful "first seen" date yet.
            entries.Add(new DnsCacheEntry(name, recordType, score, isDga, factors, lookalike, update.FirstRun ? null : update.Baseline.FirstSeen(hash)));

            if (score >= DgaDetector.HighThreshold)
                highRiskCount++;
            else if (score >= DgaDetector.AlertThreshold)
                mediumRiskCount++;

            if (update.FirstRun || !newSet.Contains(hash)) continue;
            newlyObserved++;
            if (score < DgaDetector.AlertThreshold || findings.Count >= MaximumFindings) continue;
            var severity = score >= DgaDetector.HighThreshold ? "HIGH" : "MEDIUM";
            var technique = score >= DgaDetector.HighThreshold ? "T1071.004" : "T1568";
            var factorSummary = string.Join("; ", factors.Take(3));
            findings.Add(new DnsFinding(
                Severity: severity,
                Technique: technique,
                Summary: $"DGA-like domain observed in resolver cache: {name} (Risk {score}: {factorSummary})",
                Indicator: $"dns:{name}:{score}"));
        }

        return new DnsCacheSnapshot(
            SchemaVersion: 1,
            CapturedAtUtc: now,
            TotalEntries: entries.Count,
            HighRiskCount: highRiskCount,
            MediumRiskCount: mediumRiskCount,
            Entries: entries,
            Findings: findings,
            Warnings: warnings,
            NewlyObservedCount: update.FirstRun ? 0 : newlyObserved,
            ObservedSinceUtc: update.Baseline.EstablishedUtc,
            BaselineCount: update.Baseline.Count);
    }

    private static List<(string Name, int RecordType)> ReadResolverCache(List<string> warnings)
    {
        var list = new List<(string Name, int RecordType)>();
        var seenNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var visitedPtrs = new HashSet<IntPtr>();

        try
        {
            var ret = DnsGetCacheDataTable(out var head);
            if (ret == 0 || head == IntPtr.Zero)
            {
                warnings.Add("DnsGetCacheDataTable returned no table or is unavailable.");
                return list;
            }

            var current = head;
            while (current != IntPtr.Zero && list.Count < MaximumCacheEntries)
            {
                if (!visitedPtrs.Add(current)) break; // cycle protection

                var ent = Marshal.PtrToStructure<NativeDnsCacheEntry>(current);
                if (ent.pszName != IntPtr.Zero)
                {
                    var rawName = Marshal.PtrToStringUni(ent.pszName);
                    if (!string.IsNullOrWhiteSpace(rawName))
                    {
                        var name = rawName.Trim().TrimEnd('.').ToLowerInvariant();
                        if (name.Contains('.') &&
                            !name.Any(c => c is '/' or '\\' or ':' or '%' or ' ' or '<' or '>') &&
                            seenNames.Add(name))
                        {
                            list.Add((name, ent.wType));
                        }
                    }
                }

                current = ent.pNext;
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Error reading resolver cache: {ex.Message}");
        }

        return list;
    }

    /// <summary>
    /// The baseline stores SHA-256 hashes of lower-cased domain names, never the names. A plain list of every
    /// resolved domain would be a browsing history on disk (AGENTS.md: no precise user activity).
    /// </summary>
    internal static string HashDomain(string domain) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(domain.Trim().ToLowerInvariant()))).ToLowerInvariant();

    /// <summary>Reads both file shapes: the current hash+dates model and the earlier list of hashes or plaintext names.</summary>
    private DomainBaseline LoadBaseline()
    {
        try
        {
            var info = new FileInfo(baselinePath);
            if (!info.Exists || info.Length > 8 * 1024 * 1024 || (info.Attributes & FileAttributes.ReparsePoint) != 0)
                return new DomainBaseline();

            var text = File.ReadAllText(baselinePath);
            using var document = JsonDocument.Parse(text);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("Domains", out var domains) || domains.ValueKind != JsonValueKind.Array)
                return new DomainBaseline();

            var fallback = ReadUpdatedUtc(root) ?? new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero);
            var now = DateTimeOffset.UtcNow;
            var observations = new List<DomainObservation>();
            foreach (var item in domains.EnumerateArray())
            {
                if (observations.Count >= DomainBaseline.MaximumCapacity) break;
                if (item.ValueKind == JsonValueKind.String)
                {
                    // Earlier builds stored hashes, and before that plaintext names. Both are known at least since the file's time.
                    var value = item.GetString();
                    if (string.IsNullOrWhiteSpace(value)) continue;
                    var hash = DomainBaseline.IsHash(value) ? value : HashDomain(value);
                    observations.Add(new DomainObservation(hash, fallback, fallback));
                }
                else if (item.ValueKind == JsonValueKind.Object &&
                         item.TryGetProperty("Hash", out var hashElement) && hashElement.ValueKind == JsonValueKind.String &&
                         hashElement.GetString() is { } hash && DomainBaseline.IsHash(hash))
                {
                    var first = ReadDate(item, "FirstSeenUtc") ?? fallback;
                    var last = ReadDate(item, "LastSeenUtc") ?? first;
                    // A stored date in the future would win every eviction comparison forever; keep it inside the clock.
                    observations.Add(new DomainObservation(hash, first > now + DomainBaseline.MaximumClockSkew ? now : first,
                        last > now + DomainBaseline.MaximumClockSkew ? now : last));
                }
            }
            return new DomainBaseline(observations, MaximumBaselineEntries);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or FormatException)
        {
            return new DomainBaseline();
        }
    }

    private static DateTimeOffset? ReadUpdatedUtc(JsonElement root) =>
        root.TryGetProperty("UpdatedUtc", out var updated) && updated.ValueKind == JsonValueKind.String &&
        DateTimeOffset.TryParse(updated.GetString(), System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var value)
            ? value : null;

    private static DateTimeOffset? ReadDate(JsonElement item, string name) =>
        item.TryGetProperty(name, out var element) && element.ValueKind == JsonValueKind.String &&
        DateTimeOffset.TryParse(element.GetString(), System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var value)
            ? value : null;

    private void SaveBaseline(DomainBaseline baseline)
    {
        var temporary = baselinePath + ".tmp";
        try
        {
            var dir = Path.GetDirectoryName(baselinePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var entries = baseline.Snapshot().Take(MaximumBaselineEntries)
                .Select(observation => new DnsBaselineEntry
                {
                    Hash = observation.Hash,
                    FirstSeenUtc = observation.FirstSeenUtc,
                    LastSeenUtc = observation.LastSeenUtc,
                })
                .ToList();
            var model = new DnsBaselineModel { SchemaVersion = 2, UpdatedUtc = DateTimeOffset.UtcNow, Count = entries.Count, Domains = entries };
            File.WriteAllText(temporary, JsonSerializer.Serialize(model));
            File.Move(temporary, baselinePath, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Baseline save failures never fail the capture; new domains are compared again next time.
            try { File.Delete(temporary); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    private sealed class DnsBaselineModel
    {
        public int SchemaVersion { get; set; }
        public DateTimeOffset UpdatedUtc { get; set; }
        public int Count { get; set; }
        /// <summary>SHA-256 hashes with their first and most recent observation. Never a domain name.</summary>
        public List<DnsBaselineEntry> Domains { get; set; } = [];
    }

    private sealed class DnsBaselineEntry
    {
        public string Hash { get; set; } = "";
        public DateTimeOffset FirstSeenUtc { get; set; }
        public DateTimeOffset LastSeenUtc { get; set; }
    }
}
