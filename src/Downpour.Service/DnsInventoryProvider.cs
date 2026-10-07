using System.Runtime.InteropServices;
using System.Text.Json;
using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Service;

public sealed class DnsInventoryProvider(string baselinePath)
{
    private const int MaximumCacheEntries = 4000;
    private const int MaximumBaselineEntries = 20000;
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

        var entries = new List<DnsCacheEntry>();
        var findings = new List<DnsFinding>();
        var highRiskCount = 0;
        var mediumRiskCount = 0;

        lock (_gate)
        {
            var (baselineDomains, isFirstRun) = LoadBaseline();
            var known = new HashSet<string>(baselineDomains, StringComparer.OrdinalIgnoreCase);
            var newlySeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var (name, recordType) in rawEntries)
            {
                var scored = DgaDetector.ScoreDomain(name);
                var entry = new DnsCacheEntry(
                    Domain: name,
                    RecordType: recordType,
                    RiskScore: scored.Score,
                    IsDga: scored.IsDga,
                    Factors: scored.Factors);
                entries.Add(entry);

                if (scored.Score >= DgaDetector.HighThreshold)
                    highRiskCount++;
                else if (scored.Score >= DgaDetector.AlertThreshold)
                    mediumRiskCount++;

                var hashed = HashDomain(name);
                newlySeen.Add(hashed);

                // TOFU baseline logic:
                // If not in baseline and not first run, alert!
                if (!isFirstRun && !known.Contains(hashed) && scored.Score >= DgaDetector.AlertThreshold)
                {
                    if (findings.Count < MaximumFindings)
                    {
                        var severity = scored.Score >= DgaDetector.HighThreshold ? "HIGH" : "MEDIUM";
                        var technique = scored.Score >= DgaDetector.HighThreshold ? "T1071.004" : "T1568";
                        var factorSummary = string.Join("; ", scored.Factors.Take(3));
                        findings.Add(new DnsFinding(
                            Severity: severity,
                            Technique: technique,
                            Summary: $"DGA-like domain observed in resolver cache: {name} (Risk {scored.Score}: {factorSummary})",
                            Indicator: $"dns:{name}:{scored.Score}"));
                    }
                }

                known.Add(hashed);
            }

            // Update baseline
            if (isFirstRun)
            {
                SaveBaseline(newlySeen.Take(MaximumBaselineEntries));
            }
            else if (newlySeen.Any(d => !baselineDomains.Contains(d)))
            {
                SaveBaseline(known.Take(MaximumBaselineEntries));
            }
        }

        return new DnsCacheSnapshot(
            SchemaVersion: 1,
            CapturedAtUtc: DateTimeOffset.UtcNow,
            TotalEntries: entries.Count,
            HighRiskCount: highRiskCount,
            MediumRiskCount: mediumRiskCount,
            Entries: entries,
            Findings: findings,
            Warnings: warnings);
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

    private static bool IsHash(string value) => value.Length == 64 && value.All(ch => ch is >= '0' and <= '9' or >= 'a' and <= 'f');

    private (HashSet<string> domains, bool isFirstRun) LoadBaseline()
    {
        try
        {
            var info = new FileInfo(baselinePath);
            if (!info.Exists || info.Length > 8 * 1024 * 1024 || (info.Attributes & FileAttributes.ReparsePoint) != 0)
                return (new HashSet<string>(StringComparer.Ordinal), true);

            var model = JsonSerializer.Deserialize<DnsBaselineModel>(File.ReadAllText(baselinePath));
            if (model?.Domains == null)
                return (new HashSet<string>(StringComparer.Ordinal), true);

            // Earlier builds stored plaintext names; hash them and rewrite the file once.
            var hashes = new HashSet<string>(model.Domains.Select(d => IsHash(d) ? d : HashDomain(d)), StringComparer.Ordinal);
            if (model.Domains.Any(d => !IsHash(d))) SaveBaseline(hashes);
            return (hashes, false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return (new HashSet<string>(StringComparer.Ordinal), true);
        }
    }

    private void SaveBaseline(IEnumerable<string> hashes)
    {
        var temporary = baselinePath + ".tmp";
        try
        {
            var dir = Path.GetDirectoryName(baselinePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var list = hashes.OrderBy(h => h, StringComparer.Ordinal).ToList();
            var model = new DnsBaselineModel { UpdatedUtc = DateTimeOffset.UtcNow, Count = list.Count, Domains = list };
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
        public DateTimeOffset UpdatedUtc { get; set; }
        public int Count { get; set; }
        /// <summary>SHA-256 hashes of lower-cased domain names.</summary>
        public List<string> Domains { get; set; } = [];
    }
}
