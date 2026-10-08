using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Downpour.Core;

/// <summary>Outcome of checking an audit log against its keyed hash chain.</summary>
public sealed record AuditVerification(int Records, int Chained, int Legacy, bool Intact, int? BrokenAtLine, long LastSequence, string LastHash, string Message);

/// <summary>
/// Tamper-evident audit records. Each line is <c>{"seq":n,"prev":"…","body":{…},"mac":"…"}</c> where mac is
/// HMAC-SHA256(key, "seq\nprev\nbody") over the body's exact text and prev is the previous record's mac, so editing,
/// reordering, inserting or deleting any record breaks every later link. The key never appears in the log; the head
/// (sequence and mac) is also kept in a separate anchor so a truncated tail is detected. Lines written before chaining
/// began ("legacy") are accepted only before the first chained record.
/// </summary>
public static class AuditChain
{
    public const string Genesis = "0000000000000000000000000000000000000000000000000000000000000000";
    public const int MaximumLineLength = 4096;

    public static string Mac(byte[] key, long sequence, string previous, string body)
    {
        var data = Encoding.UTF8.GetBytes($"{sequence}\n{previous}\n{body}");
        return Convert.ToHexString(HMACSHA256.HashData(key, data)).ToLowerInvariant();
    }

    /// <summary>Builds the next chained line for a JSON body.</summary>
    public static string Line(byte[] key, long sequence, string previous, string body, out string mac)
    {
        mac = Mac(key, sequence, previous, body);
        return $"{{\"seq\":{sequence},\"prev\":\"{previous}\",\"body\":{body},\"mac\":\"{mac}\"}}";
    }

    /// <summary>A MAC over the head so the anchor itself cannot be edited to match a truncated log.</summary>
    public static string AnchorMac(byte[] key, long sequence, string head) => Mac(key, sequence, "anchor", head);

    /// <summary>
    /// Checks lines oldest first. Pass the anchored head to detect truncation; null skips that check. After a rollover
    /// the retained window starts at <paramref name="firstSequence"/>: that record must carry exactly that number, and
    /// only its link to the discarded record before it is unchecked.
    /// </summary>
    public static AuditVerification Verify(IEnumerable<string> lines, byte[] key, long? anchorSequence = null, string? anchorHash = null, long firstSequence = 1)
    {
        var records = 0;
        var chained = 0;
        var legacy = 0;
        long sequence = 0;
        var previous = Genesis;
        foreach (var line in lines)
        {
            records++;
            if (string.IsNullOrWhiteSpace(line)) return Broken(records, chained, legacy, sequence, previous, "an empty line was inserted");
            if (line.Length > MaximumLineLength) return Broken(records, chained, legacy, sequence, previous, "a record is too long");
            if (!TryParse(line, out var seq, out var prev, out var body, out var mac))
            {
                // Only lines written before chaining started may lack a MAC.
                if (chained > 0 || !IsLegacyRecord(line)) return Broken(records, chained, legacy, sequence, previous, "a record is not a valid chained entry");
                legacy++;
                continue;
            }
            if (chained == 0 && firstSequence > 1)
            {
                if (seq != firstSequence) return Broken(records, chained, legacy, sequence, previous, $"the log starts at record {seq} but the kept window starts at {firstSequence} (records deleted from the start)");
                sequence = seq - 1;
                previous = prev;
            }
            if (seq != sequence + 1) return Broken(records, chained, legacy, sequence, previous, $"record {seq} follows {sequence} (records missing or reordered)");
            if (!prev.Equals(previous, StringComparison.Ordinal)) return Broken(records, chained, legacy, sequence, previous, $"record {seq} does not link to the record before it");
            if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Mac(key, seq, prev, body)), Encoding.ASCII.GetBytes(mac)))
                return Broken(records, chained, legacy, sequence, previous, $"record {seq} was altered (its MAC does not match)");
            sequence = seq;
            previous = mac;
            chained++;
        }
        if (anchorSequence is { } anchored)
        {
            if (sequence < anchored) return Broken(records + 1, chained, legacy, sequence, previous, $"the log ends at record {sequence} but {anchored} were written (records deleted from the end)");
            if (sequence == anchored && anchorHash is not null && !anchorHash.Equals(previous, StringComparison.Ordinal))
                return Broken(records + 1, chained, legacy, sequence, previous, "the last record does not match the anchored head");
        }
        var message = chained == 0 ? "No chained records yet." : $"All {chained:N0} chained records verified{(legacy > 0 ? $" ({legacy} older unchained records precede them)" : "")}.";
        return new AuditVerification(records, chained, legacy, true, null, sequence, previous, message);
    }

    private static AuditVerification Broken(int line, int chained, int legacy, long sequence, string previous, string reason) =>
        new(line, chained, legacy, false, line, sequence, previous, $"Audit log integrity check failed at line {line}: {reason}.");

    private static bool TryParse(string line, out long seq, out string prev, out string body, out string mac)
    {
        seq = 0;
        prev = body = mac = "";
        try
        {
            using var document = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("seq", out var s) || !s.TryGetInt64(out seq) || seq < 1
                || !root.TryGetProperty("prev", out var p) || p.GetString() is not { Length: 64 } prevText
                || !root.TryGetProperty("body", out var b) || b.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("mac", out var m) || m.GetString() is not { Length: 64 } macText)
                return false;
            prev = prevText;
            body = b.GetRawText();
            mac = macText;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool IsLegacyRecord(string line)
    {
        try
        {
            using var document = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 8 });
            return document.RootElement.ValueKind == JsonValueKind.Object && document.RootElement.TryGetProperty("operation", out _)
                && !document.RootElement.TryGetProperty("mac", out _);
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
