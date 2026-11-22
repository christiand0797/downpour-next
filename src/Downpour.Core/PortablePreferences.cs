using System.Text;
using System.Text.Json;

namespace Downpour.Core;

/// <summary>
/// The plaintext of a portable bundle when the only content exported is local switches: a schema marker and a flat map
/// of preference names to booleans. Names are restricted to short ASCII letter runs, so no case text, file path, host
/// name, account or feed credential can ride along under a preference's name. Encryption protects this content; these
/// bounds decide what the content is allowed to be in the first place.
/// </summary>
public static class PortablePreferences
{
    public const string Schema = "downpour-preferences.v1";
    public const int MaximumPayloadBytes = 8 * 1024;
    public const int MaximumEntries = 32;
    public const int MaximumNameLength = 64;

    /// <summary>Writes a stable document (names sorted ordinally) that <see cref="Deserialize"/> can read back.</summary>
    public static byte[] Serialize(IReadOnlyDictionary<string, bool> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Count == 0) throw new ArgumentException("There is nothing to serialize.", nameof(values));
        if (values.Count > MaximumEntries)
            throw new ArgumentException($"A bundle may hold at most {MaximumEntries} preferences.", nameof(values));
        foreach (var name in values.Keys)
            if (!IsPreferenceName(name)) throw new ArgumentException($"\"{Bound(name)}\" is not a preference name.", nameof(values));

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("schema", Schema);
            writer.WriteStartObject("values");
            foreach (var pair in values.OrderBy(p => p.Key, StringComparer.Ordinal))
                writer.WriteBoolean(pair.Key, pair.Value);
            writer.WriteEndObject();
            writer.WriteEndObject();
        }
        var payload = stream.ToArray();
        if (payload.Length > MaximumPayloadBytes)
            throw new ArgumentException("The preferences are larger than a bundle may be.", nameof(values));
        return payload;
    }

    /// <summary>
    /// Reads a document and refuses it whole — never partly — when the schema, a name, a value or a size is wrong, so a
    /// half-applied import cannot leave a PC with settings nobody chose. <paramref name="allowedNames"/> is the caller's
    /// list, which keeps this type from knowing the desktop's switches.
    /// </summary>
    public static IReadOnlyDictionary<string, bool> Deserialize(ReadOnlySpan<byte> payload, IReadOnlyCollection<string> allowedNames)
    {
        ArgumentNullException.ThrowIfNull(allowedNames);
        if (payload.Length == 0) throw new InvalidDataException("The bundle is empty.");
        if (payload.Length > MaximumPayloadBytes)
            throw new InvalidDataException($"The bundle is larger than {MaximumPayloadBytes / 1024} KiB, so it was not written by this feature.");

        JsonDocument document;
        try { document = JsonDocument.Parse(payload.ToArray()); }
        catch (JsonException) { throw new InvalidDataException("The bundle's contents are not valid preferences."); }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("The bundle's contents are not valid preferences.");
            if (!root.TryGetProperty("schema", out var schema) || schema.ValueKind != JsonValueKind.String ||
                !string.Equals(schema.GetString(), Schema, StringComparison.Ordinal))
                throw new InvalidDataException("This is not a Downpour preferences bundle, or a newer build wrote it.");
            if (!root.TryGetProperty("values", out var values) || values.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("The bundle holds no preferences.");

            var allowed = new HashSet<string>(allowedNames, StringComparer.Ordinal);
            var result = new SortedDictionary<string, bool>(StringComparer.Ordinal);
            foreach (var property in values.EnumerateObject())
            {
                if (!IsPreferenceName(property.Name))
                    throw new InvalidDataException("The bundle contains a name that is not a preference.");
                if (!allowed.Contains(property.Name))
                    throw new InvalidDataException($"The bundle contains \"{Bound(property.Name)}\", which this build does not know.");
                if (property.Value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                    throw new InvalidDataException($"The bundle's value for \"{property.Name}\" is not on or off.");
                if (!result.TryAdd(property.Name, property.Value.GetBoolean()))
                    throw new InvalidDataException("The bundle repeats a preference name.");
                if (result.Count > MaximumEntries)
                    throw new InvalidDataException($"The bundle holds more than {MaximumEntries} preferences.");
            }
            if (result.Count == 0) throw new InvalidDataException("The bundle holds no preferences.");
            return result;
        }
    }

    /// <summary>One line per difference, for the confirmation shown before anything is applied. Unchanged switches are omitted.</summary>
    public static IReadOnlyList<string> DescribeChanges(IReadOnlyDictionary<string, bool> current, IReadOnlyDictionary<string, bool> imported)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(imported);
        var changes = new List<string>();
        foreach (var pair in imported.OrderBy(p => p.Key, StringComparer.Ordinal))
        {
            if (current.TryGetValue(pair.Key, out var existing) && existing == pair.Value) continue;
            changes.Add($"{Humanize(pair.Key)}: {(existing ? "on" : "off")} → {(pair.Value ? "on" : "off")}");
            if (changes.Count == MaximumEntries) break;
        }
        return changes;
    }

    private static bool IsPreferenceName(string? name) =>
        !string.IsNullOrEmpty(name) && name.Length <= MaximumNameLength && name.All(char.IsAsciiLetter);

    private static string Humanize(string name)
    {
        var builder = new StringBuilder(name.Length + 8);
        for (var index = 0; index < name.Length; index++)
        {
            if (index > 0 && char.IsAsciiLetterUpper(name[index])) builder.Append(' ');
            builder.Append(char.ToLowerInvariant(name[index]));
        }
        return builder.ToString();
    }

    /// <summary>Bounded, control-character-free form for a message about a name that failed a check.</summary>
    private static string Bound(string? name)
    {
        if (string.IsNullOrEmpty(name)) return "(empty)";
        var bounded = name.Length <= MaximumNameLength ? name : name[..MaximumNameLength] + "…";
        return new string(bounded.Select(c => char.IsControl(c) ? '?' : c).ToArray());
    }
}
