using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Downpour.Core;

/// <summary>Bounded JSON parsing and serialization for UI-side contracts and untrusted local IPC.</summary>
public static class BoundedJson
{
    public const int MaximumPayloadBytes = 1_048_576;
    private static readonly JsonSerializerSettings Settings = new()
    {
        TypeNameHandling = TypeNameHandling.None,
        MetadataPropertyHandling = MetadataPropertyHandling.Ignore,
        MissingMemberHandling = MissingMemberHandling.Ignore,
        MaxDepth = 32,
        DateParseHandling = DateParseHandling.None,
        CheckAdditionalContent = true
    };
    public static async Task<T?> DeserializeAsync<T>(Stream source, CancellationToken cancellationToken)
    {
        using var payload = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            if (payload.Length + read > MaximumPayloadBytes)
                throw new InvalidDataException("The JSON message exceeds the configured size limit.");
            await payload.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }
        return Deserialize<T>(payload.ToArray());
    }

    public static T? Deserialize<T>(ReadOnlyMemory<byte> payload)
    {
        if (payload.Length is 0 or > MaximumPayloadBytes)
            throw new InvalidDataException("The JSON payload is empty or exceeds the configured size limit.");

        try
        {
            using var stream = new MemoryStream(payload.ToArray(), writable: false);
            using var text = new StreamReader(stream, new UTF8Encoding(false, true), detectEncodingFromByteOrderMarks: false);
            using var reader = new JsonTextReader(text) { MaxDepth = 32, DateParseHandling = DateParseHandling.None, SupportMultipleContent = false };
            var token = ParseStrict(reader);
            if (reader.Read()) throw new JsonReaderException("Unexpected trailing JSON content.");
            return token.ToObject<T>(JsonSerializer.Create(Settings));
        }
        catch (DecoderFallbackException exception)
        {
            throw new JsonReaderException("The JSON payload is not valid UTF-8.", exception);
        }
    }

    public static byte[] Serialize<T>(T value)
    {
        using var stream = new MemoryStream();
        using var writer = new StreamWriter(stream, new UTF8Encoding(false, true), 1024, true);
        using var jsonWriter = new JsonTextWriter(writer) { CloseOutput = false };
        var serializer = JsonSerializer.Create(Settings);
        serializer.Serialize(jsonWriter, value);
        jsonWriter.Flush();
        return stream.ToArray();
    }

    public static JToken ParseStrict(JsonTextReader reader)
    {
        if (!reader.Read()) throw new JsonReaderException("The JSON payload is empty.");
        return ReadToken(reader);
    }

    private static JToken ReadToken(JsonTextReader reader)
    {
        switch (reader.TokenType)
        {
            case JsonToken.StartObject:
            {
                var result = new JObject();
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                while (reader.Read())
                {
                    if (reader.TokenType == JsonToken.EndObject) return result;
                    if (reader.TokenType != JsonToken.PropertyName || reader.Value is not string name || !names.Add(name))
                        throw new JsonReaderException("JSON object contains an invalid or duplicate property name.");
                    if (!reader.Read()) throw new JsonReaderException("JSON object ended before a property value.");
                    result.Add(name, ReadToken(reader));
                }
                throw new JsonReaderException("JSON object was not closed.");
            }
            case JsonToken.StartArray:
            {
                var result = new JArray();
                while (reader.Read())
                {
                    if (reader.TokenType == JsonToken.EndArray) return result;
                    result.Add(ReadToken(reader));
                }
                throw new JsonReaderException("JSON array was not closed.");
            }
            case JsonToken.String: return new JValue((string?)reader.Value ?? "");
            case JsonToken.Integer: return new JValue(reader.Value!);
            case JsonToken.Float:
            {
                if (reader.Value is double number && !double.IsFinite(number))
                    throw new JsonReaderException("Non-finite JSON numbers are not accepted.");
                return new JValue(reader.Value!);
            }
            case JsonToken.Boolean: return new JValue((bool)reader.Value!);
            case JsonToken.Null: return JValue.CreateNull();
            default: throw new JsonReaderException($"JSON token {reader.TokenType} is not permitted.");
        }
    }
}
