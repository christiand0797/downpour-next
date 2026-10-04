using Downpour.Contracts;
using Newtonsoft.Json;

namespace Downpour.Core;

public static class CapabilityRegistry
{
    private static readonly JsonSerializerSettings JsonOptions = new()
    {
        TypeNameHandling = TypeNameHandling.None,
        MissingMemberHandling = MissingMemberHandling.Error,
        MaxDepth = 24,
        DateParseHandling = DateParseHandling.None,
        CheckAdditionalContent = true
    };

    public static IReadOnlyList<CapabilityDefinition> Load(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("The Downpour capability registry is missing.", path);
        }

        var bytes = File.ReadAllBytes(path);
        if (bytes.Length > BoundedJson.MaximumPayloadBytes)
            throw new InvalidDataException("The Downpour capability registry exceeds its size limit.");
        var document = JsonConvert.DeserializeObject<CapabilityDocument>(new System.Text.UTF8Encoding(false, true).GetString(bytes), JsonOptions)
            ?? throw new InvalidDataException("The Downpour capability registry is empty.");

        if (document.SchemaVersion != 1 || document.Capabilities is null || document.Capabilities.Count == 0)
        {
            throw new InvalidDataException("The Downpour capability registry has an unsupported schema or no routes.");
        }

        var duplicateRoute = document.Capabilities
            .GroupBy(item => item.RouteId, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault(group => group.Count() > 1);
        var duplicateTitle = document.Capabilities
            .GroupBy(item => item.Title.Trim(), StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault(group => group.Count() > 1);

        if (duplicateRoute is not null)
        {
            throw new InvalidDataException($"Duplicate capability route ID: {duplicateRoute.Key}");
        }

        if (duplicateTitle is not null)
        {
            throw new InvalidDataException($"Duplicate capability title: {duplicateTitle.Key}");
        }

        foreach (var item in document.Capabilities)
        {
            if (string.IsNullOrWhiteSpace(item.RouteId) ||
                string.IsNullOrWhiteSpace(item.Title) ||
                string.IsNullOrWhiteSpace(item.Group) ||
                string.IsNullOrWhiteSpace(item.SourceMethod) ||
                string.IsNullOrWhiteSpace(item.Description) ||
                item.Icon.Length != 4 ||
                !item.Icon.All(Uri.IsHexDigit))
            {
                throw new InvalidDataException($"Capability '{item.RouteId}' has incomplete or invalid route metadata.");
            }

            if (item.Status is not ("prototype" or "planned" or "in-progress" or "implemented"))
            {
                throw new InvalidDataException($"Capability '{item.RouteId}' has unknown migration status '{item.Status}'.");
            }
        }

        return document.Capabilities.AsReadOnly();
    }

    private sealed record CapabilityDocument(
        int SchemaVersion,
        string SourceBaseline,
        List<CapabilityDefinition> Capabilities);
}
