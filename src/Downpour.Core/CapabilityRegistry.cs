using System.Text.Json;
using System.Text.Json.Serialization;
using Downpour.Contracts;

namespace Downpour.Core;

public static class CapabilityRegistry
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public static IReadOnlyList<CapabilityDefinition> Load(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("The Downpour capability registry is missing.", path);
        }

        using var stream = File.OpenRead(path);
        var document = JsonSerializer.Deserialize<CapabilityDocument>(stream, JsonOptions)
            ?? throw new InvalidDataException("The Downpour capability registry is empty.");

        if (document.SchemaVersion != 1 || document.Capabilities.Count == 0)
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
