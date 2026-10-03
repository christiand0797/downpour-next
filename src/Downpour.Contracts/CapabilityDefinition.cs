namespace Downpour.Contracts;

public sealed record CapabilityDefinition(
    string RouteId,
    string Group,
    string Title,
    string Icon,
    string SourceMethod,
    string Status,
    string Description);
