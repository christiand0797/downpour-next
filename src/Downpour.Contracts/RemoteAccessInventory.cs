namespace Downpour.Contracts;

public sealed record RemoteAccessExposure(
    string Kind,
    string Vector,
    string Risk,
    string Description,
    int LocalPort,
    string RemoteEndpoint,
    int ProcessId,
    string ProcessName);

public sealed record RemoteAccessTool(int ProcessId, string ProcessName, string Category);

public sealed record RemoteAccessFinding(string Severity, string Technique, string Summary, string Indicator);

public sealed record RemoteAccessSnapshot(
    int SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    bool? RdpEnabled,
    bool? RdpNetworkLevelAuthentication,
    int? RdpPort,
    IReadOnlyList<RemoteAccessExposure> Exposures,
    IReadOnlyList<RemoteAccessTool> Tools,
    IReadOnlyList<RemoteAccessFinding> Findings,
    IReadOnlyList<string> Warnings);

public static class RemoteAccessKinds
{
    public const string Listener = "Listening";
    public const string Connection = "Connected";
    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal) { Listener, Connection };
}
