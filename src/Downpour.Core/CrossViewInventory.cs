namespace Downpour.Core;

public sealed record InventoryView(string Name, IReadOnlySet<string> Artifacts);

public sealed record InventoryAnomaly(string Artifact, string Detail, string Confidence);

/// <summary>
/// Compares two independent enumerations of the same thing (SCM versus registry for services, loaded modules versus
/// driver registry keys for drivers, two TCP table APIs for ports). An artifact visible in one view and not the other is
/// a consistency anomaly that deserves review; it is not proof of a rootkit, and the wording says so. Artifacts that are
/// known to legitimately differ between views are supplied by the caller and never reported.
/// </summary>
public static class CrossViewInventory
{
    public const int MaximumArtifacts = 20_000;
    public const int MaximumAnomalies = 200;

    public static IReadOnlyList<InventoryAnomaly> Compare(
        InventoryView primary,
        InventoryView secondary,
        IReadOnlySet<string>? knownDifferences = null)
    {
        ArgumentNullException.ThrowIfNull(primary);
        ArgumentNullException.ThrowIfNull(secondary);
        if (primary.Artifacts.Count > MaximumArtifacts || secondary.Artifacts.Count > MaximumArtifacts)
            throw new InvalidOperationException("The inventory views exceed the supported bound.");
        var anomalies = new List<InventoryAnomaly>();
        void Add(string artifact, string detail)
        {
            if (anomalies.Count >= MaximumAnomalies) return;
            if (knownDifferences is not null && knownDifferences.Contains(artifact)) return;
            anomalies.Add(new InventoryAnomaly(artifact, detail, "Consistency anomaly, not proof of tampering"));
        }

        foreach (var artifact in primary.Artifacts)
            if (!secondary.Artifacts.Contains(artifact))
                Add(artifact, $"Present in {primary.Name} but not in {secondary.Name}.");
        foreach (var artifact in secondary.Artifacts)
            if (!primary.Artifacts.Contains(artifact))
                Add(artifact, $"Present in {secondary.Name} but not in {primary.Name}.");
        return anomalies.OrderBy(anomaly => anomaly.Artifact, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public static string Summarize(IReadOnlyList<InventoryAnomaly> anomalies, string kind) => anomalies.Count == 0
        ? $"Both {kind} views agree."
        : $"{anomalies.Count:N0} {kind} artifact(s) appear in only one view. Review them as a consistency anomaly; a single differing enumeration is not evidence of a rootkit.";
}
