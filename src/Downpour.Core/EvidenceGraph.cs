namespace Downpour.Core;

public sealed record EvidenceNode(string Id, string Kind, string Label);

public sealed record EvidenceEdge(string From, string To, string Relation);

/// <summary>
/// A small in-memory graph over observations that already exist locally (process, file, connection, service, autorun,
/// driver, alert). It is deliberately not a database: the investigation view builds it from a bounded case snapshot,
/// so it cannot grow with the machine or retain evidence beyond the case. Edges require both endpoints, which keeps a
/// partial snapshot from producing dangling paths.
/// </summary>
public sealed class EvidenceGraph
{
    public const int MaximumNodes = 5_000;
    public const int MaximumEdges = 20_000;

    private readonly Dictionary<string, EvidenceNode> _nodes = new(StringComparer.Ordinal);
    private readonly List<EvidenceEdge> _edges = [];
    private readonly HashSet<(string From, string To, string Relation)> _edgeKeys = [];

    public IReadOnlyCollection<EvidenceNode> Nodes => _nodes.Values;
    public IReadOnlyList<EvidenceEdge> Edges => _edges;

    public bool AddNode(EvidenceNode node)
    {
        ArgumentNullException.ThrowIfNull(node);
        if (string.IsNullOrWhiteSpace(node.Id) || node.Id.Length > 256 || node.Kind.Length is 0 or > 32 || node.Label.Length > 512)
            throw new ArgumentException("The evidence node is outside its bounds.", nameof(node));
        if (_nodes.Count >= MaximumNodes) throw new InvalidOperationException("The evidence graph is at its node limit.");
        return _nodes.TryAdd(node.Id, node);
    }

    public bool AddEdge(EvidenceEdge edge)
    {
        ArgumentNullException.ThrowIfNull(edge);
        if (edge.Relation.Length is 0 or > 32) return false;
        if (!_nodes.ContainsKey(edge.From) || !_nodes.ContainsKey(edge.To) || edge.From == edge.To) return false;
        if (_edges.Count >= MaximumEdges || !_edgeKeys.Add((edge.From, edge.To, edge.Relation))) return false;
        _edges.Add(edge);
        return true;
    }

    public EvidenceNode? Find(string id) => _nodes.GetValueOrDefault(id);

    public IReadOnlyList<EvidenceEdge> EdgesFor(string nodeId) =>
        _edges.Where(edge => edge.From == nodeId || edge.To == nodeId).ToArray();

    /// <summary>Breadth-first expansion from one node, bounded by <paramref name="depth"/>.</summary>
    public IReadOnlyList<EvidenceNode> Reachable(string startId, int depth = 2)
    {
        if (depth is < 0 or > 4 || !_nodes.TryGetValue(startId, out var start)) return [];
        var seen = new HashSet<string>(StringComparer.Ordinal) { startId };
        var result = new List<EvidenceNode> { start };
        var frontier = new List<string> { startId };
        for (var level = 0; level < depth && frontier.Count > 0; level++)
        {
            var next = new List<string>();
            foreach (var id in frontier)
                foreach (var edge in EdgesFor(id))
                {
                    var other = edge.From == id ? edge.To : edge.From;
                    if (!seen.Add(other) || !_nodes.TryGetValue(other, out var node)) continue;
                    result.Add(node);
                    next.Add(other);
                }
            frontier = next;
        }
        return result;
    }
}
