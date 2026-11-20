namespace Downpour.Core;

public enum LocalChangeArea
{
    Autorun,
    Service,
    ScheduledTask,
    Driver,
    ListeningPort,
    HostsEntry,
    DefenderSetting,
    NetworkDestination,
}

public enum LocalChangeKind { Removed, Added }

public sealed record LocalChange(LocalChangeArea Area, string Key, string Detail, LocalChangeKind Kind);

/// <summary>
/// Turns two collections of collected local facts into a ranked "what changed" list. Additions outrank removals and
/// persistence areas outrank observations, because a new autorun or service is what an intrusion usually needs.
/// This is presentation logic over data the sensors already collect; it makes no verdict about intent.
/// </summary>
public static class LocalChangeDigest
{
    public static IReadOnlyList<LocalChange> Compare(LocalChangeArea area, IEnumerable<string> previous, IEnumerable<string> current)
    {
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(current);
        var before = new HashSet<string>(previous.Where(v => !string.IsNullOrWhiteSpace(v)), StringComparer.OrdinalIgnoreCase);
        var after = new HashSet<string>(current.Where(v => !string.IsNullOrWhiteSpace(v)), StringComparer.OrdinalIgnoreCase);
        return before.Except(after).Select(key => new LocalChange(area, key, "", LocalChangeKind.Removed))
            .Concat(after.Except(before).Select(key => new LocalChange(area, key, "", LocalChangeKind.Added)))
            .OrderByDescending(Weight)
            .ThenBy(change => change.Key, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static IReadOnlyList<LocalChange> Rank(IEnumerable<LocalChange> changes) =>
        changes.OrderByDescending(Weight).ThenBy(change => change.Key, StringComparer.OrdinalIgnoreCase).ToArray();

    private static int Weight(LocalChange change) =>
        (change.Kind is LocalChangeKind.Added ? 2 : 1) * (change.Area switch
        {
            LocalChangeArea.Driver => 5,
            LocalChangeArea.Autorun or LocalChangeArea.Service or LocalChangeArea.ScheduledTask => 4,
            LocalChangeArea.DefenderSetting => 3,
            LocalChangeArea.HostsEntry or LocalChangeArea.ListeningPort => 2,
            _ => 1,
        });
}
