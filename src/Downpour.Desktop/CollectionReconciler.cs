using System.Collections.ObjectModel;

namespace Downpour_Desktop;

/// <summary>Updates observable rows in place so periodic refreshes do not reset whole lists.</summary>
internal static class CollectionReconciler
{
    public static void Apply<T, TKey>(ObservableCollection<T> target, IReadOnlyList<T> desired,
        Func<T, TKey> keySelector, Action<T, T> update) where TKey : notnull
    {
        for (var destination = 0; destination < desired.Count; destination++)
        {
            var incoming = desired[destination];
            var key = keySelector(incoming);
            var existing = -1;
            for (var index = destination; index < target.Count; index++)
            {
                if (EqualityComparer<TKey>.Default.Equals(keySelector(target[index]), key))
                {
                    existing = index;
                    break;
                }
            }

            if (existing < 0)
                target.Insert(destination, incoming);
            else
            {
                var current = target[existing];
                update(current, incoming);
                if (existing != destination) target.Move(existing, destination);
            }
        }

        while (target.Count > desired.Count) target.RemoveAt(target.Count - 1);
    }
}
