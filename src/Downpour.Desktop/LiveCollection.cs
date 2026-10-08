using System.Collections;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Reflection;
using Microsoft.UI.Dispatching;

namespace Downpour_Desktop;

/// <summary>
/// Drop-in replacement for <see cref="ObservableCollection{T}"/> on pages that rebuild rows with Clear() then Add().
/// Clear() starts staging: page code sees the staged rows immediately (Count, indexer, enumeration on this type), while
/// the bound list keeps showing the previous rows until the current UI work item finishes and then receives only the
/// minimal changes. Unchanged rows are never touched, so a one-second refresh keeps scroll position, selection and focus.
/// Rows are compared by <see cref="RowSignature"/>.
/// </summary>
public sealed class LiveCollection<T> : ObservableCollection<T>
{
    private readonly List<string> _shownSignatures = [];
    private List<T>? _staged;
    private bool _applying;
    private bool _flushQueued;

    public new int Count => _staged?.Count ?? base.Count;

    public new T this[int index]
    {
        get => _staged is { } staged ? staged[index] : base[index];
        set => Stage()[index] = value;
    }

    public new void Add(T item) => Stage().Add(item);
    public new void Insert(int index, T item) => Stage().Insert(index, item);
    public new bool Remove(T item) => Stage().Remove(item);
    public new void RemoveAt(int index) => Stage().RemoveAt(index);
    public new bool Contains(T item) => _staged?.Contains(item) ?? base.Contains(item);
    public new int IndexOf(T item) => _staged?.IndexOf(item) ?? base.IndexOf(item);
    public new IEnumerator<T> GetEnumerator() => (_staged ?? [.. Items]).GetEnumerator();
    public void AddRange(IEnumerable<T> items) => Stage().AddRange(items);

    // Calls that arrive through the base class or the IList interfaces are staged too.
    protected override void ClearItems() { if (_applying) base.ClearItems(); else Stage().Clear(); }
    protected override void InsertItem(int index, T item) { if (_applying) base.InsertItem(index, item); else Stage().Insert(Math.Min(index, Stage().Count), item); }
    protected override void RemoveItem(int index) { if (_applying) base.RemoveItem(index); else Stage().RemoveAt(index); }
    protected override void SetItem(int index, T item) { if (_applying) base.SetItem(index, item); else Stage()[index] = item; }
    protected override void MoveItem(int oldIndex, int newIndex)
    {
        if (_applying) { base.MoveItem(oldIndex, newIndex); return; }
        var staged = Stage();
        var item = staged[oldIndex];
        staged.RemoveAt(oldIndex);
        staged.Insert(newIndex, item);
    }

    private List<T> Stage()
    {
        if (_staged is null)
        {
            _staged = [.. Items];
            if (!_flushQueued)
            {
                _flushQueued = true;
                // Runs after the page finishes its current synchronous update; applies immediately off the UI thread.
                if (DispatcherQueue.GetForCurrentThread() is not { } queue || !queue.TryEnqueue(DispatcherQueuePriority.Low, Flush)) Flush();
            }
        }
        return _staged;
    }

    /// <summary>Applies staged rows now (normally automatic).</summary>
    public void Flush()
    {
        _flushQueued = false;
        if (_staged is not { } desired) return;
        _staged = null;
        while (_shownSignatures.Count < Items.Count) _shownSignatures.Add(RowSignature.Of(Items[_shownSignatures.Count]));
        var desiredSignatures = desired.Select(item => RowSignature.Of(item)).ToList();
        _applying = true;
        try
        {
            for (var i = 0; i < desired.Count; i++)
            {
                var signature = desiredSignatures[i];
                if (i < Items.Count && _shownSignatures[i] == signature) continue;
                var later = i + 1 < _shownSignatures.Count ? _shownSignatures.IndexOf(signature, i + 1) : -1;
                if (later > i)
                {
                    base.MoveItem(later, i);
                    _shownSignatures.RemoveAt(later);
                    _shownSignatures.Insert(i, signature);
                }
                else if (i < Items.Count && desiredSignatures.IndexOf(_shownSignatures[i], i + 1) < 0)
                {
                    // The row here is gone and the new one is new: replace in place (keeps the scroll anchor).
                    base.SetItem(i, desired[i]);
                    _shownSignatures[i] = signature;
                }
                else
                {
                    base.InsertItem(i, desired[i]);
                    _shownSignatures.Insert(i, signature);
                }
            }
            while (Items.Count > desired.Count)
            {
                base.RemoveItem(Items.Count - 1);
                _shownSignatures.RemoveAt(_shownSignatures.Count - 1);
            }
        }
        finally
        {
            _applying = false;
        }
    }
}

/// <summary>Content signature of a row: its readable public scalar properties (strings, numbers, dates, enums, booleans).</summary>
public static class RowSignature
{
    private static readonly ConcurrentDictionary<Type, PropertyInfo[]> Properties = new();

    public static string Of(object? row)
    {
        if (row is null) return "\0null";
        if (row is string or ValueType) return row.ToString() ?? "";
        var properties = Properties.GetOrAdd(row.GetType(), type => type
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.CanRead && p.GetIndexParameters().Length == 0 && IsScalar(p.PropertyType))
            .OrderBy(p => p.Name, StringComparer.Ordinal)
            .ToArray());
        if (properties.Length == 0) return row.ToString() ?? "";
        var parts = new string[properties.Length];
        for (var i = 0; i < properties.Length; i++)
        {
            try { parts[i] = Convert.ToString(properties[i].GetValue(row), System.Globalization.CultureInfo.InvariantCulture) ?? ""; }
            catch (TargetInvocationException) { parts[i] = "?"; }
        }
        return string.Join('\u001f', parts);
    }

    private static bool IsScalar(Type type)
    {
        type = Nullable.GetUnderlyingType(type) ?? type;
        return type.IsPrimitive || type.IsEnum || type == typeof(string) || type == typeof(decimal) ||
               type == typeof(DateTime) || type == typeof(DateTimeOffset) || type == typeof(TimeSpan) || type == typeof(Guid);
    }
}

/// <summary>
/// One-second live refresh for a page while it is on screen and the window is visible. A tick is skipped while the
/// previous refresh is still running, so slow sources never pile up requests.
/// </summary>
public static class LiveRefresh
{
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(1);

    public static void Attach(Microsoft.UI.Xaml.FrameworkElement page, Func<Task> refresh)
    {
        var timer = new Microsoft.UI.Xaml.DispatcherTimer { Interval = Interval };
        var running = false;
        timer.Tick += async (_, _) =>
        {
            if (running || !App.IsMainWindowVisible) return;
            running = true;
            try { await refresh(); }
            catch (Exception ex) when (ex is OperationCanceledException or IOException or InvalidOperationException) { }
            finally { running = false; }
        };
        page.Loaded += (_, _) => timer.Start();
        page.Unloaded += (_, _) => timer.Stop();
    }
}

/// <summary>Binds plain row arrays through a <see cref="LiveCollection{T}"/> so repeated refreshes update in place.</summary>
public static class LiveList
{
    public static void Set(object control, System.Collections.IEnumerable? items)
    {
        LiveCollection<object>? target = control switch
        {
            Microsoft.UI.Xaml.Controls.ItemsControl list => list.ItemsSource as LiveCollection<object>,
            Microsoft.UI.Xaml.Controls.ItemsRepeater repeater => repeater.ItemsSource as LiveCollection<object>,
            _ => throw new ArgumentException("Unsupported list control.", nameof(control)),
        };
        var fresh = target is null;
        target ??= new LiveCollection<object>();
        target.Clear();
        if (items is not null) foreach (var item in items) target.Add(item!);
        if (!fresh) return;
        target.Flush();
        if (control is Microsoft.UI.Xaml.Controls.ItemsControl itemsControl) itemsControl.ItemsSource = target;
        else ((Microsoft.UI.Xaml.Controls.ItemsRepeater)control).ItemsSource = target;
    }
}
