using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.UI;

namespace Downpour_Desktop.Pages;

/// <summary>
/// Read-only Task Scheduler view over the same persistence snapshot the Hunt route uses. The service reads every
/// folder including hidden tasks, and the extra per-task fields travel with the entry but not its baseline hash, so
/// opening this page never makes a task look modified.
/// </summary>
public sealed partial class ScheduledTasksPage : Page
{
    private const string AllStates = "All states";
    private static readonly string[] States = [AllStates, "Ready", "Running", "Disabled", "Queued", "Unknown"];
    private readonly PersistenceInventoryClient _client = new();
    private readonly ScheduledTaskActionClient _actions = new();
    private IReadOnlyList<PersistenceEntry> _tasks = [];
    private bool _requestInFlight;

    public LiveCollection<ScheduledTaskRow> Tasks { get; } = [];

    private readonly BreakdownChart _stateChart = new() { Title = "Tasks by state", Subtitle = "Including hidden tasks" };
    private readonly BreakdownChart _folderChart = new() { Title = "Tasks by folder", Subtitle = "Top-level Task Scheduler folder" };

    public ScheduledTasksPage()
    {
        InitializeComponent();
        Charts.Row(ChartRow, _stateChart, _folderChart);
        EntityDetails.Attach(TaskList, item => item is ScheduledTaskRow row ? row.ToDetail() : null);
        LiveRefresh.Attach(this, () => RefreshAsync(quiet: true));
        foreach (var state in States) StateFilter.Items.Add(state);
        StateFilter.SelectedIndex = 0;
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _ = RefreshAsync();
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();

    private void Filter_Changed(object sender, object e) => ApplyFilter();

    private async Task RefreshAsync(bool quiet = false)
    {
        if (_requestInFlight) return;
        _requestInFlight = true;
        if (!quiet) RefreshButton.IsEnabled = false;
        if (!quiet) StatusHeadline.Text = "Reading Task Scheduler";
        try
        {
            var snapshot = await _client.TryGetSnapshotAsync();
            if (snapshot is null)
            {
                await App.EnsureSensorServiceAsync();
                snapshot = await _client.TryGetSnapshotAsync();
            }

            if (snapshot is null)
            {
                _tasks = [];
                ApplyFilter();
                _stateChart.SetData(Enumerable.Empty<(string Label, double Value)>());
                _folderChart.SetData(Enumerable.Empty<(string Label, double Value)>());
                StatusHeadline.Text = "Downpour is running · persistence sensor offline";
                StatusDetail.Text = $"{App.SensorServiceStatusHint} Scheduled tasks are not cached or substituted.";
                return;
            }

            App.MarkSensorServiceConnected();
            _tasks = snapshot.Entries
                .Where(entry => entry.Category == PersistenceCategories.ScheduledTask)
                .ToArray();

            _stateChart.SetData(_tasks
                .GroupBy(task => task.TaskDetail?.State ?? "Unknown")
                .Select(group => (Label: group.Key, Value: (double)group.Count())),
                new Dictionary<string, Color>
                {
                    ["Running"] = Color.FromArgb(255, 120, 220, 160),
                    ["Ready"] = Color.FromArgb(255, 120, 200, 255),
                    ["Queued"] = Color.FromArgb(255, 255, 200, 100),
                    ["Disabled"] = Color.FromArgb(255, 150, 155, 170),
                    ["Unknown"] = Color.FromArgb(255, 170, 150, 200),
                });
            _folderChart.SetData(_tasks
                .GroupBy(task => FolderRoot(task.Location))
                .Select(group => (Label: group.Key, Value: (double)group.Count())));

            ApplyFilter();

            var ready = _tasks.Count(task => task.TaskDetail?.State == "Ready");
            var disabled = _tasks.Count(task => task.TaskDetail?.State == "Disabled");
            var hidden = _tasks.Count(task => task.TaskDetail?.Hidden == true);
            var recent = _tasks.Count(task => task.Change != PersistenceChanges.Baseline);
            StatusHeadline.Text = $"{_tasks.Count:N0} scheduled tasks · {ready:N0} ready · {disabled:N0} disabled · {hidden:N0} hidden · {recent:N0} new or changed";

            var baseline = snapshot.BaselineCreatedAtUtc is { } created ? $"Baseline since {created.ToLocalTime():yyyy-MM-dd HH:mm}." : "";
            var sources = snapshot.SourceStatus.Where(status => status.StartsWith("Scheduled tasks", StringComparison.OrdinalIgnoreCase));
            var warnings = snapshot.Warnings.Count == 0 ? "" : $" {string.Join(" ", snapshot.Warnings)}";
            StatusDetail.Text = $"{baseline} {string.Join(" · ", sources)}.{warnings}".Trim();
        }
        finally
        {
            _requestInFlight = false;
            RefreshButton.IsEnabled = true;
        }
    }

    private void ApplyFilter()
    {
        var query = SearchBox?.Text?.Trim() ?? "";
        var state = StateFilter?.SelectedItem as string;
        var hiddenOnly = HiddenOnly?.IsChecked == true;
        var matches = _tasks
            .Where(task =>
                (state is null || state == AllStates || (task.TaskDetail?.State ?? "Unknown") == state)
                && (!hiddenOnly || task.TaskDetail?.Hidden == true)
                && (query.Length == 0 || new[]
                {
                    task.Name, task.Location, task.Value,
                    task.TaskDetail?.RunAs ?? "", string.Join(" ", task.TaskDetail?.Triggers ?? Array.Empty<string>())
                }.Any(value => value.Contains(query, StringComparison.OrdinalIgnoreCase))))
            .OrderBy(task => task.TaskDetail?.State == "Disabled")
            .ThenBy(task => task.Location, StringComparer.OrdinalIgnoreCase)
            .ThenBy(task => task.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        Tasks.Clear();
        foreach (var task in matches) Tasks.Add(new ScheduledTaskRow(task));
        if (TaskCount is not null) TaskCount.Text = $"{matches.Length:N0} of {_tasks.Count:N0} tasks";
        if (EmptyState is not null)
        {
            EmptyState.Text = _tasks.Count == 0
                ? "No scheduled tasks were reported. Task Scheduler may be unavailable, or the service has not completed its first capture."
                : "No scheduled tasks match this filter.";
            EmptyState.Visibility = matches.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        }
    }

    private void RowMenu_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not ScheduledTaskRow row) return;
        var flyout = new MenuFlyout();

        var toggle = new MenuFlyoutItem
        {
            Text = row.State == "Disabled" ? "Enable task" : "Disable task",
            Tag = new ScheduledTaskCommand(row, row.State == "Disabled" ? ScheduledTaskActionKind.Enable : ScheduledTaskActionKind.Disable),
        };
        toggle.Click += TaskAction_Click;
        flyout.Items.Add(toggle);

        var delete = new MenuFlyoutItem
        {
            Text = "Delete task…",
            Tag = new ScheduledTaskCommand(row, ScheduledTaskActionKind.Delete),
        };
        delete.Click += TaskAction_Click;
        flyout.Items.Add(delete);

        flyout.ShowAt((FrameworkElement)sender);
    }

    private async void TaskAction_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is ScheduledTaskCommand command)
            await ApplyActionAsync(command);
    }

    private async Task ApplyActionAsync(ScheduledTaskCommand command)
    {
        var row = command.Row;
        var preview = await _actions.PreviewAsync(row.Path, command.Kind);
        if (preview is null)
        {
            await ShowMessageAsync("Task action service unavailable",
                "The Downpour service did not answer. Start or restart it, then try again. No change was made.");
            return;
        }

        if (!preview.Accepted || preview.Preview?.ConsentToken is not { } token)
        {
            await ShowMessageAsync("No change made", preview.Message);
            return;
        }

        var plan = preview.Preview;
        var isDelete = command.Kind == ScheduledTaskActionKind.Delete;
        var panel = new StackPanel { Spacing = 10, MaxWidth = 520 };
        panel.Children.Add(new TextBlock
        {
            Text = row.Path,
            FontFamily = new FontFamily("Consolas"),
            TextWrapping = TextWrapping.Wrap,
            IsTextSelectionEnabled = true,
        });
        panel.Children.Add(new TextBlock { Text = "What will happen", FontWeight = FontWeights.SemiBold });
        foreach (var effect in plan.ExpectedEffects)
            panel.Children.Add(new TextBlock { Text = "• " + effect, TextWrapping = TextWrapping.Wrap, FontSize = 12 });
        panel.Children.Add(new TextBlock { Text = "Risks", FontWeight = FontWeights.SemiBold });
        foreach (var risk in plan.Risks)
            panel.Children.Add(new TextBlock
            {
                Text = "• " + risk,
                TextWrapping = TextWrapping.Wrap,
                FontSize = 12,
            });
        panel.Children.Add(new TextBlock
        {
            Text = "Downpour records this confirmation and the result in its action audit log; Windows records the change in the Task Scheduler log.",
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap,
        });

        CheckBox? acknowledge = null;
        if (isDelete)
        {
            acknowledge = new CheckBox { Content = "I understand this permanently removes the task." };
            panel.Children.Add(acknowledge);
        }

        var dialog = new ContentDialog
        {
            Title = command.Kind switch
            {
                ScheduledTaskActionKind.Enable => "Enable scheduled task",
                ScheduledTaskActionKind.Disable => "Disable scheduled task",
                _ => "Delete scheduled task",
            },
            Content = new ScrollViewer { Content = panel, MaxHeight = 380 },
            PrimaryButtonText = command.Kind switch
            {
                ScheduledTaskActionKind.Enable => "Enable",
                ScheduledTaskActionKind.Disable => "Disable",
                _ => "Delete",
            },
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = XamlRoot,
        };

        if (acknowledge is not null)
        {
            dialog.IsPrimaryButtonEnabled = false;
            acknowledge.Checked += (_, _) => dialog.IsPrimaryButtonEnabled = true;
            acknowledge.Unchecked += (_, _) => dialog.IsPrimaryButtonEnabled = false;
        }

        if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;

        StatusHeadline.Text = isDelete ? "Removing task" : "Updating task";
        var result = await _actions.ExecuteAsync(row.Path, command.Kind, token);
        await RefreshAsync(quiet: true);
        StatusDetail.Text = result is null
            ? "The service did not answer. No change is assumed; check that the Downpour service is running."
            : $"{result.Message} {row.Path} The table updates on the next sensor capture.";
    }

    private async Task ShowMessageAsync(string title, string message)
    {
        await new ContentDialog
        {
            Title = title,
            Content = new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap },
            CloseButtonText = "Close",
            XamlRoot = XamlRoot,
        }.ShowAsync();
    }

    private static string FolderRoot(string location)
    {
        var trimmed = location.Trim('\\');
        if (trimmed.Length == 0) return @"\ (root)";
        var separator = trimmed.IndexOf('\\');
        return separator < 0 ? trimmed : trimmed[..separator];
    }
}

internal sealed record ScheduledTaskCommand(ScheduledTaskRow Row, ScheduledTaskActionKind Kind);

public sealed class ScheduledTaskRow(PersistenceEntry entry)
{
    private PersistenceTaskDetail? Detail => entry.TaskDetail;

    public string Name { get; } = Leaf(entry.Name);
    public string Path { get; } = entry.Name;
    public string Folder { get; } = entry.Location;
    public string State { get; } = entry.TaskDetail?.State ?? "Unknown";
    public string RunAs { get; } = Blank(entry.TaskDetail?.RunAs);
    public string RunLevel { get; } = Blank(entry.TaskDetail?.RunLevel);
    public string Author { get; } = Blank(entry.TaskDetail?.Author);
    public bool Hidden { get; } = entry.TaskDetail?.Hidden == true;
    public string Triggers { get; } = entry.TaskDetail?.Triggers is { Count: > 0 } triggers ? string.Join(" · ", triggers) : "—";
    public string NextRun { get; } = Format(entry.TaskDetail?.NextRunUtc);
    public string LastRun { get; } = Format(entry.TaskDetail?.LastRunUtc);
    public string LastResult { get; } = entry.TaskDetail?.LastResult is { } result ? result.ToString() : "—";
    public string Action { get; } = entry.Value;
    public string Indicators { get; } = entry.Indicators.Count == 0 ? "—" : string.Join(" · ", entry.Indicators);
    public string Change { get; } = entry.Change switch
    {
        PersistenceChanges.New => $"New {entry.ChangedAtUtc?.ToLocalTime():MM-dd}",
        PersistenceChanges.Modified => $"Changed {entry.ChangedAtUtc?.ToLocalTime():MM-dd}",
        _ => "",
    };

    public SolidColorBrush StateBrush => new(State switch
    {
        "Running" => Color.FromArgb(255, 120, 220, 160),
        "Ready" => Color.FromArgb(255, 120, 200, 255),
        "Queued" => Color.FromArgb(255, 255, 200, 100),
        "Disabled" => Color.FromArgb(255, 150, 155, 170),
        _ => Color.FromArgb(255, 170, 150, 200),
    });

    public SolidColorBrush ChangeBrush { get; } = new(entry.Change == PersistenceChanges.Modified
        ? Color.FromArgb(255, 255, 170, 90)
        : Color.FromArgb(255, 120, 200, 255));

    public DetailEntity ToDetail() => new(
        Name,
        $"{State} · {Folder}",
        [
            new("Task", Path),
            new("Folder", Folder),
            new("State", State),
            new("Run as", RunAs),
            new("Run level", RunLevel),
            new("Author", Author),
            new("Hidden", Hidden ? "Yes" : "No"),
            new("Triggers", Triggers),
            new("Next run", NextRun),
            new("Last run", LastRun),
            new("Last result", LastResult),
            new("Action", Action),
            new("Change", string.IsNullOrEmpty(Change) ? "Unchanged since the baseline" : Change),
            new("Indicators", Indicators),
        ],
        FilePath: PersistenceAnalyzer.LaunchTarget(entry),
        Kind: "scheduled task");

    private static string Leaf(string path)
    {
        var separator = path.LastIndexOf('\\');
        return separator >= 0 && separator < path.Length - 1 ? path[(separator + 1)..] : path;
    }

    private static string Blank(string? value) => string.IsNullOrWhiteSpace(value) ? "—" : value;

    private static string Format(DateTimeOffset? value) =>
        value is { } time && time.Year > 1900 ? time.ToLocalTime().ToString("yyyy-MM-dd HH:mm") : "—";
}
