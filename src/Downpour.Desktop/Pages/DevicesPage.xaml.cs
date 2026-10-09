using System.Collections.ObjectModel;
using System.Diagnostics;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;

namespace Downpour_Desktop.Pages;

/// <summary>
/// Devices &amp; Drivers: device health with explained problem codes, missing drivers, driver age and signers, a
/// read-only Windows Update driver search, and hand-offs to Windows' own Optional updates and Device Manager for
/// changes (which elevate themselves). Charts come from this page's own data.
/// </summary>
public sealed partial class DevicesPage : Page
{
    private readonly DeviceClient _client = new();
    private readonly BreakdownChart _healthChart = new() { Title = "Device health", Subtitle = "Connected devices by driver status" };
    private readonly TopBarsChart _classChart = new() { Title = "Devices by class", Subtitle = "Connected devices per Device Manager class" };
    private readonly TopBarsChart _ageChart = new() { Title = "Oldest drivers", Subtitle = "Years since the driver was released" };
    private DeviceInventorySnapshot? _snapshot;
    private string _structure = "";
    private bool _busy;

    public ObservableCollection<PnpDeviceRow> Rows { get; } = [];

    public DevicesPage()
    {
        InitializeComponent();
        Charts.Row(ChartRow, _healthChart, _classChart, _ageChart);
        EntityDetails.Attach(DeviceList, item => item is PnpDeviceRow r ? DescribeDevice(r.Device) : null);
        LiveRefresh.Attach(this, () => RefreshAsync());
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _ = RefreshAsync(ensureService: true);
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync(ensureService: true);

    private async void Search_Click(object sender, RoutedEventArgs e)
    {
        SearchButton.IsEnabled = false;
        var response = await _client.SearchUpdatesAsync();
        UpdatesStatus.Text = response switch
        {
            null => _client.LastFailure ?? "The sensor service did not answer.",
            { ResultCode: "already-searching" } => "A search is already running.",
            _ => "Searching Windows Update for driver updates… this usually takes under a minute.",
        };
        await RefreshAsync();
    }

    /// <summary>Windows' own tools for driver changes (fixed targets; nothing user-supplied is run).</summary>
    private void DeviceManager_Click(object sender, RoutedEventArgs e) => OpenDeviceManager();

    private static void OpenDeviceManager()
    {
        try { Process.Start(new ProcessStartInfo("devmgmt.msc") { UseShellExecute = true })?.Dispose(); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException) { }
    }

    private async void InstallDrivers_Click(object sender, RoutedEventArgs e) => await InstallDriversAsync();

    private async Task InstallDriversAsync()
    {
        InstallDriversButton.IsEnabled = false;
        try
        {
            var result = await UpdateRunner.RunAsync(XamlRoot, "drivers", text => UpdatesStatus.Text = text);
            if (result is not null)
            {
                await _client.SearchUpdatesAsync();
                await RefreshAsync();
                UpdatesStatus.Text = FixerClient.Describe(result);
            }
        }
        finally { InstallDriversButton.IsEnabled = true; }
    }

    private static async Task OpenSettings(string uri) => await Windows.System.Launcher.LaunchUriAsync(new Uri(uri));

    private void Filter_Changed(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args) => ApplyFilter();

    private void ClassFilter_Changed(object sender, SelectionChangedEventArgs e) => ApplyFilter();

    private async Task RefreshAsync(bool ensureService = false)
    {
        if (_busy) return;
        _busy = true;
        try
        {
            var response = await _client.GetSnapshotAsync();
            if (response?.Snapshot is null && ensureService)
            {
                await App.EnsureSensorServiceAsync();
                response = await _client.GetSnapshotAsync();
            }
            if (response?.Snapshot is not { } snapshot)
            {
                SummaryHeadline.Text = "Device information is unavailable";
                SummaryDetail.Text = _client.LastFailure ?? "The local sensor service did not answer.";
                return;
            }
            _snapshot = snapshot;
            Render(snapshot);
        }
        finally
        {
            _busy = false;
        }
    }

    private void Render(DeviceInventorySnapshot s)
    {
        var connected = s.Devices.Where(d => d.Present).ToArray();
        var problems = DeviceAnalyzer.Problems(s.Devices);
        var missing = problems.Count(p => p.MissingDriver);
        var serious = problems.Count(p => p.Severity != "LOW");

        SummaryHeadline.Text = serious == 0
            ? $"All {connected.Length:N0} connected devices are working"
            : $"{serious} device{(serious == 1 ? "" : "s")} need{(serious == 1 ? "s" : "")} attention{(missing > 0 ? $", {missing} missing a driver" : "")}";
        SummaryDetail.Text = $"{s.Devices.Count:N0} devices known to Windows, {connected.Length:N0} connected. Updated {s.CapturedAtUtc.ToLocalTime():T}."
            + (s.Warnings.Count > 0 ? " " + string.Join(" ", s.Warnings) : "");
        SummaryIcon.Foreground = HudPalette.Resource(serious == 0 ? "HudGreenBrush" : missing > 0 ? "HudOrangeBrush" : "HudAmberBrush");

        _healthChart.SetData(
        [
            ("Working", connected.Count(d => DeviceAnalyzer.Problem(d) is null)),
            ("Missing driver", problems.Count(p => p.MissingDriver && p.Device.Present)),
            ("Problem", problems.Count(p => !p.MissingDriver && p.Severity != "LOW" && p.Device.Present)),
            ("Disabled or idle", problems.Count(p => p.Severity == "LOW" && p.Device.Present)),
        ], new Dictionary<string, Windows.UI.Color>
        {
            ["Working"] = HudPalette.Good, ["Missing driver"] = HudPalette.Serious, ["Problem"] = HudPalette.Warning, ["Disabled or idle"] = HudPalette.Other,
        });
        _classChart.SetData(connected.GroupBy(d => d.Class).Select(g => (g.Key, (double)g.Count())), "", HudPalette.Categorical[1]);
        var now = DateTimeOffset.UtcNow;
        _ageChart.SetData(connected.Where(d => d.DriverProvider is not null && !d.DriverProvider.Equals("Microsoft", StringComparison.OrdinalIgnoreCase))
                .Select(d => (d.Name, (double)(DeviceAnalyzer.AgeYears(d, now) ?? 0))), " yr",
            colorFor: years => years >= 5 ? HudPalette.Serious : years >= 3 ? HudPalette.Warning : HudPalette.Categorical[0]);

        var structure = string.Join("|", problems.Select(p => p.Device.InstanceId + p.Device.ProblemCode)) + "#" + s.UpdateSearchState + s.Updates.Count + s.UpdatesCheckedAtUtc + "#" + s.Devices.Count
            + "#" + s.SystemManufacturer + s.BoardManufacturer + string.Join(",", s.VendorTools ?? []);
        if (structure == _structure) return;
        _structure = structure;
        RenderProblems(problems.Where(p => p.Device.Present || p.MissingDriver).ToArray());
        RenderSources(s);
        RenderChecks(s);
        RenderUpdates(s);
        RebuildClassFilter(s);
        ApplyFilter();
    }

    private void RenderProblems(IReadOnlyList<DeviceProblem> problems)
    {
        ProblemsPanel.Children.Clear();
        ProblemsEmpty.Visibility = problems.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        foreach (var p in problems.Take(60))
        {
            var body = new StackPanel { Spacing = 3 };
            body.Children.Add(new TextBlock { Text = $"{p.Device.Name} — {p.Title}", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            body.Children.Add(new TextBlock { Text = $"{p.Explanation} {p.Fix}", FontSize = 12, Foreground = HudPalette.Resource("HudTextDimBrush"), TextWrapping = TextWrapping.Wrap });
            body.Children.Add(new TextBlock
            {
                Text = $"{p.Device.Class} · {p.Device.Manufacturer} · driver {(p.Device.DriverProvider is null ? "none" : $"{p.Device.DriverProvider} {p.Device.DriverVersion}")}",
                FontSize = 11, Foreground = HudPalette.Resource("HudTextFaintBrush"), TextWrapping = TextWrapping.Wrap,
            });
            var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 4, 0, 0) };
            if (p.MissingDriver || p.Device.ProblemCode is 1 or 10 or 18 or 31 or 37 or 39 or 43 or 48 or 52)
                actions.Children.Add(Action("Find and install driver", InstallDriversAsync));
            actions.Children.Add(Action("Details", () => EntityDetails.ShowAsync(XamlRoot, DescribeDevice(p.Device))));
            body.Children.Add(actions);
            var tone = HudPalette.Severity(p.Severity) is { } c ? new SolidColorBrush(c) : HudPalette.Resource("HudAmberBrush");
            ProblemsPanel.Children.Add(Card(p.MissingDriver ? "NO DRIVER" : p.Severity, tone, body));
        }
    }

    /// <summary>Opens a maker page from the fixed, verified table in <see cref="DriverSourceAdvisor"/> (never a URL from data).</summary>
    private static Task OpenOfficial(DriverSource source) => Windows.System.Launcher.LaunchUriAsync(new Uri(source.Url)).AsTask();

    private void RenderSources(DeviceInventorySnapshot s)
    {
        SourcesPanel.Children.Clear();
        var system = string.Join(" ", new[] { s.SystemManufacturer, s.SystemModel }.Where(t => !string.IsNullOrWhiteSpace(t)));
        var board = string.Join(" ", new[] { s.BoardManufacturer, s.BoardProduct }.Where(t => !string.IsNullOrWhiteSpace(t)));
        SourcesPanel.Children.Add(new TextBlock
        {
            Text = $"This PC: {(system.Length > 0 ? system : "maker not reported")}{(board.Length > 0 ? $"  ·  Motherboard: {board}" : "")}",
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap,
        });
        var makers = new[] { DriverSourceAdvisor.MakerSource(s.SystemManufacturer), DriverSourceAdvisor.MakerSource(s.BoardManufacturer) }
            .OfType<DriverSource>().DistinctBy(m => m.Url).ToArray();
        var chips = s.Devices.Where(d => d.Present).Select(DriverSourceAdvisor.ChipMaker).Where(c => c?.Source is not null)
            .Select(c => c!.Value.Source!).DistinctBy(c => c.Url).ToArray();
        var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        foreach (var source in makers.Concat(chips).Take(6))
        {
            var button = Action(source.IsPcMaker ? source.Name : $"{source.Name} drivers", () => OpenOfficial(source));
            ToolTipService.SetToolTip(button, $"{source.Why} Opens {source.Url}");
            actions.Children.Add(button);
        }
        if (actions.Children.Count > 0) SourcesPanel.Children.Add(actions);
        else SourcesPanel.Children.Add(new TextBlock { Text = "No maker-specific driver source was recognised; use Windows Update and Device Manager.", FontSize = 12, Foreground = HudPalette.Resource("HudTextDimBrush") });
        SourcesPanel.Children.Add(new TextBlock
        {
            Text = s.VendorTools is { Count: > 0 } tools
                ? $"Official updater apps already installed: {string.Join(", ", tools)}. They know your exact hardware and are the easiest way to update these drivers."
                : "No official maker updater app was found. The maker pages above find the right drivers for your exact model.",
            FontSize = 12, Foreground = HudPalette.Resource("HudTextDimBrush"), TextWrapping = TextWrapping.Wrap,
        });
    }

    private void RenderChecks(DeviceInventorySnapshot s)
    {
        ChecksPanel.Children.Clear();
        var checks = DriverSourceAdvisor.Checks(s.Devices, s.SystemManufacturer, s.BoardManufacturer, DateTimeOffset.UtcNow);
        ChecksStatus.Text = checks.Count == 0
            ? "No third-party drivers look out of date (graphics older than six months or other drivers older than three years)."
            : $"{checks.Count} driver{(checks.Count == 1 ? "" : "s")} may have a newer version from the maker. Windows Update often does not carry these.";
        foreach (var c in checks)
        {
            var body = new StackPanel { Spacing = 3 };
            body.Children.Add(new TextBlock { Text = c.Label ?? c.Device.Name, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            body.Children.Add(new TextBlock { Text = $"{c.Device.DriverProvider} {c.Device.DriverVersion} · released {c.Device.DriverDate:yyyy-MM-dd}. {c.Reason}", FontSize = 12, Foreground = HudPalette.Resource("HudTextDimBrush"), TextWrapping = TextWrapping.Wrap });
            body.Children.Add(new TextBlock { Text = c.Sources[0].Why, FontSize = 11, Foreground = HudPalette.Resource("HudTextFaintBrush"), TextWrapping = TextWrapping.Wrap });
            var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 4, 0, 0) };
            foreach (var source in c.Sources.Take(3)) actions.Children.Add(Action($"Get from {source.Name}", () => OpenOfficial(source)));
            body.Children.Add(actions);
            var tone = c.Device.Class.Equals("Display", StringComparison.OrdinalIgnoreCase) ? HudPalette.Resource("HudVioletBrush") : HudPalette.Resource("HudBlueBrush");
            ChecksPanel.Children.Add(Card(c.AgeYears is { } years && years > 0 ? $"{years} YR OLD" : "CHECK", tone, body));
        }
    }

    private void RenderUpdates(DeviceInventorySnapshot s)
    {
        UpdatesPanel.Children.Clear();
        UpdatesStatus.Text = s.UpdateSearchState switch
        {
            UpdateSearchStates.Searching => "Searching Windows Update for driver updates…",
            UpdateSearchStates.Failed => s.UpdateSearchError ?? "The search failed.",
            UpdateSearchStates.Done when s.Updates.Count == 0 => $"Windows Update has no driver updates for this PC (checked {s.UpdatesCheckedAtUtc?.ToLocalTime():t}).",
            UpdateSearchStates.Done => $"{s.Updates.Count} driver update{(s.Updates.Count == 1 ? "" : "s")} available (checked {s.UpdatesCheckedAtUtc?.ToLocalTime():t}). Select Install driver updates and Downpour installs them.",
            _ => "Not checked yet. Check for driver updates, or Install driver updates to find and install them in one step.",
        };
        SearchButton.IsEnabled = s.UpdateSearchState != UpdateSearchStates.Searching;
        foreach (var offer in s.Updates)
        {
            var targets = DeviceAnalyzer.Targets(offer, s.Devices);
            var body = new StackPanel { Spacing = 3 };
            body.Children.Add(new TextBlock { Text = offer.Title, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            body.Children.Add(new TextBlock
            {
                Text = $"{offer.DriverProvider ?? offer.DriverManufacturer ?? "Unknown provider"} · {offer.DriverClass ?? "driver"} · released {offer.DriverDate?.ToLocalTime():d}"
                    + (offer.MaximumDownloadBytes is { } size && size > 0 ? $" · up to {size / 1048576.0:0.#} MB" : ""),
                FontSize = 12, Foreground = HudPalette.Resource("HudTextDimBrush"), TextWrapping = TextWrapping.Wrap,
            });
            body.Children.Add(new TextBlock
            {
                Text = targets.Count == 0 ? "Applies to hardware Windows Update detected on this PC." : "For: " + string.Join(", ", targets.Select(t => $"{t.Name} (now {t.DriverVersion ?? "no driver"})")),
                FontSize = 11, Foreground = HudPalette.Resource("HudTextFaintBrush"), TextWrapping = TextWrapping.Wrap,
            });
            var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 4, 0, 0) };
            actions.Children.Add(Action("Install", InstallDriversAsync));
            body.Children.Add(actions);
            UpdatesPanel.Children.Add(Card("UPDATE", HudPalette.Resource("HudCyanBrush"), body));
        }
    }

    private void RebuildClassFilter(DeviceInventorySnapshot s)
    {
        var selected = ClassFilter.SelectedItem as string;
        var classes = new List<string> { "All classes" };
        classes.AddRange(s.Devices.Select(d => d.Class).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(c => c, StringComparer.OrdinalIgnoreCase));
        ClassFilter.ItemsSource = classes;
        ClassFilter.SelectedItem = selected is not null && classes.Contains(selected) ? selected : classes[0];
    }

    private void ApplyFilter()
    {
        if (_snapshot is null) return;
        var query = SearchBox.Text?.Trim() ?? "";
        var cls = ClassFilter.SelectedItem as string;
        var rows = _snapshot.Devices
            .Where(d => cls is null or "All classes" || d.Class.Equals(cls, StringComparison.OrdinalIgnoreCase))
            .Where(d => query.Length == 0 || $"{d.Name} {d.Class} {d.Manufacturer} {d.DriverProvider} {d.DriverVersion}".Contains(query, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(d => d.Present).ThenBy(d => d.Class, StringComparer.OrdinalIgnoreCase).ThenBy(d => d.Name, StringComparer.OrdinalIgnoreCase)
            .Take(1200)
            .Select(d => new PnpDeviceRow(d))
            .ToArray();
        Rows.Clear();
        foreach (var row in rows) Rows.Add(row);
        ListCount.Text = $"Showing {rows.Length:N0} of {_snapshot.Devices.Count:N0} devices";
    }

    private DetailEntity DescribeDevice(DeviceEntry d)
    {
        var problem = DeviceAnalyzer.Problem(d);
        var chip = DriverSourceAdvisor.ChipMaker(d);
        var sources = DriverSourceAdvisor.SourcesFor(d, _snapshot?.SystemManufacturer, _snapshot?.BoardManufacturer);
        return new DetailEntity(d.Name, $"{d.Class} · {(d.Present ? "connected" : "not connected")}",
        [
            new("Status", problem is null ? "Working" : $"{problem.Title}: {problem.Explanation} {problem.Fix}"),
            new("Class", d.Class), new("Manufacturer", d.Manufacturer), new("Chip maker (from hardware ID)", chip?.Maker ?? "Not recognised"),
            new("Driver", d.DriverProvider is null ? "No driver information" : $"{d.DriverProvider} {d.DriverVersion}"),
            new("Driver date", d.DriverDate?.ToString("yyyy-MM-dd") ?? ""), new("INF", d.InfName ?? ""),
            new("Signed by", d.DriverSigned == false ? "NOT signed" : d.DriverSigner ?? ""), new("Hardware ID", d.HardwareId ?? ""), new("Instance ID", d.InstanceId),
            new("Where to get drivers", sources.Count == 0 ? "Windows Update and Device Manager" : string.Join("; ", sources.Select(s => $"{s.Name} ({s.Url})"))),
        ], FilePath: d.InfName is { Length: > 0 } inf ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "INF", inf) : null, Kind: "device");
    }

    private static Button Action(string text, Func<Task> run)
    {
        var button = new Button { Content = text, FontSize = 12, Padding = new Thickness(10, 4, 10, 4) };
        button.Click += async (_, _) =>
        {
            button.IsEnabled = false;
            try { await run(); }
            finally { button.IsEnabled = true; }
        };
        return button;
    }

    private static Border Card(string chip, Brush tone, UIElement body)
    {
        var grid = new Grid { ColumnSpacing = 14 };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.Children.Add(new Border
        {
            Padding = new Thickness(8, 3, 8, 3), CornerRadius = new CornerRadius(4), BorderThickness = new Thickness(1), BorderBrush = tone,
            VerticalAlignment = VerticalAlignment.Top, MinWidth = 76,
            Child = new TextBlock { Text = chip, FontSize = 11, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, Foreground = tone, HorizontalAlignment = HorizontalAlignment.Center },
        });
        Grid.SetColumn((FrameworkElement)body, 1);
        grid.Children.Add(body);
        return new Border
        {
            Padding = new Thickness(14, 10, 14, 10), CornerRadius = new CornerRadius(8), BorderThickness = new Thickness(3, 1, 1, 1),
            BorderBrush = tone, Background = HudPalette.Resource("HudPanelBrush"), Child = grid,
        };
    }
}

public sealed class PnpDeviceRow(DeviceEntry device)
{
    public DeviceEntry Device { get; } = device;
    public string Name { get; } = device.Name;
    public string Manufacturer { get; } = device.Manufacturer;
    public string Class { get; } = device.Class;
    public string State { get; } = !device.Present ? "Not connected"
        : DeviceAnalyzer.Problem(device) is { } p ? p.Title : "Working";
    public Brush StateBrush { get; } = HudPalette.Resource(!device.Present ? "HudTextFaintBrush"
        : DeviceAnalyzer.Problem(device) is { } p ? (p.MissingDriver ? "HudOrangeBrush" : p.Severity == "LOW" ? "HudTextDimBrush" : "HudAmberBrush") : "HudGreenBrush");
    public string Driver { get; } = device.DriverProvider is null ? "No driver information"
        : $"{device.DriverProvider} {device.DriverVersion}{(device.DriverDate is { } d ? $" · {d:yyyy-MM-dd}" : "")}";
    public string Signer { get; } = device.DriverSigned == false ? "NOT signed" : device.DriverSigner ?? "";

    public override string ToString() => $"{Name}, {Class}, {State}";
}
