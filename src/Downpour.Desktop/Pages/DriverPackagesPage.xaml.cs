using System.Collections.ObjectModel;
using System.Linq;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed partial class DriverPackagesPage : Page
{
    private readonly DriverPackageInventoryClient _client = new();
    private IReadOnlyList<DriverPackageEntry> _packages = [];
    private bool _requestInFlight;

    public LiveCollection<DriverPackageRow> VisiblePackages { get; } = [];

    private readonly BreakdownChart _signatureChart = new() { Title = "Signatures", Subtitle = "Catalog signature status of each package" };
    private readonly TopBarsChart _classChart = new() { Title = "By device class", Subtitle = "Driver packages per class" };
    private readonly TopBarsChart _providerChart = new() { Title = "By provider", Subtitle = "Who supplied the packages" };

    public DriverPackagesPage()
    {
        InitializeComponent();
        Charts.Row(ChartRow, _signatureChart, _classChart, _providerChart);
        LiveRefresh.Attach(this, () => RefreshAsync(quiet: true));
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _ = RefreshAsync();
    }

    private async void RefreshButton_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) => await RefreshAsync();

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilter();

    private async Task RefreshAsync(bool quiet = false)
    {
        if (_requestInFlight) return;
        _requestInFlight = true;
        if (!quiet) RefreshButton.IsEnabled = false;
        if (!quiet) StatusText.Text = "Enumerating driver packages from the Driver Store…";
        try
        {
            var snapshot = await _client.TryGetSnapshotAsync();
            if (snapshot is null)
            {
                StatusText.Text = "Driver package inventory is unavailable.";
                return;
            }
            _packages = snapshot.Packages;
            _signatureChart.SetData(
            [
                ("Signed", snapshot.Packages.Count(p => p.IsSigned)),
                ("Unknown", snapshot.Packages.Count(p => !p.IsSigned && p.SignatureStatus?.StartsWith("Unknown", StringComparison.Ordinal) == true)),
                ("Unsigned or untrusted", snapshot.Packages.Count(p => !p.IsSigned && p.SignatureStatus?.StartsWith("Unknown", StringComparison.Ordinal) != true)),
            ], new Dictionary<string, Windows.UI.Color> { ["Signed"] = HudPalette.Good, ["Unknown"] = HudPalette.Other, ["Unsigned or untrusted"] = HudPalette.Serious });
            _classChart.SetData(snapshot.Packages.GroupBy(p => string.IsNullOrWhiteSpace(p.DriverClass) ? "(none)" : p.DriverClass).Select(g => (g.Key, (double)g.Count())), "", HudPalette.Categorical[1]);
            _providerChart.SetData(snapshot.Packages.GroupBy(p => string.IsNullOrWhiteSpace(p.ProviderName) ? "(unknown)" : p.ProviderName).Select(g => (g.Key, (double)g.Count())), "", HudPalette.Categorical[3]);
            var captured = snapshot.CapturedAtUtc.ToLocalTime();
            var warningText = snapshot.Warnings.Count == 0 ? "" : $" · {string.Join(" ", snapshot.Warnings)}";
            var signed = snapshot.Packages.Count(package => package.IsSigned);
            var unknown = snapshot.Packages.Count(package => package.SignatureStatus?.StartsWith("Unknown", StringComparison.Ordinal) == true);
            StatusText.Text = $"{snapshot.PackageCount:N0} driver packages · {signed:N0} catalog-signed · {snapshot.PackageCount - signed - unknown:N0} unsigned or untrusted · {unknown:N0} unknown · captured {captured:HH:mm:ss}{warningText}";
            ApplyFilter();
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Failed to enumerate driver packages: {ex.Message}";
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
        var matches = _packages
            .Where(package => query.Length == 0 || Matches(package, query))
            .OrderBy(package => package.IsSigned)
            .ThenBy(package => package.InfFile, StringComparer.OrdinalIgnoreCase)
            .Select(package => new DriverPackageRow(package))
            .ToArray();
        VisiblePackages.Clear();
        foreach (var row in matches) VisiblePackages.Add(row);
        PackageCount.Text = _packages.Count == 0 ? "" : $"{matches.Length:N0} of {_packages.Count:N0}";
        EmptyState.Text = _packages.Count == 0 ? "Click 'Refresh driver store' to load data." : "No packages match the filter.";
        EmptyState.Visibility = VisiblePackages.Count == 0 ? Microsoft.UI.Xaml.Visibility.Visible : Microsoft.UI.Xaml.Visibility.Collapsed;
    }

    private static bool Matches(DriverPackageEntry package, string query) =>
        new[] { package.InfFile, package.OriginalInfFile, package.ProviderName, package.DriverClass, package.HardwareId, package.DriverVersion, package.SignerName ?? "", package.SignatureStatus ?? "" }
            .Any(value => value.Contains(query, StringComparison.OrdinalIgnoreCase));
}

public sealed class DriverPackageRow
{
    public DriverPackageEntry Entry { get; }
    public string InfFile => Entry.OriginalInfFile.Length > 0 && !Entry.OriginalInfFile.Equals(Entry.InfFile, StringComparison.OrdinalIgnoreCase)
        ? $"{Entry.InfFile}  ({Entry.OriginalInfFile})"
        : Entry.InfFile;
    public string DriverClass => Entry.DriverClass;
    public string ProviderDisplay => $"Provider: {Entry.ProviderName}";
    public string VersionDateDisplay => $"Version: {Entry.DriverVersion} · Date: {Entry.Date}";
    public string HardwareId => Entry.HardwareId;
    public string SignatureDisplay => Entry.IsSigned
        ? $"{Entry.SignatureStatus} · {Entry.SignerName ?? "signer unavailable"}"
        : Entry.SignatureStatus ?? "Signature status unknown";
    public SolidColorBrush SignatureBrush => new(Entry.IsSigned
        ? Microsoft.UI.Colors.LightGreen
        : Entry.SignatureStatus?.StartsWith("Unknown", StringComparison.Ordinal) != false
            ? Microsoft.UI.Colors.Gold
            : Microsoft.UI.Colors.OrangeRed);

    public DriverPackageRow(DriverPackageEntry entry)
    {
        Entry = entry;
    }
}