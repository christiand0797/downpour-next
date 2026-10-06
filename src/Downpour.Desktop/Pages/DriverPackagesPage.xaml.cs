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
    private bool _requestInFlight;

    public ObservableCollection<DriverPackageRow> VisiblePackages { get; } = [];

    public DriverPackagesPage() => InitializeComponent();

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _ = RefreshAsync();
    }

    private async void RefreshButton_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) => await RefreshAsync();

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilter();

    private async Task RefreshAsync()
    {
        if (_requestInFlight) return;
        _requestInFlight = true;
        RefreshButton.IsEnabled = false;
        StatusText.Text = "Enumerating driver packages from the Driver Store…";
        try
        {
            var snapshot = await _client.TryGetSnapshotAsync();
            if (snapshot is null)
            {
                StatusText.Text = "Driver package inventory is unavailable.";
                return;
            }
            var captured = snapshot.CapturedAtUtc.ToLocalTime();
            var warningText = snapshot.Warnings.Count == 0 ? "" : $" · {string.Join(" ", snapshot.Warnings)}";
            StatusText.Text = $"{snapshot.PackageCount:N0} driver packages · captured {captured:HH:mm:ss}{warningText}";
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
        VisiblePackages.Clear();
        // In a real implementation, we would filter from the client's cached data
        // For now, just show all
        EmptyState.Visibility = VisiblePackages.Count == 0 ? Microsoft.UI.Xaml.Visibility.Visible : Microsoft.UI.Xaml.Visibility.Collapsed;
    }
}

public sealed class DriverPackageRow
{
    public DriverPackageEntry Entry { get; }
    public string InfFile => Entry.InfFile;
    public string DriverClass => Entry.DriverClass;
    public string ProviderDisplay => $"Provider: {Entry.ProviderName}";
    public string VersionDateDisplay => $"Version: {Entry.DriverVersion} · Date: {Entry.Date}";
    public string HardwareId => Entry.HardwareId;
    public string SignatureDisplay => Entry.IsSigned ? $"Signed by {Entry.SignerName} · {Entry.SignatureStatus}" : "Not signed";
    public SolidColorBrush SignatureBrush => Entry.IsSigned ? new SolidColorBrush(Microsoft.UI.Colors.LightGreen) : new SolidColorBrush(Microsoft.UI.Colors.OrangeRed);

    public DriverPackageRow(DriverPackageEntry entry)
    {
        Entry = entry;
    }
}