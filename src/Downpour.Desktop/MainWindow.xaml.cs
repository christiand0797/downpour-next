using System.Globalization;
using Downpour.Contracts;
using Downpour.Core;
using Downpour_Desktop.Pages;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Downpour_Desktop;

public sealed partial class MainWindow : Window
{
    private readonly IReadOnlyList<CapabilityDefinition> _capabilities;
    private readonly Dictionary<string, NavigationViewItem> _routeItems = new(StringComparer.OrdinalIgnoreCase);
    private string? _currentRouteId;

    public MainWindow()
    {
        _capabilities = CapabilityRegistry.Load(Path.Combine(AppContext.BaseDirectory, "capabilities.json"));
        InitializeComponent();
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;
        AppWindow.SetIcon("Assets/AppIcon.ico");
        NavFrame.Navigated += NavFrame_Navigated;
        BuildNavigation();
        Navigate(_capabilities[0]);
    }

    private void BuildNavigation()
    {
        foreach (var group in _capabilities.GroupBy(capability => capability.Group))
        {
            NavView.MenuItems.Add(new NavigationViewItemHeader { Content = group.Key });
            foreach (var capability in group)
            {
                var item = new NavigationViewItem
                {
                    Content = capability.Title,
                    Tag = capability.RouteId,
                    Icon = new FontIcon { Glyph = char.ConvertFromUtf32(int.Parse(capability.Icon, NumberStyles.HexNumber, CultureInfo.InvariantCulture)) }
                };
                _routeItems.Add(capability.RouteId, item);
                NavView.MenuItems.Add(item);
            }
        }
    }

    private void Navigate(CapabilityDefinition capability)
    {
        if (string.Equals(_currentRouteId, capability.RouteId, StringComparison.OrdinalIgnoreCase)) return;
        _currentRouteId = capability.RouteId;
        NavView.SelectedItem = _routeItems[capability.RouteId];
        if (capability.RouteId.Equals("dashboard", StringComparison.OrdinalIgnoreCase))
            NavFrame.Navigate(typeof(HomePage));
        else if (capability.RouteId.Equals("processes", StringComparison.OrdinalIgnoreCase))
            NavFrame.Navigate(typeof(ProcessPage));
        else
            NavFrame.Navigate(typeof(CapabilityPage), capability);
    }

    private void TitleBar_PaneToggleRequested(TitleBar sender, object args) => NavView.IsPaneOpen = !NavView.IsPaneOpen;

    private void TitleBar_BackRequested(TitleBar sender, object args)
    {
        if (NavFrame.CanGoBack) NavFrame.GoBack();
    }

    private void NavView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItem is not NavigationViewItem item || item.Tag is not string routeId) return;
        var capability = _capabilities.FirstOrDefault(candidate => candidate.RouteId.Equals(routeId, StringComparison.OrdinalIgnoreCase));
        if (capability is not null) Navigate(capability);
    }

    private void NavFrame_Navigated(object sender, Microsoft.UI.Xaml.Navigation.NavigationEventArgs args)
    {
        var routeId = args.Content is CapabilityPage && args.Parameter is CapabilityDefinition capability
            ? capability.RouteId
            : args.Content is HomePage ? "dashboard" : null;

        if (routeId is null || !_routeItems.TryGetValue(routeId, out var item)) return;
        _currentRouteId = routeId;
        NavView.SelectedItem = item;
    }
}
