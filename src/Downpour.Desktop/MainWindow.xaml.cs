using System.Globalization;
using Downpour.Contracts;
using Downpour.Core;
using Downpour_Desktop.Pages;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.UI;

namespace Downpour_Desktop;

public sealed partial class MainWindow : Window
{
    private readonly IReadOnlyList<CapabilityDefinition> _capabilities;
    private readonly Dictionary<string, NavigationViewItem> _routeItems = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<StormDrop> _rainDrops = [];
    private readonly List<Ellipse> _stars = [];
    private readonly Random _random = new();
    private Microsoft.UI.Dispatching.DispatcherQueueTimer? _rainTimer;
    private Microsoft.UI.Dispatching.DispatcherQueueTimer? _starTimer;
    private string? _currentRouteId;

    public MainWindow()
    {
        _capabilities = CapabilityRegistry.Load(System.IO.Path.Combine(AppContext.BaseDirectory, "capabilities.json"));
        InitializeComponent();
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;
        AppWindow.SetIcon("Assets/AppIcon.ico");
        InitializeStorm();
        Activated += Window_Activated;
        NavFrame.Navigated += NavFrame_Navigated;
        BuildNavigation();
        Navigate(_capabilities[0]);
    }

    private void InitializeStorm()
    {
        _rainTimer = Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread().CreateTimer();
        _rainTimer.Interval = TimeSpan.FromMilliseconds(40);
        _rainTimer.IsRepeating = true;
        _rainTimer.Tick += (_, _) => AnimateRain();

        _starTimer = Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread().CreateTimer();
        _starTimer.Interval = TimeSpan.FromMilliseconds(720);
        _starTimer.IsRepeating = true;
        _starTimer.Tick += (_, _) => TwinkleStars();
    }

    private void ShellRoot_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (e.NewSize.Width <= 0 || e.NewSize.Height <= 0 || _rainDrops.Count > 0) return;

        for (var index = 0; index < 66; index++)
        {
            var streak = new Rectangle
            {
                Width = _random.Next(1, 3),
                Height = _random.Next(14, 34),
                Opacity = _random.NextDouble() * 0.20 + 0.07,
                Fill = new SolidColorBrush(Color.FromArgb(255, 100, 206, 238)),
                RenderTransform = new RotateTransform { Angle = 8 }
            };
            var drop = new StormDrop(streak, _random.NextDouble() * e.NewSize.Width,
                _random.NextDouble() * e.NewSize.Height, _random.NextDouble() * 6 + 5);
            _rainDrops.Add(drop);
            StormCanvas.Children.Add(streak);
            Canvas.SetLeft(streak, drop.X);
            Canvas.SetTop(streak, drop.Y);
        }

        for (var index = 0; index < 34; index++)
        {
            var star = new Ellipse
            {
                Width = _random.NextDouble() * 1.5 + 0.8,
                Height = _random.NextDouble() * 1.5 + 0.8,
                Opacity = _random.NextDouble() * 0.45 + 0.16,
                Fill = new SolidColorBrush(Color.FromArgb(255, 184, 226, 255))
            };
            _stars.Add(star);
            StormCanvas.Children.Add(star);
            Canvas.SetLeft(star, _random.NextDouble() * e.NewSize.Width);
            Canvas.SetTop(star, _random.NextDouble() * e.NewSize.Height);
        }

        _rainTimer?.Start();
        _starTimer?.Start();
    }

    private void AnimateRain()
    {
        var width = ShellRoot.ActualWidth;
        var height = ShellRoot.ActualHeight;
        if (width <= 0 || height <= 0) return;
        foreach (var drop in _rainDrops)
        {
            drop.Y += drop.Speed;
            if (drop.Y > height)
            {
                drop.Y = -drop.Shape.Height;
                drop.X = _random.NextDouble() * width;
            }
            Canvas.SetLeft(drop.Shape, drop.X);
            Canvas.SetTop(drop.Shape, drop.Y);
        }
    }

    private void TwinkleStars()
    {
        foreach (var star in _stars)
        {
            var target = _random.NextDouble() * 0.72 + 0.12;
            star.Opacity = Math.Abs(star.Opacity - target) < 0.12 ? target : star.Opacity + Math.Sign(target - star.Opacity) * 0.12;
        }
    }

    private void Window_Activated(object sender, WindowActivatedEventArgs args)
    {
        if (args.WindowActivationState == WindowActivationState.Deactivated)
        {
            _rainTimer?.Stop();
            _starTimer?.Stop();
            return;
        }
        if (_rainDrops.Count > 0 && _rainTimer is { IsRunning: false }) _rainTimer.Start();
        if (_stars.Count > 0 && _starTimer is { IsRunning: false }) _starTimer.Start();
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
        else if (capability.RouteId.Equals("drivers", StringComparison.OrdinalIgnoreCase))
            NavFrame.Navigate(typeof(DriverPage));
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
            : args.Content is HomePage ? "dashboard"
            : args.Content is ProcessPage ? "processes"
            : args.Content is DriverPage ? "drivers" : null;

        if (routeId is null || !_routeItems.TryGetValue(routeId, out var item)) return;
        _currentRouteId = routeId;
        NavView.SelectedItem = item;
    }

    private sealed class StormDrop(Rectangle shape, double x, double y, double speed)
    {
        public Rectangle Shape { get; } = shape;
        public double X { get; set; } = x;
        public double Y { get; set; } = y;
        public double Speed { get; } = speed;
    }
}
