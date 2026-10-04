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
    private readonly List<Polyline> _auroraBands = [];
    private readonly List<Polyline> _lightningBolts = [];
    private readonly Random _random = new();
    private Microsoft.UI.Dispatching.DispatcherQueueTimer? _rainTimer;
    private Microsoft.UI.Dispatching.DispatcherQueueTimer? _starTimer;
    private string? _currentRouteId;
    private int _stormPhaseIndex = 1;
    private int _stormPhaseTarget = 1;
    private int _stormPhaseAge;
    private int _phaseTransitionTicks;
    private int _lightningTicksRemaining;
    private int _windTicksRemaining;
    private double _auroraPhase;
    private double _wind;
    private double _windTarget;

    private static readonly (string Name, double RainMultiplier, double WindMultiplier, double LightningChance)[] StormPhases =
    [
        ("DRIZZLE", 0.7, 0.45, 0.0002),
        ("STORM", 1.15, 0.8, 0.0008),
        ("THUNDERSTORM", 1.65, 1.1, 0.0024),
        ("HURRICANE", 2.1, 2.0, 0.0011)
    ];

    public MainWindow()
    {
        _capabilities = CapabilityRegistry.Load(System.IO.Path.Combine(AppContext.BaseDirectory, "capabilities.json"));
        InitializeComponent();
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;
        AppWindow.SetIcon("Assets/AppIcon.ico");
        InitializeStorm();
        StormModeController.ModeChanged += ApplyStormMode;
        AppPreferences.Changed += ApplyVisualPreferences;
        StormModeController.SetAutomaticCycling(AppPreferences.AutoStormCycle);
        ApplyVisualPreferences();
        Activated += Window_Activated;
        NavFrame.Navigated += NavFrame_Navigated;
        BuildNavigation();
        Navigate(_capabilities[0]);
    }

    private void InitializeStorm()
    {
        _rainTimer = Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread().CreateTimer();
        _rainTimer.Interval = TimeSpan.FromMilliseconds(33);
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

        CreateAurora(e.NewSize.Width, e.NewSize.Height);

        for (var index = 0; index < 280; index++)
        {
            var foregroundDrop = index % 5 == 0;
            var streak = new Rectangle
            {
                Width = foregroundDrop ? _random.NextDouble() * 1.4 + 1.2 : _random.NextDouble() * 0.8 + 0.7,
                Height = foregroundDrop ? _random.Next(28, 54) : _random.Next(13, 31),
                Opacity = foregroundDrop ? _random.NextDouble() * 0.2 + 0.16 : _random.NextDouble() * 0.24 + 0.1,
                Fill = new SolidColorBrush(_random.Next(4) == 0
                    ? Color.FromArgb(255, 168, 197, 255)
                    : Color.FromArgb(255, 87, 207, 240)),
                RenderTransform = new RotateTransform { Angle = 8 }
            };
            var baseOpacity = streak.Opacity;
            var drop = new StormDrop(streak, _random.NextDouble() * e.NewSize.Width,
                _random.NextDouble() * e.NewSize.Height, foregroundDrop ? _random.NextDouble() * 8 + 13 : _random.NextDouble() * 6 + 7,
                _random.NextDouble() * 0.55 + 0.6, baseOpacity);
            _rainDrops.Add(drop);
            StormCanvas.Children.Add(streak);
            Canvas.SetLeft(streak, drop.X);
            Canvas.SetTop(streak, drop.Y);
        }

        for (var index = 0; index < 46; index++)
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

        ApplyVisualPreferences();
    }

    private void AnimateRain()
    {
        var width = ShellRoot.ActualWidth;
        var height = ShellRoot.ActualHeight;
        if (width <= 0 || height <= 0) return;
        _stormPhaseAge++;
        if (_stormPhaseAge >= 1150)
        {
            _stormPhaseAge = 0;
            if (AppPreferences.AutoStormCycle && !StormModeController.IsManual) _stormPhaseTarget = _random.Next(StormPhases.Length);
        }
        if (_stormPhaseIndex != _stormPhaseTarget && ++_phaseTransitionTicks >= 24)
        {
            _phaseTransitionTicks = 0;
            _stormPhaseIndex += Math.Sign(_stormPhaseTarget - _stormPhaseIndex);
            StormModeController.SetAutomaticMode(_stormPhaseTarget);
        }

        var phase = StormPhases[_stormPhaseIndex];
        if (--_windTicksRemaining <= 0)
        {
            _windTarget = (_random.NextDouble() * 2 - 1) * phase.WindMultiplier;
            _windTicksRemaining = _random.Next(30, 120);
        }
        _wind += (_windTarget - _wind) * 0.035;
        foreach (var drop in _rainDrops)
        {
            drop.Y += drop.Speed * phase.RainMultiplier;
            drop.Shape.Opacity = Math.Clamp(drop.BaseOpacity * phase.RainMultiplier, 0.08, 0.82);
            drop.X += _wind * drop.WindResponse * phase.WindMultiplier;
            if (drop.Y > height)
            {
                drop.Y = -drop.Shape.Height;
                drop.X = _random.NextDouble() * width;
            }
            if (drop.X < -4) drop.X = width + 4;
            if (drop.X > width + 4) drop.X = -4;
            Canvas.SetLeft(drop.Shape, drop.X);
            Canvas.SetTop(drop.Shape, drop.Y);
        }

        AnimateAurora(width);
        if (_lightningTicksRemaining > 0)
        {
            _lightningTicksRemaining--;
            LightningFlash.Opacity = _lightningTicksRemaining is 12 or 11 or 6 ? 0.16
                : _lightningTicksRemaining is 10 or 5 or 4 ? 0.065 : 0;
            foreach (var bolt in _lightningBolts)
            {
                bolt.Opacity = _lightningTicksRemaining > 3 ? 0.96 : 0.45;
            }
            if (_lightningTicksRemaining == 0)
            {
                LightningFlash.Opacity = 0;
                foreach (var bolt in _lightningBolts) StormCanvas.Children.Remove(bolt);
                _lightningBolts.Clear();
            }
        }
        else if (_random.NextDouble() < phase.LightningChance)
        {
            TriggerLightning(width, height);
        }
    }

    private void CreateAurora(double width, double height)
    {
        var colors = new[]
        {
            Color.FromArgb(255, 59, 225, 220),
            Color.FromArgb(255, 109, 120, 255),
            Color.FromArgb(255, 57, 211, 162)
        };
        for (var band = 0; band < colors.Length; band++)
        {
            var polyline = new Polyline
            {
                Stroke = new SolidColorBrush(colors[band]),
                StrokeThickness = 12 + band * 3,
                StrokeLineJoin = PenLineJoin.Round,
                Opacity = 0.035
            };
            _auroraBands.Add(polyline);
            StormCanvas.Children.Add(polyline);
        }
        AnimateAurora(width, height);
    }

    private void AnimateAurora(double width, double? knownHeight = null)
    {
        if (_auroraBands.Count == 0 || width <= 0) return;
        var height = knownHeight ?? ShellRoot.ActualHeight;
        _auroraPhase += 0.012;
        for (var band = 0; band < _auroraBands.Count; band++)
        {
            var points = new PointCollection();
            for (var point = 0; point <= 18; point++)
            {
                var x = width * point / 18d;
                var wave = Math.Sin(_auroraPhase + point * 0.43 + band * 1.4) * (11 + band * 2);
                var y = height * (0.12 + band * 0.045) + wave;
                points.Add(new Windows.Foundation.Point(x, y));
            }
            _auroraBands[band].Points = points;
            _auroraBands[band].Opacity = 0.035 + (Math.Sin(_auroraPhase * 0.7 + band) + 1) * 0.04;
        }
    }

    private void TriggerLightning(double width, double height)
    {
        _lightningTicksRemaining = 14;
        var startX = _random.NextDouble() * width * 0.46 + width * 0.27;
        var startY = height * 0.035;
        var endY = height * (_random.NextDouble() * 0.08 + 0.19);
        var currentX = startX;
        var points = new PointCollection { new(currentX, startY) };
        for (var index = 0; index < 9; index++)
        {
            currentX += (_random.NextDouble() - 0.5) * width * 0.035;
            points.Add(new Windows.Foundation.Point(currentX, startY + (endY - startY) * (index + 1) / 9d));
        }
        AddBolt(points, 2.4, 0.96);

        if (_random.NextDouble() < 0.72)
        {
            var branch = new PointCollection();
            var startAt = Math.Clamp(_random.Next(3, points.Count - 1), 0, points.Count - 1);
            var branchStart = points[startAt];
            branch.Add(branchStart);
            branch.Add(new Windows.Foundation.Point(branchStart.X + (_random.NextDouble() - 0.5) * width * 0.08, branchStart.Y + height * 0.035));
            branch.Add(new Windows.Foundation.Point(branchStart.X + (_random.NextDouble() - 0.5) * width * 0.12, branchStart.Y + height * 0.065));
            AddBolt(branch, 1.3, 0.7);
        }

        void AddBolt(PointCollection boltPoints, double thickness, double opacity)
        {
            var bolt = new Polyline
            {
                Points = boltPoints,
                Stroke = new SolidColorBrush(Color.FromArgb(255, 206, 241, 255)),
                StrokeThickness = thickness,
                StrokeLineJoin = PenLineJoin.Round,
                Opacity = opacity
            };
            _lightningBolts.Add(bolt);
            StormCanvas.Children.Add(bolt);
        }
    }

    private void ApplyStormMode(int mode)
    {
        _stormPhaseTarget = Math.Clamp(mode, 0, StormPhases.Length - 1);
        _stormPhaseAge = 0;
        _phaseTransitionTicks = 0;
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
        ApplyVisualPreferences();
    }

    private void ApplyVisualPreferences()
    {
        if (!DispatcherQueue.HasThreadAccess)
        {
            _ = DispatcherQueue.TryEnqueue(ApplyVisualPreferences);
            return;
        }

        StormCanvas.Visibility = AppPreferences.RainEffectsEnabled ? Visibility.Visible : Visibility.Collapsed;
        if (!AppPreferences.RainEffectsEnabled || AppPreferences.ReduceMotion)
        {
            _rainTimer?.Stop();
            _starTimer?.Stop();
            LightningFlash.Opacity = 0;
            foreach (var bolt in _lightningBolts) StormCanvas.Children.Remove(bolt);
            _lightningBolts.Clear();
            _lightningTicksRemaining = 0;
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
        else if (capability.RouteId.Equals("services", StringComparison.OrdinalIgnoreCase))
            NavFrame.Navigate(typeof(ServicesPage));
        else if (capability.RouteId.Equals("network", StringComparison.OrdinalIgnoreCase))
            NavFrame.Navigate(typeof(NetworkPage));
        else if (capability.RouteId.Equals("security-events", StringComparison.OrdinalIgnoreCase))
            NavFrame.Navigate(typeof(SecurityEventsPage));
        else if (capability.RouteId.Equals("intel", StringComparison.OrdinalIgnoreCase))
            NavFrame.Navigate(typeof(IntelPage));
        else if (capability.RouteId.Equals("settings", StringComparison.OrdinalIgnoreCase))
            NavFrame.Navigate(typeof(SettingsPage));
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
            : args.Content is DriverPage ? "drivers"
            : args.Content is ServicesPage ? "services"
            : args.Content is NetworkPage ? "network"
            : args.Content is SecurityEventsPage ? "security-events" : null;
        if (routeId is null && args.Content is IntelPage) routeId = "intel";
        if (routeId is null && args.Content is SettingsPage) routeId = "settings";

        if (routeId is null || !_routeItems.TryGetValue(routeId, out var item)) return;
        _currentRouteId = routeId;
        NavView.SelectedItem = item;
    }

    private sealed class StormDrop(Rectangle shape, double x, double y, double speed, double windResponse, double baseOpacity)
    {
        public Rectangle Shape { get; } = shape;
        public double X { get; set; } = x;
        public double Y { get; set; } = y;
        public double Speed { get; } = speed;
        public double WindResponse { get; } = windResponse;
        public double BaseOpacity { get; } = baseOpacity;
    }
}
