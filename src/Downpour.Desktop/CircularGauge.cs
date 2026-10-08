using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Shapes;
using Windows.UI;

namespace Downpour_Desktop;

/// <summary>
/// HUD ring gauge: a ticked bezel, a slowly turning scanner arc, a glowing gradient progress arc with a bright end cap,
/// and an inner dashed ring. Progress follows the exact centerline of its track. Motion stops when Windows animations
/// are turned off, and the reading is always shown as text so it never depends on color or motion.
/// </summary>
public sealed class CircularGauge : UserControl
{
    private const double CanvasSize = 136;
    private const double RingSize = 120;
    private const double Center = RingSize / 2;
    private const double Radius = 56;
    private const double StrokeWidth = 7;
    private readonly Microsoft.UI.Xaml.Shapes.Path _glowArc;
    private readonly Microsoft.UI.Xaml.Shapes.Path _progressArc;
    private readonly Ellipse _capGlow;
    private readonly Ellipse _cap;
    private readonly TextBlock _valueText;
    private readonly Storyboard? _scan;
    private double? _value;

    public CircularGauge(string caption, Color accent)
    {
        Width = CanvasSize;
        Height = CanvasSize;
        HorizontalAlignment = HorizontalAlignment.Center;
        VerticalAlignment = VerticalAlignment.Center;
        var bright = Blend(accent, Color.FromArgb(255, 255, 255, 255), 0.45);
        var magenta = Color.FromArgb(255, 255, 43, 214);

        var root = new Grid { Width = CanvasSize, Height = CanvasSize };

        // Bezel: 60 fine ticks around the outside.
        root.Children.Add(Ring(132, 3, Color.FromArgb(110, accent.R, accent.G, accent.B), [0.35, 1.95]));
        // Scanner: two magenta arcs that slowly orbit the bezel.
        var scanner = Ring(126, 1.6, Color.FromArgb(170, magenta.R, magenta.G, magenta.B), [22, 40]);
        scanner.RenderTransformOrigin = new Windows.Foundation.Point(0.5, 0.5);
        var rotation = new RotateTransform();
        scanner.RenderTransform = rotation;
        root.Children.Add(scanner);
        // Track and inner rings.
        root.Children.Add(Ring(RingSize, StrokeWidth, Color.FromArgb(46, accent.R, accent.G, accent.B), null));
        root.Children.Add(Ring(94, 1, Color.FromArgb(90, accent.R, accent.G, accent.B), [2, 3]));

        _glowArc = Arc(new SolidColorBrush(Color.FromArgb(60, accent.R, accent.G, accent.B)), StrokeWidth + 9);
        root.Children.Add(_glowArc);
        _progressArc = Arc(new LinearGradientBrush
        {
            StartPoint = new Windows.Foundation.Point(0, 0),
            EndPoint = new Windows.Foundation.Point(1, 1),
            GradientStops = { new GradientStop { Color = accent, Offset = 0 }, new GradientStop { Color = bright, Offset = 0.55 }, new GradientStop { Color = accent, Offset = 1 } },
        }, StrokeWidth);
        root.Children.Add(_progressArc);

        var caps = new Canvas { Width = RingSize, Height = RingSize, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center, IsHitTestVisible = false };
        _capGlow = new Ellipse { Width = 18, Height = 18, Fill = new SolidColorBrush(Color.FromArgb(90, accent.R, accent.G, accent.B)), Visibility = Visibility.Collapsed };
        _cap = new Ellipse { Width = 8, Height = 8, Fill = new SolidColorBrush(bright), Visibility = Visibility.Collapsed };
        caps.Children.Add(_capGlow);
        caps.Children.Add(_cap);
        root.Children.Add(caps);

        var centerText = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center, Spacing = 0 };
        _valueText = new TextBlock
        {
            Text = "—", FontSize = 25, FontWeight = FontWeights.SemiBold, HorizontalTextAlignment = TextAlignment.Center,
            FontFamily = new FontFamily("Bahnschrift"), Foreground = new SolidColorBrush(Color.FromArgb(255, 233, 248, 255)),
        };
        var captionText = new TextBlock
        {
            Text = caption, FontSize = 10, CharacterSpacing = 200, HorizontalTextAlignment = TextAlignment.Center,
            FontFamily = new FontFamily("Bahnschrift"), Foreground = new SolidColorBrush(bright),
        };
        centerText.Children.Add(_valueText);
        centerText.Children.Add(captionText);
        root.Children.Add(centerText);
        Content = root;
        AutomationProperties.SetName(this, caption);

        if (!AppPreferences.ReduceMotion && new Windows.UI.ViewManagement.UISettings().AnimationsEnabled)
        {
            var spin = new DoubleAnimation { From = 0, To = 360, Duration = new Duration(TimeSpan.FromSeconds(18)), RepeatBehavior = RepeatBehavior.Forever };
            Storyboard.SetTarget(spin, rotation);
            Storyboard.SetTargetProperty(spin, "Angle");
            _scan = new Storyboard { Children = { spin } };
            Loaded += (_, _) => _scan.Begin();
            Unloaded += (_, _) => _scan.Stop();
        }
    }

    private static Ellipse Ring(double size, double thickness, Color color, double[]? dashes)
    {
        var ring = new Ellipse
        {
            Width = size, Height = size, Stroke = new SolidColorBrush(color), StrokeThickness = thickness,
            HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center, IsHitTestVisible = false,
        };
        if (dashes is not null)
        {
            var collection = new DoubleCollection();
            foreach (var dash in dashes) collection.Add(dash);
            ring.StrokeDashArray = collection;
        }
        return ring;
    }

    private static Microsoft.UI.Xaml.Shapes.Path Arc(Brush stroke, double thickness) => new()
    {
        Width = RingSize, Height = RingSize, Stroke = stroke, StrokeThickness = thickness,
        StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round, StrokeLineJoin = PenLineJoin.Round,
        HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center,
        Visibility = Visibility.Collapsed, IsHitTestVisible = false,
    };

    private static Color Blend(Color a, Color b, double amount) => Color.FromArgb(255,
        (byte)(a.R + (b.R - a.R) * amount), (byte)(a.G + (b.G - a.G) * amount), (byte)(a.B + (b.B - a.B) * amount));

    public void SetValue(double? value)
    {
        SetMetric(value, value is { } measured && double.IsFinite(measured) ? $"{Math.Clamp(measured, 0, 100):0}%" : null);
    }

    public void SetMetric(double? normalizedPercent, string? displayValue)
    {
        double? nextValue = normalizedPercent is { } measured && double.IsFinite(measured) ? Math.Clamp(measured, 0, 100) : null;
        // A reading without a known maximum (e.g. GPU memory in use) shows its text with an empty ring.
        var nextDisplay = string.IsNullOrWhiteSpace(displayValue) ? "—" : displayValue;
        if (_value == nextValue && _valueText.Text == nextDisplay) return;
        _value = nextValue;
        _valueText.Text = nextDisplay;
        _valueText.FontSize = nextDisplay.Length > 5 ? 15 : nextDisplay.Length > 4 ? 18 : 25;
        AutomationProperties.SetHelpText(this, nextDisplay);
        UpdateArc();
    }

    private void UpdateArc()
    {
        if (_value is not { } value || value <= 0)
        {
            _glowArc.Visibility = _progressArc.Visibility = _cap.Visibility = _capGlow.Visibility = Visibility.Collapsed;
            return;
        }

        // One arc along the track centerline; a full reading stops just short of closing so the end cap stays visible.
        var sweep = Math.Min(value, 99.9) / 100d * 360d;
        var endAngle = (-90d + sweep) * Math.PI / 180d;
        var end = new Windows.Foundation.Point(Center + Radius * Math.Cos(endAngle), Center + Radius * Math.Sin(endAngle));
        _progressArc.Data = Geometry(end, sweep > 180);
        _glowArc.Data = Geometry(end, sweep > 180);
        Canvas.SetLeft(_cap, end.X - _cap.Width / 2);
        Canvas.SetTop(_cap, end.Y - _cap.Height / 2);
        Canvas.SetLeft(_capGlow, end.X - _capGlow.Width / 2);
        Canvas.SetTop(_capGlow, end.Y - _capGlow.Height / 2);
        _glowArc.Visibility = _progressArc.Visibility = _cap.Visibility = _capGlow.Visibility = Visibility.Visible;
    }

    private static PathGeometry Geometry(Windows.Foundation.Point end, bool large)
    {
        var figure = new PathFigure { StartPoint = new Windows.Foundation.Point(Center, Center - Radius), IsClosed = false };
        figure.Segments.Add(new ArcSegment { Point = end, Size = new Windows.Foundation.Size(Radius, Radius), IsLargeArc = large, SweepDirection = SweepDirection.Clockwise });
        var geometry = new PathGeometry();
        geometry.Figures.Add(figure);
        return geometry;
    }
}
