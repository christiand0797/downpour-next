using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Microsoft.UI.Text;
using Windows.UI;

namespace Downpour_Desktop;

/// <summary>A circular utilization gauge whose progress follows the exact centerline of its track.</summary>
public sealed class CircularGauge : UserControl
{
    private const double CanvasSize = 136;
    private const double RingSize = 120;
    private const double Center = RingSize / 2;
    private const double Radius = 56;
    private const double StrokeWidth = 8;
    private readonly Microsoft.UI.Xaml.Shapes.Path _progressRing;
    private readonly Ellipse _fullProgressRing;
    private readonly TextBlock _valueText;
    private double? _value;
    private string? _displayValue;

    public CircularGauge(string caption, Color accent)
    {
        Width = CanvasSize;
        Height = CanvasSize;
        HorizontalAlignment = HorizontalAlignment.Center;
        VerticalAlignment = VerticalAlignment.Center;

        var root = new Grid { Width = CanvasSize, Height = CanvasSize };
        root.Children.Add(new Ellipse
        {
            Width = RingSize,
            Height = RingSize,
            Stroke = new SolidColorBrush(Color.FromArgb(76, accent.R, accent.G, accent.B)),
            StrokeThickness = StrokeWidth,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center
        });

        _fullProgressRing = new Ellipse
        {
            Width = RingSize,
            Height = RingSize,
            Stroke = new SolidColorBrush(accent),
            StrokeThickness = StrokeWidth,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            Visibility = Visibility.Collapsed,
            IsHitTestVisible = false
        };
        root.Children.Add(_fullProgressRing);

        _progressRing = new Microsoft.UI.Xaml.Shapes.Path
        {
            Width = RingSize,
            Height = RingSize,
            Stroke = new SolidColorBrush(accent),
            StrokeThickness = StrokeWidth,
            StrokeLineJoin = PenLineJoin.Round,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            Visibility = Visibility.Collapsed,
            IsHitTestVisible = false
        };
        root.Children.Add(_progressRing);

        var centerText = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center, Spacing = 1 };
        _valueText = new TextBlock { Text = "—", FontSize = 25, FontWeight = FontWeights.SemiBold, HorizontalTextAlignment = TextAlignment.Center };
        var captionText = new TextBlock { Text = caption, FontSize = 10, CharacterSpacing = 110, Opacity = 0.72, HorizontalTextAlignment = TextAlignment.Center };
        centerText.Children.Add(_valueText);
        centerText.Children.Add(captionText);
        root.Children.Add(centerText);
        Content = root;
    }

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
        _displayValue = nextDisplay;
        _valueText.Text = _displayValue;
        _valueText.FontSize = _valueText.Text.Length > 5 ? 15 : _valueText.Text.Length > 4 ? 18 : 25;
        UpdateArc();
    }

    private void UpdateArc()
    {
        if (_value is not { } value || value <= 0)
        {
            _progressRing.Visibility = Visibility.Collapsed;
            _fullProgressRing.Visibility = Visibility.Collapsed;
            return;
        }

        // Follow the exact centerline of the track with a single arc. A PathGeometry
        // avoids rebuilding mutable PointCollections during the live refresh cycle.
        if (value >= 99.95)
        {
            _progressRing.Visibility = Visibility.Collapsed;
            _fullProgressRing.Visibility = Visibility.Visible;
            return;
        }
        _fullProgressRing.Visibility = Visibility.Collapsed;
        var endAngle = (-90d + 360d * value / 100d) * Math.PI / 180d;
        var geometry = new PathGeometry();
        var figure = new PathFigure
        {
            StartPoint = new Windows.Foundation.Point(Center, Center - Radius),
            IsClosed = false
        };
        figure.Segments.Add(new ArcSegment
        {
            Point = new Windows.Foundation.Point(Center + Radius * Math.Cos(endAngle), Center + Radius * Math.Sin(endAngle)),
            Size = new Windows.Foundation.Size(Radius, Radius),
            IsLargeArc = value > 50,
            SweepDirection = SweepDirection.Clockwise
        });
        geometry.Figures.Add(figure);
        _progressRing.Data = geometry;
        _progressRing.Visibility = Visibility.Visible;
    }
}
