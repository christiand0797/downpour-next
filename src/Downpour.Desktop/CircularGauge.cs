using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Microsoft.UI.Text;
using Windows.UI;
using Windows.Foundation;

namespace Downpour_Desktop;

public sealed class CircularGauge : UserControl
{
    private const double CanvasSize = 136;
    private const double Center = CanvasSize / 2;
    private const double StrokeWidth = 8;
    private readonly Ellipse _progressRing;
    private readonly TextBlock _valueText;
    private readonly TextBlock _captionText;
    private readonly Color _accent;
    private double? _value;

    public CircularGauge(string caption, Color accent)
    {
        _accent = accent;
        Width = CanvasSize;
        Height = CanvasSize;
        HorizontalAlignment = HorizontalAlignment.Center;
        VerticalAlignment = VerticalAlignment.Center;

        var root = new Grid { Width = CanvasSize, Height = CanvasSize };
        root.Children.Add(new Ellipse
        {
            Margin = new Thickness(8),
            Stroke = new SolidColorBrush(Color.FromArgb(74, accent.R, accent.G, accent.B)),
            StrokeThickness = 8
        });

        var rotation = new RotateTransform { Angle = -90, CenterX = Center, CenterY = Center };
        _progressRing = new Ellipse
        {
            Margin = new Thickness(8),
            Stroke = new SolidColorBrush(accent),
            StrokeThickness = StrokeWidth,
            StrokeDashArray = new DoubleCollection { 0.1, 1 },
            RenderTransform = rotation,
            Visibility = Visibility.Collapsed
        };
        root.Children.Add(_progressRing);

        var centerText = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center, Spacing = 1 };
        _valueText = new TextBlock { Text = "—", FontSize = 25, FontWeight = FontWeights.SemiBold, HorizontalTextAlignment = TextAlignment.Center };
        _captionText = new TextBlock { Text = caption, FontSize = 10, CharacterSpacing = 110, Opacity = 0.72, HorizontalTextAlignment = TextAlignment.Center };
        centerText.Children.Add(_valueText);
        centerText.Children.Add(_captionText);
        root.Children.Add(centerText);
        Content = root;
        SizeChanged += (_, _) => UpdateArc();
    }

    public void SetValue(double? value)
    {
        _value = value is { } measured && double.IsFinite(measured) ? Math.Clamp(measured, 0, 100) : null;
        _valueText.Text = _value is { } present ? $"{present:0}%" : "—";
        UpdateArc();
    }

    private void UpdateArc()
    {
        if (_value is not { } value || value <= 0)
        {
            _progressRing.Visibility = Visibility.Collapsed;
            return;
        }

        var totalDashUnits = 2 * Math.PI * (Center - 8) / StrokeWidth;
        var activeDashUnits = Math.Max(0.12, totalDashUnits * Math.Min(value, 99.8) / 100d);
        var gapDashUnits = Math.Max(0.12, totalDashUnits - activeDashUnits);
        _progressRing.StrokeDashArray = new DoubleCollection { activeDashUnits, gapDashUnits };
        _progressRing.Visibility = Visibility.Visible;
    }
}
