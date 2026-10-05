using Microsoft.UI;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.Foundation;
using Windows.UI;

namespace Downpour_Desktop;

/// <summary>Draws bounded chart segments without mutable WinUI PointCollection ownership.</summary>
internal static class ChartLineRenderer
{
    public static void Add(Canvas canvas, IReadOnlyList<Point> points, Color color)
    {
        for (var index = 1; index < points.Count; index++)
        {
            var from = points[index - 1];
            var to = points[index];
            if (!double.IsFinite(from.X) || !double.IsFinite(from.Y) || !double.IsFinite(to.X) || !double.IsFinite(to.Y)) continue;
            canvas.Children.Add(CreateLine(from, to, Color.FromArgb(28, color.R, color.G, color.B), 8));
            canvas.Children.Add(CreateLine(from, to, color, 2));
        }
    }

    private static Line CreateLine(Point from, Point to, Color color, double thickness) => new()
    {
        X1 = from.X,
        Y1 = from.Y,
        X2 = to.X,
        Y2 = to.Y,
        Stroke = new SolidColorBrush(color),
        StrokeThickness = thickness
    };
}
