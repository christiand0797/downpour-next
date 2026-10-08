using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.Foundation;
using Windows.UI;
using PathShape = Microsoft.UI.Xaml.Shapes.Path;

namespace Downpour_Desktop;

/// <summary>Updates fixed chart shapes while keeping the visual tree stable between samples.</summary>
internal sealed class ChartLineRenderer
{
    private readonly Canvas _canvas;
    private readonly PathShape _area;
    private readonly PathShape _glow;
    private readonly PathShape _line;
    private readonly Ellipse _markerGlow;
    private readonly Ellipse _marker;
    public ChartLineRenderer(Canvas canvas, Color color)
    {
        _canvas = canvas;
        // Neon area under the line that fades to nothing at the baseline.
        _area = new PathShape
        {
            Fill = new LinearGradientBrush
            {
                StartPoint = new Point(0, 0),
                EndPoint = new Point(0, 1),
                GradientStops =
                {
                    new GradientStop { Color = Color.FromArgb(70, color.R, color.G, color.B), Offset = 0 },
                    new GradientStop { Color = Color.FromArgb(0, color.R, color.G, color.B), Offset = 1 },
                },
            },
            IsHitTestVisible = false
        };
        _glow = new PathShape
        {
            Stroke = new SolidColorBrush(Color.FromArgb(48, color.R, color.G, color.B)),
            StrokeThickness = 7,
            StrokeLineJoin = PenLineJoin.Round,
            IsHitTestVisible = false
        };
        _line = new PathShape
        {
            Stroke = new SolidColorBrush(color),
            StrokeThickness = 2,
            StrokeLineJoin = PenLineJoin.Round,
            IsHitTestVisible = false
        };
        _markerGlow = new Ellipse
        {
            Width = 12,
            Height = 12,
            Fill = new SolidColorBrush(Color.FromArgb(40, color.R, color.G, color.B)),
            Visibility = Microsoft.UI.Xaml.Visibility.Collapsed,
            IsHitTestVisible = false
        };
        _marker = new Ellipse
        {
            Width = 5,
            Height = 5,
            Fill = new SolidColorBrush(color),
            Visibility = Microsoft.UI.Xaml.Visibility.Collapsed,
            IsHitTestVisible = false
        };

        // Add once. Refreshes replace only each path's independently-owned geometry.
        canvas.Children.Add(_area);
        canvas.Children.Add(_glow);
        canvas.Children.Add(_line);
        canvas.Children.Add(_markerGlow);
        canvas.Children.Add(_marker);
    }

    public void Update(IReadOnlyList<Point?> points, double newestSampleRightEdge)
    {
        var figures = BuildFigures(points);
        _area.Data = new PathGeometry { Figures = AreaFigures(figures, _canvas.ActualHeight) };
        _glow.Data = new PathGeometry { Figures = CloneFigures(figures) };
        _line.Data = new PathGeometry { Figures = figures };

        if (points.Count > 0 && points[^1] is { } newest
            && double.IsFinite(newest.X) && double.IsFinite(newest.Y)
            && newest.X >= newestSampleRightEdge)
        {
            _markerGlow.Visibility = Microsoft.UI.Xaml.Visibility.Visible;
            _marker.Visibility = Microsoft.UI.Xaml.Visibility.Visible;
            Canvas.SetLeft(_markerGlow, newest.X - _markerGlow.Width / 2);
            Canvas.SetTop(_markerGlow, newest.Y - _markerGlow.Height / 2);
            Canvas.SetLeft(_marker, newest.X - _marker.Width / 2);
            Canvas.SetTop(_marker, newest.Y - _marker.Height / 2);
        }
        else
        {
            _markerGlow.Visibility = Microsoft.UI.Xaml.Visibility.Collapsed;
            _marker.Visibility = Microsoft.UI.Xaml.Visibility.Collapsed;
        }
    }

    private static PathFigureCollection BuildFigures(IReadOnlyList<Point?> points)
    {
        var figures = new PathFigureCollection();
        var current = new List<Point>();
        for (var index = 0; index < points.Count; index++)
        {
            if (points[index] is not { } point || !double.IsFinite(point.X) || !double.IsFinite(point.Y))
            {
                AddCurrentFigure();
                continue;
            }
            current.Add(point);
        }
        AddCurrentFigure();
        return figures;

        void AddCurrentFigure()
        {
            if (current.Count >= 2)
            {
                var pathSegments = new PathSegmentCollection();
                for (var index = 1; index < current.Count; index++)
                    pathSegments.Add(new LineSegment { Point = current[index] });
                figures.Add(new PathFigure { StartPoint = current[0], Segments = pathSegments, IsClosed = false });
            }
            current.Clear();
        }
    }

    private static PathFigureCollection AreaFigures(PathFigureCollection source, double baseline)
    {
        var areas = new PathFigureCollection();
        if (!double.IsFinite(baseline) || baseline <= 0) return areas;
        foreach (var figure in source)
        {
            var segments = new PathSegmentCollection();
            var last = figure.StartPoint;
            foreach (var segment in figure.Segments)
            {
                if (segment is not LineSegment line) continue;
                segments.Add(new LineSegment { Point = line.Point });
                last = line.Point;
            }
            segments.Add(new LineSegment { Point = new Point(last.X, baseline) });
            segments.Add(new LineSegment { Point = new Point(figure.StartPoint.X, baseline) });
            areas.Add(new PathFigure { StartPoint = figure.StartPoint, Segments = segments, IsClosed = true, IsFilled = true });
        }
        return areas;
    }

    private static PathFigureCollection CloneFigures(PathFigureCollection source)
    {
        var clone = new PathFigureCollection();
        foreach (var figure in source)
        {
            var segments = new PathSegmentCollection();
            foreach (var segment in figure.Segments)
            {
                if (segment is LineSegment line) segments.Add(new LineSegment { Point = line.Point });
            }
            clone.Add(new PathFigure { StartPoint = figure.StartPoint, Segments = segments, IsClosed = figure.IsClosed });
        }
        return clone;
    }
}

/// <summary>Five fixed grid rows; labels and line positions update without Canvas resets.</summary>
internal sealed class ChartGrid
{
    private readonly Line[] _guides = new Line[5];
    private readonly TextBlock[] _labels = new TextBlock[5];
    private readonly double _insetX;
    private readonly double _insetY;
    private readonly double _labelWidth;
    private readonly double _labelHeight;
    private readonly double _fontSize;

    public ChartGrid(Canvas canvas, double insetX, double insetY, double labelWidth, double labelHeight,
        double fontSize, Color guideColor, Color labelColor)
    {
        _insetX = insetX;
        _insetY = insetY;
        _labelWidth = labelWidth;
        _labelHeight = labelHeight;
        _fontSize = fontSize;
        var guideBrush = new SolidColorBrush(guideColor);
        var labelBrush = new SolidColorBrush(labelColor);
        for (var index = 0; index < _guides.Length; index++)
        {
            _guides[index] = new Line { Stroke = guideBrush, StrokeThickness = 1, IsHitTestVisible = false };
            _labels[index] = new TextBlock
            {
                Width = labelWidth,
                Height = labelHeight,
                FontSize = fontSize,
                Foreground = labelBrush,
                HorizontalTextAlignment = Microsoft.UI.Xaml.TextAlignment.Right,
                IsHitTestVisible = false
            };
            canvas.Children.Add(_guides[index]);
            canvas.Children.Add(_labels[index]);
        }
    }

    public void Update(double width, double height, IReadOnlyList<string> labels)
    {
        for (var index = 0; index < _guides.Length; index++)
        {
            var y = _insetY + (height - _insetY * 2) * index / (_guides.Length - 1);
            _guides[index].X1 = _insetX;
            _guides[index].X2 = Math.Max(_insetX, width - 8);
            _guides[index].Y1 = y;
            _guides[index].Y2 = y;
            _labels[index].Text = index < labels.Count ? labels[index] : string.Empty;
            Canvas.SetLeft(_labels[index], 0);
            Canvas.SetTop(_labels[index], Math.Clamp(y - _labelHeight / 2, 0, Math.Max(0, height - _labelHeight)));
        }
    }
}
