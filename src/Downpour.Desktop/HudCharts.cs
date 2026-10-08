using System.Globalization;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.UI;

namespace Downpour_Desktop;

/// <summary>
/// Chart building blocks for the per-tab visuals. Every chart sits in a titled HUD card, uses thin marks with rounded
/// data ends, keeps text in text colours (series colour only on the mark), shows a tooltip on every mark and exposes a
/// text summary to screen readers. Colours: the validated HUD chart palette in fixed order (cyan, violet, magenta, blue;
/// dataviz validator, dark surface #071226) and the reserved status colours for severities, always with their label.
/// </summary>
public static class HudPalette
{
    public static readonly Color[] Categorical =
    [
        Color.FromArgb(255, 0x15, 0xA4, 0xB7), // cyan
        Color.FromArgb(255, 0xA1, 0x6F, 0xFD), // violet
        Color.FromArgb(255, 0xF4, 0x15, 0xCC), // magenta
        Color.FromArgb(255, 0x3C, 0x91, 0xFF), // blue
    ];
    public static readonly Color Other = Color.FromArgb(255, 0x5B, 0x6F, 0x82);
    public static readonly Color Good = Color.FromArgb(255, 0x2B, 0xD9, 0x9A);
    public static readonly Color Warning = Color.FromArgb(255, 0xFF, 0xCB, 0x47);
    public static readonly Color Serious = Color.FromArgb(255, 0xFF, 0x9A, 0x1F);
    public static readonly Color Critical = Color.FromArgb(255, 0xFF, 0x4D, 0x73);

    private static readonly string[] SeverityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

    public static Color? Severity(string label) => label.ToUpperInvariant() switch
    {
        "CRITICAL" => Critical,
        "HIGH" => Serious,
        "MEDIUM" => Warning,
        "LOW" => Color.FromArgb(255, 0x3C, 0x91, 0xFF),
        "INFO" => Color.FromArgb(255, 0x6F, 0x93, 0xA8),
        _ => null,
    };

    public static int SeverityRank(string label) => Array.IndexOf(SeverityOrder, label.ToUpperInvariant()) is var i and >= 0 ? i : 99;

    public static Brush Resource(string key) => (Brush)Application.Current.Resources[key];

    public static string Number(double value) =>
        value >= 100 || value == Math.Floor(value) ? value.ToString("N0", CultureInfo.CurrentCulture) : value.ToString("0.#", CultureInfo.CurrentCulture);
}

/// <summary>A single chart: a HUD card with a title, a subtitle line, and the chart body.</summary>
public abstract partial class HudChart : UserControl
{
    private readonly TextBlock _title = new() { FontSize = 11, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, CharacterSpacing = 120 };
    private readonly TextBlock _subtitle = new() { FontSize = 11, TextWrapping = TextWrapping.Wrap };

    protected HudChart(UIElement body)
    {
        _title.Foreground = HudPalette.Resource("HudTextDimBrush");
        _subtitle.Foreground = HudPalette.Resource("HudTextFaintBrush");
        var stack = new StackPanel { Spacing = 8 };
        stack.Children.Add(_title);
        stack.Children.Add(body);
        stack.Children.Add(_subtitle);
        Content = new Border
        {
            Padding = new Thickness(16, 12, 16, 12),
            CornerRadius = new CornerRadius(12),
            BorderThickness = new Thickness(1),
            Background = HudPalette.Resource("HudPanelBrush"),
            BorderBrush = HudPalette.Resource("HudEdgeBrush"),
            Child = stack,
        };
    }

    public string Title { get => _title.Text; set => _title.Text = value.ToUpperInvariant(); }

    public string Subtitle { get => _subtitle.Text; set => _subtitle.Text = value; }

    protected static TextBlock Ink(string text, double size = 12, string brush = "HudTextBrush") =>
        new() { Text = text, FontSize = size, Foreground = HudPalette.Resource(brush), TextTrimming = TextTrimming.CharacterEllipsis };
}

/// <summary>Share of a whole: one stacked bar with 2 px gaps and a legend of label and value.</summary>
public sealed partial class BreakdownChart : HudChart
{
    private readonly Grid _bar = new() { Height = 12, ColumnSpacing = 2 };
    private readonly StackPanel _legend = new() { Spacing = 4 };
    private readonly Dictionary<string, Color> _colors = new(StringComparer.OrdinalIgnoreCase);
    private string _signature = "";

    public BreakdownChart() : base(Body(out var bar, out var legend))
    {
        _bar = bar;
        _legend = legend;
    }

    private static StackPanel Body(out Grid bar, out StackPanel legend)
    {
        bar = new Grid { Height = 12, ColumnSpacing = 2 };
        legend = new StackPanel { Spacing = 4 };
        var body = new StackPanel { Spacing = 10 };
        body.Children.Add(bar);
        body.Children.Add(legend);
        return body;
    }

    /// <summary>
    /// Values by label. Severities (CRITICAL..INFO) keep their order and status colours; other labels keep a stable
    /// colour per label (never by rank) and fold into "Other" beyond four. An optional colour pins a label (for example
    /// good/bad states).
    /// </summary>
    public void SetData(IEnumerable<(string Label, double Value)> data, IReadOnlyDictionary<string, Color>? pinned = null, string unit = "")
    {
        var items = data.Where(d => d.Value > 0).ToList();
        var severities = items.Count > 0 && items.All(d => HudPalette.Severity(d.Label) is not null);
        items = severities ? [.. items.OrderBy(d => HudPalette.SeverityRank(d.Label))]
            : pinned is not null ? [.. items.OrderBy(d => pinned.ContainsKey(d.Label) ? 0 : 1).ThenByDescending(d => d.Value)]
            : [.. items.OrderByDescending(d => d.Value).ThenBy(d => d.Label, StringComparer.OrdinalIgnoreCase)];
        if (!severities && items.Count > HudPalette.Categorical.Length)
            items = [.. items.Take(HudPalette.Categorical.Length - 1), ("Other", items.Skip(HudPalette.Categorical.Length - 1).Sum(d => d.Value))];

        var signature = string.Join("|", items.Select(d => $"{d.Label}={d.Value:0.##}"));
        if (signature == _signature) return;
        _signature = signature;
        _bar.Children.Clear();
        _bar.ColumnDefinitions.Clear();
        _legend.Children.Clear();
        var total = Math.Max(1e-9, items.Sum(d => d.Value));
        for (var i = 0; i < items.Count; i++)
        {
            var (label, value) = items[i];
            var color = pinned?.GetValueOrDefault(label) is { A: > 0 } pin ? pin
                : severities ? HudPalette.Severity(label)!.Value
                : label == "Other" ? HudPalette.Other : ColorFor(label);
            _bar.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(value, GridUnitType.Star) });
            var segment = new Border
            {
                Background = new SolidColorBrush(color),
                CornerRadius = new CornerRadius(i == 0 ? 4 : 0, i == items.Count - 1 ? 4 : 0, i == items.Count - 1 ? 4 : 0, i == 0 ? 4 : 0),
            };
            var text = $"{label}: {HudPalette.Number(value)}{unit} ({value * 100 / total:0}%)";
            ToolTipService.SetToolTip(segment, text);
            AutomationProperties.SetName(segment, text);
            Grid.SetColumn(segment, i);
            _bar.Children.Add(segment);

            var row = new Grid { ColumnSpacing = 8 };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            row.Children.Add(new Ellipse { Width = 8, Height = 8, Fill = new SolidColorBrush(color), VerticalAlignment = VerticalAlignment.Center });
            var name = Ink(label);
            Grid.SetColumn(name, 1);
            row.Children.Add(name);
            var number = Ink($"{HudPalette.Number(value)}{unit} · {value * 100 / total:0}%", 12, "HudTextDimBrush");
            Grid.SetColumn(number, 2);
            row.Children.Add(number);
            _legend.Children.Add(row);
        }
        if (items.Count == 0) _legend.Children.Add(Ink("Nothing to show yet", 12, "HudTextDimBrush"));
        AutomationProperties.SetName(this, $"{Title}: " + string.Join(", ", items.Select(d => $"{d.Label} {HudPalette.Number(d.Value)}{unit}")));
    }

    private Color ColorFor(string label)
    {
        if (!_colors.TryGetValue(label, out var color))
        {
            color = HudPalette.Categorical[_colors.Count % HudPalette.Categorical.Length];
            _colors[label] = color;
        }
        return color;
    }
}

/// <summary>Ranked values: up to N thin horizontal bars on one shared scale, with the value at the end.</summary>
public sealed partial class TopBarsChart : HudChart
{
    private readonly StackPanel _rows;
    private string _signature = "";

    public TopBarsChart() : base(new StackPanel { Spacing = 6 }) => _rows = (StackPanel)((StackPanel)((Border)Content).Child).Children[1];

    public int Limit { get; set; } = 6;

    /// <summary>Bars in the given colour (default cyan); a value of null-equivalent 0 is dropped.</summary>
    public void SetData(IEnumerable<(string Label, double Value)> data, string unit = "", Color? color = null, Func<double, Color?>? colorFor = null)
    {
        var items = data.Where(d => d.Value > 0).OrderByDescending(d => d.Value).Take(Limit).ToList();
        var signature = string.Join("|", items.Select(d => $"{d.Label}={d.Value:0.#}"));
        if (signature == _signature) return;
        _signature = signature;
        _rows.Children.Clear();
        var max = items.Count == 0 ? 1 : Math.Max(items[0].Value, 1e-9);
        foreach (var (label, value) in items)
        {
            var row = new Grid { ColumnSpacing = 8 };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.1, GridUnitType.Star) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.4, GridUnitType.Star) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(64) });
            row.Children.Add(Ink(label));
            var track = new Grid { Height = 8, VerticalAlignment = VerticalAlignment.Center };
            track.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(value / max, GridUnitType.Star) });
            track.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1 - value / max + 1e-6, GridUnitType.Star) });
            var bar = new Border
            {
                Background = new SolidColorBrush(colorFor?.Invoke(value) ?? color ?? HudPalette.Categorical[0]),
                CornerRadius = new CornerRadius(0, 4, 4, 0),
            };
            var text = $"{label}: {HudPalette.Number(value)}{unit}";
            ToolTipService.SetToolTip(bar, text);
            AutomationProperties.SetName(bar, text);
            track.Children.Add(bar);
            Grid.SetColumn(track, 1);
            row.Children.Add(track);
            var number = Ink($"{HudPalette.Number(value)}{unit}", 12, "HudTextDimBrush");
            number.HorizontalAlignment = HorizontalAlignment.Right;
            Grid.SetColumn(number, 2);
            row.Children.Add(number);
            _rows.Children.Add(row);
        }
        if (items.Count == 0) _rows.Children.Add(Ink("Nothing to show yet", 12, "HudTextDimBrush"));
        AutomationProperties.SetName(this, $"{Title}: " + string.Join(", ", items.Select(d => $"{d.Label} {HudPalette.Number(d.Value)}{unit}")));
    }
}

/// <summary>One measure over time: a 2 px line with a light area, the latest value, and a hover crosshair tooltip.</summary>
public sealed partial class TrendChart : HudChart
{
    private readonly Canvas _plot;
    private readonly Polyline _line = new() { StrokeThickness = 2, StrokeLineJoin = PenLineJoin.Round };
    private readonly Polygon _area = new() { Opacity = 0.16 };
    private readonly Line _cross = new() { StrokeThickness = 1, Visibility = Visibility.Collapsed };
    private readonly Ellipse _marker = new() { Width = 8, Height = 8, StrokeThickness = 2, Visibility = Visibility.Collapsed };
    private readonly TextBlock _value;
    private readonly ToolTip _tip = new();
    private readonly List<(DateTimeOffset At, double Value)> _points = [];

    public TrendChart() : base(Body(out var plot, out var value))
    {
        _plot = plot;
        _value = value;
        Accent = HudPalette.Categorical[0];
        _cross.Stroke = HudPalette.Resource("HudTextFaintBrush");
        _marker.Stroke = HudPalette.Resource("HudPanelBrush");
        _plot.Children.Add(_area);
        _plot.Children.Add(_line);
        _plot.Children.Add(_cross);
        _plot.Children.Add(_marker);
        ToolTipService.SetToolTip(_plot, _tip);
        _plot.PointerMoved += (_, e) => Hover(e.GetCurrentPoint(_plot).Position.X);
        _plot.PointerExited += (_, _) => { _cross.Visibility = Visibility.Collapsed; _marker.Visibility = Visibility.Collapsed; };
        _plot.SizeChanged += (_, _) => Draw();
    }

    private static StackPanel Body(out Canvas plot, out TextBlock value)
    {
        value = new TextBlock { FontSize = 22, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, Foreground = HudPalette.Resource("HudTextBrush") };
        plot = new Canvas { Height = 64, Background = new SolidColorBrush(Colors.Transparent) };
        var body = new StackPanel { Spacing = 6 };
        body.Children.Add(value);
        body.Children.Add(plot);
        return body;
    }

    public Color Accent
    {
        get => ((SolidColorBrush)_line.Stroke).Color;
        set
        {
            _line.Stroke = new SolidColorBrush(value);
            _area.Fill = new SolidColorBrush(value);
            _marker.Fill = new SolidColorBrush(value);
        }
    }

    public string Unit { get; set; } = "";

    /// <summary>Keeps this many points; older ones scroll off the left.</summary>
    public int Capacity { get; set; } = 120;

    /// <summary>Fixed top of the scale (for percentages); null scales to the data.</summary>
    public double? Maximum { get; set; }

    public void Push(double value, DateTimeOffset? at = null)
    {
        _points.Add((at ?? DateTimeOffset.Now, value));
        while (_points.Count > Capacity) _points.RemoveAt(0);
        _value.Text = $"{HudPalette.Number(value)}{Unit}";
        AutomationProperties.SetName(this, $"{Title}: now {HudPalette.Number(value)}{Unit}");
        Draw();
    }

    /// <summary>Replaces the whole series (for history that already exists, such as hourly counts).</summary>
    public void SetSeries(IEnumerable<(DateTimeOffset At, double Value)> series)
    {
        _points.Clear();
        _points.AddRange(series.TakeLast(Capacity));
        if (_points.Count > 0) _value.Text = $"{HudPalette.Number(_points[^1].Value)}{Unit}";
        Draw();
    }

    private void Draw()
    {
        var width = _plot.ActualWidth;
        var height = _plot.Height;
        if (width < 20 || _points.Count == 0) return;
        var max = Maximum ?? Math.Max(1e-9, _points.Max(p => p.Value) * 1.1);
        var line = new PointCollection();
        for (var i = 0; i < _points.Count; i++)
        {
            var x = _points.Count == 1 ? width : width - (_points.Count - 1 - i) * width / Math.Max(1, Capacity - 1);
            var y = height - 2 - Math.Clamp(_points[i].Value / max, 0, 1) * (height - 6);
            line.Add(new Windows.Foundation.Point(x, y));
        }
        _line.Points = line;
        var area = new PointCollection();
        foreach (var p in line) area.Add(p);
        area.Add(new Windows.Foundation.Point(line[^1].X, height));
        area.Add(new Windows.Foundation.Point(line[0].X, height));
        _area.Points = area;
    }

    private void Hover(double x)
    {
        if (_line.Points.Count == 0) return;
        var nearest = 0;
        for (var i = 1; i < _line.Points.Count; i++)
            if (Math.Abs(_line.Points[i].X - x) < Math.Abs(_line.Points[nearest].X - x)) nearest = i;
        var p = _line.Points[nearest];
        _cross.X1 = _cross.X2 = p.X;
        _cross.Y1 = 0;
        _cross.Y2 = _plot.Height;
        _cross.Visibility = Visibility.Visible;
        Canvas.SetLeft(_marker, p.X - 4);
        Canvas.SetTop(_marker, p.Y - 4);
        _marker.Visibility = Visibility.Visible;
        var point = _points[nearest];
        _tip.Content = $"{point.At:g}: {HudPalette.Number(point.Value)}{Unit}";
    }
}

/// <summary>Lays charts out side by side in a page's chart row (equal columns).</summary>
public static class Charts
{
    public static void Row(Grid row, params HudChart[] charts)
    {
        row.ColumnSpacing = 14;
        row.Children.Clear();
        row.ColumnDefinitions.Clear();
        for (var i = 0; i < charts.Length; i++)
        {
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            Grid.SetColumn(charts[i], i);
            row.Children.Add(charts[i]);
        }
    }
}
