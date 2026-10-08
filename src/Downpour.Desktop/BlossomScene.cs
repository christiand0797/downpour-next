using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.Foundation;
using Windows.UI;

namespace Downpour_Desktop;

/// <summary>
/// "Sakura Sentinel": a transparent, click-through overlay over a page's own content. A cherry tree stands in a band at
/// the top of the page; its petals drift down over the real interface and settle on the top edges of the page's cards,
/// and Kuro, a black cat with a neon rim light, sits on top of one card with his tail draped over its edge, sweeping
/// petals aside. Petals fall faster the busier the PC is; Kuro's tail swishes faster under load, his ears twitch, he
/// breathes, glances back now and then, and stays on guard with lit eyes while threats are open. Load and mood are
/// also stated in text. Motion uses render transforms only, pauses when scrolled away or hidden, and stops entirely
/// with Reduce motion.
/// </summary>
public sealed class BlossomScene : UserControl
{
    private const double TreeSceneWidth = 1200;
    private const double TreeSceneHeight = 320;
    private const int MaximumFalling = 220;
    private const int MaximumSettled = 180;
    private const int MaximumSurfaces = 80;
    private const double CatScale = 0.85;

    private readonly Canvas _overlay = new() { IsHitTestVisible = false };
    private readonly Canvas _treeScene = new() { Width = TreeSceneWidth, Height = TreeSceneHeight };
    private readonly Viewbox _treeBox;
    private readonly Canvas _petalLayer = new() { IsHitTestVisible = false };
    private readonly Canvas _cat = new() { Width = 90, Height = 120, IsHitTestVisible = false, Visibility = Visibility.Collapsed };
    private readonly Random _random = new(29);
    private readonly List<Petal> _falling = [];
    private readonly List<Petal> _settled = [];
    private readonly Queue<Ellipse> _pool = new();
    private readonly List<Point> _blossomSpots = [];
    private readonly List<Rect> _surfaces = [];
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromMilliseconds(33) };
    private readonly DispatcherTimer _layoutTimer = new() { Interval = TimeSpan.FromSeconds(1.5) };
    private readonly Brush[] _petalBrushes;
    private readonly RotateTransform _tailRotation = new();
    private readonly RotateTransform _leftEar = new();
    private readonly RotateTransform _rightEar = new();
    private readonly ScaleTransform _breath = new();
    private readonly TranslateTransform _headShift = new();
    private readonly RotateTransform _headTilt = new();
    private readonly RotateTransform _tailTip = new();
    private readonly ScaleTransform _eyeScale = new();
    private readonly Ellipse _leftEye;
    private readonly Ellipse _rightEye;
    private readonly Canvas _face = new() { Opacity = 0, IsHitTestVisible = false };
    private readonly TextBlock _status;
    private readonly Border _labels;
    private readonly bool _animate;
    private Panel? _content;
    private FrameworkElement? _treeBand;
    private FrameworkElement? _catPerch;
    private Point _treeOrigin;
    private double _treeScale = 1;
    private Point _catOrigin;
    private double _load = 0.15;
    private int _threats;
    private double _time;
    private double _spawnDebt;
    private double _nextGlance = 9;
    private double _glanceUntil;
    private DateTime _lastTick = DateTime.UtcNow;
    private double _nextLeftEar = 2, _nextRightEar = 4, _leftEarUntil, _rightEarUntil, _leftEarAngle, _rightEarAngle;
    private double _nextTilt = 6, _tiltUntil, _tiltTarget;
    private double _nextBlink = 3, _blinkUntil, _nextSlowBlink = 20, _slowBlinkUntil;
    private double _nextFlick = 5, _flickUntil;

    private sealed class Petal
    {
        public required Ellipse Shape { get; init; }
        public required CompositeTransform Transform { get; init; }
        public double X, Y, Vx, Vy, Spin, Sway, Phase;
    }

    public BlossomScene()
    {
        IsHitTestVisible = false;
        HorizontalAlignment = HorizontalAlignment.Stretch;
        VerticalAlignment = VerticalAlignment.Stretch;
        _animate = !AppPreferences.ReduceMotion && new Windows.UI.ViewManagement.UISettings().AnimationsEnabled;
        _petalBrushes =
        [
            Gradient(Color.FromArgb(255, 255, 196, 222), Color.FromArgb(255, 255, 122, 182)),
            Gradient(Color.FromArgb(255, 255, 214, 232), Color.FromArgb(255, 247, 150, 200)),
            Gradient(Color.FromArgb(255, 255, 160, 205), Color.FromArgb(255, 224, 82, 152)),
            Gradient(Color.FromArgb(235, 255, 236, 244), Color.FromArgb(235, 255, 176, 214)),
        ];

        DrawTree();
        _treeBox = new Viewbox { Stretch = Stretch.Uniform, Child = _treeScene, IsHitTestVisible = false };
        (_leftEye, _rightEye) = DrawCat();
        _cat.RenderTransform = new ScaleTransform { ScaleX = CatScale, ScaleY = CatScale };

        _status = new TextBlock
        {
            FontFamily = new FontFamily("Bahnschrift"), FontSize = 12, CharacterSpacing = 120, Foreground = new SolidColorBrush(Color.FromArgb(235, 255, 240, 248)),
            Margin = new Thickness(14, 0, 0, 0), IsHitTestVisible = false,
        };
        var title = new TextBlock
        {
            Text = "SAKURA SENTINEL", FontFamily = new FontFamily("Bahnschrift"), FontSize = 11, FontWeight = FontWeights.SemiBold, CharacterSpacing = 300,
            Foreground = new SolidColorBrush(Color.FromArgb(255, 255, 214, 236)), Margin = new Thickness(14, 0, 0, 0), IsHitTestVisible = false,
        };
        var labelStack = new StackPanel { Spacing = 2, Padding = new Thickness(0, 8, 18, 8) };
        labelStack.Children.Add(title);
        labelStack.Children.Add(_status);
        _labels = new Border
        {
            Child = labelStack, CornerRadius = new CornerRadius(0, 0, 6, 0), IsHitTestVisible = false,
            Background = new LinearGradientBrush
            {
                StartPoint = new Point(0, 0), EndPoint = new Point(1, 0),
                GradientStops =
                {
                    new GradientStop { Color = Color.FromArgb(200, 20, 6, 32), Offset = 0 },
                    new GradientStop { Color = Color.FromArgb(150, 20, 6, 32), Offset = 0.7 },
                    new GradientStop { Color = Color.FromArgb(0, 20, 6, 32), Offset = 1 },
                },
            },
        };

        _overlay.Children.Add(_treeBox);
        _overlay.Children.Add(_cat);
        _overlay.Children.Add(_petalLayer);
        _overlay.Children.Add(_labels);
        Content = _overlay;
        AutomationProperties.SetName(this, "Sakura Sentinel: cherry petals fall onto the page faster as system load rises; Kuro the cat sits on a card");
        UpdateStatus();

        _timer.Tick += (_, _) =>
        {
            // Decoration must never take the app down: a failed frame is skipped and the scene keeps going.
            try { Tick(); }
            catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or InvalidOperationException or ArgumentException)
            {
                _lastTick = DateTime.UtcNow;
            }
        };
        _layoutTimer.Tick += (_, _) => Relayout();
        SizeChanged += (_, _) => Relayout();
        Loaded += (_, _) =>
        {
            _lastTick = DateTime.UtcNow;
            _layoutTimer.Start();
            Relayout();
            if (_animate) _timer.Start();
        };
        Unloaded += (_, _) => { _timer.Stop(); _layoutTimer.Stop(); };
        // Pause while scrolled out of view: an off-screen scene costs nothing.
        EffectiveViewportChanged += (_, args) =>
        {
            if (!_animate || !IsLoaded) return;
            var view = args.EffectiveViewport;
            var visible = !view.IsEmpty && view.Bottom > 0 && view.Top < ActualHeight && view.Right > 0 && view.Left < ActualWidth;
            if (visible && !_timer.IsEnabled) { _lastTick = DateTime.UtcNow; _timer.Start(); }
            else if (!visible && _timer.IsEnabled) _timer.Stop();
        };
    }

    /// <summary>
    /// Binds the overlay to the page: <paramref name="content"/> holds the cards petals land on, <paramref name="treeBand"/>
    /// is the empty band where the tree stands, and <paramref name="catPerch"/> is the card Kuro sits on.
    /// </summary>
    public void Attach(Panel content, FrameworkElement treeBand, FrameworkElement catPerch)
    {
        _content = content;
        _treeBand = treeBand;
        _catPerch = catPerch;
        content.SizeChanged += (_, _) => Relayout();
        Relayout();
    }

    /// <summary>Load 0–100 (CPU and memory combined); drives petal fall and tail speed.</summary>
    public void SetLoad(double cpuPercent, double memoryPercent)
    {
        if (!double.IsFinite(cpuPercent)) cpuPercent = 0;
        if (!double.IsFinite(memoryPercent)) memoryPercent = 0;
        _load = Math.Clamp(0.75 * cpuPercent / 100 + 0.25 * memoryPercent / 100, 0, 1);
        UpdateStatus();
    }

    public void SetThreats(int openThreats)
    {
        _threats = Math.Max(0, openThreats);
        UpdateStatus();
        if (!_animate) SetEyes(true);
    }

    private void UpdateStatus()
    {
        var mood = _threats > 0 ? $"on guard · {_threats} open threat{(_threats == 1 ? "" : "s")}"
            : _load < 0.25 ? "calm" : _load < 0.55 ? "curious" : _load < 0.8 ? "restless" : "hunting the storm";
        _status.Text = $"LOAD {_load * 100:0}%  ·  KURO IS {mood.ToUpperInvariant()}";
    }

    // ---------- layout: where the tree stands, which card tops petals land on, where Kuro sits ----------

    private void Relayout()
    {
        if (_content is null || _treeBand is null || _catPerch is null || !IsLoaded || XamlRoot is null) return;
        _overlay.Width = ActualWidth;
        _overlay.Height = ActualHeight;
        _petalLayer.Width = ActualWidth;
        _petalLayer.Height = ActualHeight;

        var band = Bounds(_treeBand);
        if (band is { } treeRect && treeRect.Height > 0)
        {
            _treeScale = treeRect.Height / TreeSceneHeight;
            _treeOrigin = new Point(treeRect.X, treeRect.Y);
            _treeBox.Width = TreeSceneWidth * _treeScale;
            _treeBox.Height = treeRect.Height;
            Canvas.SetLeft(_treeBox, treeRect.X);
            Canvas.SetTop(_treeBox, treeRect.Y);
            Canvas.SetLeft(_labels, treeRect.X);
            Canvas.SetTop(_labels, treeRect.Y);
        }

        // Card tops: framed elements (Borders with a stroke) that are reasonably large, found a few levels deep.
        var previous = _surfaces.ToArray();
        _surfaces.Clear();
        CollectSurfaces(_content, 0);
        _surfaces.Sort((a, b) => a.Y.CompareTo(b.Y));

        if (Bounds(_catPerch) is { } perch && perch.Width > 0)
        {
            // Kuro sits on the top edge of his card, tail hanging over the front, at the rightmost spot where his body
            // does not cover a button or other control (header buttons often end just above the card).
            var y = perch.Y - 118 * CatScale;
            _controls.Clear();
            CollectControls(_content, 0);
            var x = perch.X + perch.Width * 0.82 - 45 * CatScale;
            foreach (var fraction in new[] { 0.82, 0.7, 0.58, 0.46, 0.34, 0.22, 0.1 })
            {
                var candidate = perch.X + perch.Width * fraction - 45 * CatScale;
                var body = new Rect(candidate, y, 90 * CatScale, 118 * CatScale);
                if (_controls.Any(control => Overlaps(control, body))) continue;
                x = candidate;
                break;
            }
            _catOrigin = new Point(x, y);
            Canvas.SetLeft(_cat, x);
            Canvas.SetTop(_cat, y);
            _cat.Visibility = Visibility.Visible;
        }

        // When cards move (resize, content change), petals resting on the old positions drift away.
        if (!SameSurfaces(previous, _surfaces))
        {
            foreach (var petal in _settled) Recycle(petal);
            _settled.Clear();
            if (!_animate) SeedStillPetals();
        }
    }

    private void CollectSurfaces(DependencyObject parent, int depth)
    {
        if (depth > 6 || _surfaces.Count >= MaximumSurfaces) return;
        var count = VisualTreeHelper.GetChildrenCount(parent);
        for (var i = 0; i < count && _surfaces.Count < MaximumSurfaces; i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (ReferenceEquals(child, _treeBand)) continue;
            if (child is Border { BorderThickness.Top: > 0, ActualWidth: > 120, ActualHeight: > 36, Visibility: Visibility.Visible } border &&
                Bounds(border) is { } rect && rect.Width > 0)
            {
                _surfaces.Add(new Rect(rect.X + 6, rect.Y, Math.Max(0, rect.Width - 12), rect.Height));
                continue; // a card's own inner borders are not separate ledges
            }
            if (child is UIElement { Visibility: Visibility.Visible }) CollectSurfaces(child, depth + 1);
        }
    }

    private readonly List<Rect> _controls = [];

    /// <summary>Visible interactive controls in the page, so Kuro never sits in front of something you click.</summary>
    private void CollectControls(DependencyObject parent, int depth)
    {
        if (depth > 12 || _controls.Count >= 200) return;
        var count = VisualTreeHelper.GetChildrenCount(parent);
        for (var i = 0; i < count; i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is UIElement { Visibility: not Visibility.Visible }) continue;
            if (child is Microsoft.UI.Xaml.Controls.Primitives.ButtonBase or ComboBox or ToggleSwitch or TextBox or Slider or HyperlinkButton
                && child is FrameworkElement control && Bounds(control) is { } rect)
            {
                _controls.Add(rect);
                continue;
            }
            CollectControls(child, depth + 1);
        }
    }

    private static bool Overlaps(Rect a, Rect b) => a.X < b.X + b.Width && b.X < a.X + a.Width && a.Y < b.Y + b.Height && b.Y < a.Y + a.Height;

    private Rect? Bounds(FrameworkElement element)
    {
        try
        {
            if (element.ActualWidth <= 0 || element.ActualHeight <= 0 || element.XamlRoot is null) return null;
            var origin = element.TransformToVisual(this).TransformPoint(new Point(0, 0));
            return new Rect(origin.X, origin.Y, element.ActualWidth, element.ActualHeight);
        }
        catch (ArgumentException) { return null; }
    }

    private static bool SameSurfaces(Rect[] a, List<Rect> b) =>
        a.Length == b.Count && a.Zip(b).All(p => Math.Abs(p.First.X - p.Second.X) < 1 && Math.Abs(p.First.Y - p.Second.Y) < 1 && Math.Abs(p.First.Width - p.Second.Width) < 1);

    // ---------- tree (drawn once, in its own 1200×320 scene scaled into the band) ----------

    private void DrawTree()
    {
        var bark = new SolidColorBrush(Color.FromArgb(255, 98, 54, 100));
        var barkLight = new SolidColorBrush(Color.FromArgb(255, 176, 116, 178));
        Branch(new Point(26, TreeSceneHeight + 12), -70, 150, 40, 0, bark, barkLight);
        // A dense canopy band across the upper left, like blossoms hanging over the page.
        for (var x = 0.0; x < 760; x += 16)
        {
            var reach = 1 - x / 760;
            if (_random.NextDouble() > 0.35 + reach * 0.6) continue;
            _blossomSpots.Add(new Point(x + _random.NextDouble() * 10, 6 + _random.NextDouble() * (40 + reach * 60)));
        }
        foreach (var spot in _blossomSpots.ToArray())
        {
            var count = _random.Next(10, 18);
            for (var i = 0; i < count; i++)
            {
                var angle = _random.NextDouble() * Math.PI * 2;
                var distance = Math.Sqrt(_random.NextDouble()) * 30;
                var size = 2.5 + _random.NextDouble() * 6.5;
                var blossom = new Ellipse { Width = size, Height = size, Fill = new SolidColorBrush(Blossom((byte)_random.Next(170, 255))) };
                Canvas.SetLeft(blossom, spot.X + Math.Cos(angle) * distance - size / 2);
                Canvas.SetTop(blossom, spot.Y + Math.Sin(angle) * distance * 0.7 - size / 2);
                _treeScene.Children.Add(blossom);
            }
        }
    }

    private void Branch(Point start, double angleDegrees, double length, double thickness, int depth, Brush bark, Brush barkLight)
    {
        var angle = angleDegrees * Math.PI / 180;
        var bend = (_random.NextDouble() - 0.5) * 0.6;
        var end = new Point(start.X + Math.Cos(angle) * length, start.Y + Math.Sin(angle) * length);
        var control = new Point(start.X + Math.Cos(angle + bend) * length * 0.55, start.Y + Math.Sin(angle + bend) * length * 0.55);
        foreach (var (brush, width, offset) in new[] { (bark, thickness, 0.0), (barkLight, Math.Max(1, thickness * 0.28), -thickness * 0.18) })
        {
            var figure = new PathFigure { StartPoint = new Point(start.X + offset, start.Y) };
            figure.Segments.Add(new QuadraticBezierSegment { Point1 = new Point(control.X + offset, control.Y), Point2 = new Point(end.X + offset, end.Y) });
            var geometry = new PathGeometry();
            geometry.Figures.Add(figure);
            _treeScene.Children.Add(new Microsoft.UI.Xaml.Shapes.Path
            {
                Data = geometry, Stroke = brush, StrokeThickness = width, StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round,
            });
        }
        if (depth >= 2) _blossomSpots.Add(end);
        if (depth >= 5 || thickness < 1.4) { _blossomSpots.Add(end); return; }
        var children = depth == 0 ? 3 : _random.NextDouble() < 0.45 ? 3 : 2;
        for (var i = 0; i < children; i++)
        {
            var spread = depth == 0 ? new[] { -26.0, 12.0, 44.0 }[i] : (_random.NextDouble() - 0.35) * 70;
            Branch(end, angleDegrees + spread + (depth == 0 ? 0 : 6), length * (0.62 + _random.NextDouble() * 0.2), thickness * 0.62, depth + 1, bark, barkLight);
        }
    }

    // ---------- Kuro ----------

    private static readonly Color FurColor = Color.FromArgb(255, 9, 6, 14);
    private static readonly Color RimColor = Color.FromArgb(215, 255, 150, 214);

    private (Ellipse LeftEye, Ellipse RightEye) DrawCat()
    {
        var fur = new SolidColorBrush(FurColor);
        // A pink neon rim light so the black silhouette reads against the dark storm backdrop.
        var rim = new SolidColorBrush(RimColor);
        var sheen = new SolidColorBrush(Color.FromArgb(46, 196, 170, 255));
        var random = new Random(7);

        // Soft contact shadow where he sits on the card.
        var shadow = new Ellipse
        {
            Width = 86, Height = 12,
            Fill = new RadialGradientBrush
            {
                GradientStops = { new GradientStop { Color = Color.FromArgb(150, 0, 0, 0), Offset = 0 }, new GradientStop { Color = Color.FromArgb(0, 0, 0, 0), Offset = 1 } },
            },
        };
        Canvas.SetLeft(shadow, 2);
        Canvas.SetTop(shadow, 112);
        _cat.Children.Add(shadow);

        // Tail: a tapered base segment that swishes, with a tip segment that curls and flicks on its own.
        var tail = new Canvas { RenderTransform = _tailRotation };
        var baseLine = Bezier(new Point(0, 0), new Point(16, 2), new Point(22, 20), new Point(16, 38), 14);
        tail.Children.Add(Tapered(baseLine, 10.5, 7.5, rim, null, 1));
        tail.Children.Add(Tapered(baseLine, 8.5, 5.5, fur, null, 0));
        var tip = new Canvas { RenderTransform = _tailTip };
        var tipLine = Bezier(new Point(0, 0), new Point(-4, 10), new Point(-2, 22), new Point(7, 29), 12);
        tip.Children.Add(Tapered(tipLine, 7.5, 3.5, rim, null, 1));
        tip.Children.Add(Tapered(tipLine, 5.5, 1.8, fur, null, 0));
        Canvas.SetLeft(tip, 16);
        Canvas.SetTop(tip, 38);
        _tailTip.CenterX = 0;
        _tailTip.CenterY = 0;
        tail.Children.Add(tip);
        Canvas.SetLeft(tail, 64);
        Canvas.SetTop(tail, 108);
        _cat.Children.Add(tail);

        // Body seen from behind: narrow shoulders, a waist, then rounded haunches tucked under him.
        var body = new PathFigure { StartPoint = new Point(36, 50), IsClosed = true, IsFilled = true };
        body.Segments.Add(new BezierSegment { Point1 = new Point(28, 56), Point2 = new Point(24, 66), Point3 = new Point(23, 76) });
        body.Segments.Add(new BezierSegment { Point1 = new Point(10, 86), Point2 = new Point(6, 104), Point3 = new Point(14, 114) });
        body.Segments.Add(new BezierSegment { Point1 = new Point(26, 120), Point2 = new Point(64, 120), Point3 = new Point(76, 114) });
        body.Segments.Add(new BezierSegment { Point1 = new Point(84, 104), Point2 = new Point(80, 86), Point3 = new Point(67, 76) });
        body.Segments.Add(new BezierSegment { Point1 = new Point(66, 66), Point2 = new Point(62, 56), Point3 = new Point(54, 50) });
        body.Segments.Add(new BezierSegment { Point1 = new Point(48, 47), Point2 = new Point(42, 47), Point3 = new Point(36, 50) });
        var bodyGeometry = new PathGeometry();
        bodyGeometry.Figures.Add(body);
        _breath.CenterX = 45;
        _breath.CenterY = 118;
        var torso = new Canvas { RenderTransform = _breath };
        torso.Children.Add(new Microsoft.UI.Xaml.Shapes.Path { Data = bodyGeometry, Fill = fur, Stroke = rim, StrokeThickness = 1.6 });
        // Faint sheen along the spine and over each haunch gives the silhouette form.
        torso.Children.Add(Curve(new Point(45, 54), new Point(44, 72), new Point(46, 94), sheen, 2.2));
        torso.Children.Add(Curve(new Point(20, 92), new Point(17, 100), new Point(22, 110), sheen, 1.6));
        torso.Children.Add(Curve(new Point(70, 92), new Point(73, 100), new Point(68, 110), sheen, 1.6));
        // Fur texture: short tufts breaking the outline at the haunches and shoulders.
        foreach (var (x, y, dx, dy) in new[] { (12.0, 98.0, -3.0, 1.0), (9.0, 104.0, -3.0, 2.0), (78.0, 98.0, 3.0, 1.0), (81.0, 104.0, 3.0, 2.0),
                     (25.0, 72.0, -2.5, 1.5), (65.0, 72.0, 2.5, 1.5), (22.0, 80.0, -3.0, 0.5), (68.0, 80.0, 3.0, 0.5) })
        {
            var jitter = random.NextDouble() * 1.4;
            torso.Children.Add(new Line { X1 = x, Y1 = y, X2 = x + dx - jitter, Y2 = y + dy, Stroke = rim, StrokeThickness = 1, Opacity = 0.75 });
        }
        _cat.Children.Add(torso);

        // Head: wider than tall, with cheek ruff, rounded ears with pink inner ears and tufts.
        _headTilt.CenterX = 30;
        _headTilt.CenterY = 44;
        var head = new Canvas { Width = 60, Height = 56, RenderTransform = new TransformGroup { Children = { _headTilt, _headShift } } };
        Canvas.SetLeft(head, 15);
        Canvas.SetTop(head, 2);
        head.Children.Add(Ear(new Point(9, 26), new Point(13, 1), new Point(30, 17), _leftEar, 18, 20, rim));
        head.Children.Add(Ear(new Point(30, 17), new Point(47, 1), new Point(51, 26), _rightEar, 42, 20, rim));
        foreach (var (cx, cy, w, h) in new[] { (12.0, 34.0, 16.0, 14.0), (48.0, 34.0, 16.0, 14.0) }) // cheek ruff
        {
            var cheek = new Ellipse { Width = w, Height = h, Fill = fur, Stroke = rim, StrokeThickness = 1.2 };
            Canvas.SetLeft(cheek, cx - w / 2);
            Canvas.SetTop(cheek, cy - h / 2);
            head.Children.Add(cheek);
        }
        var skull = new Ellipse { Width = 46, Height = 38, Fill = fur, Stroke = rim, StrokeThickness = 1.4 };
        Canvas.SetLeft(skull, 7);
        Canvas.SetTop(skull, 13);
        head.Children.Add(skull);
        // Cover the cheek outlines inside the skull so only the outer ruff edge glows.
        var inner = new Ellipse { Width = 42, Height = 33, Fill = fur };
        Canvas.SetLeft(inner, 9);
        Canvas.SetTop(inner, 15);
        head.Children.Add(inner);
        head.Children.Add(Curve(new Point(22, 18), new Point(30, 15), new Point(38, 18), sheen, 1.6)); // crown sheen
        var whisker = new SolidColorBrush(Color.FromArgb(160, 255, 236, 246));
        foreach (var (x1, y1, cx, cy, x2, y2) in new[]
                 {
                     (9.0, 36.0, -2.0, 33.0, -15.0, 33.0), (9.0, 39.0, -3.0, 39.0, -16.0, 42.0), (10.0, 41.0, 0.0, 44.0, -11.0, 49.0),
                     (51.0, 36.0, 62.0, 33.0, 75.0, 33.0), (51.0, 39.0, 63.0, 39.0, 76.0, 42.0), (50.0, 41.0, 60.0, 44.0, 71.0, 49.0),
                 })
            head.Children.Add(Curve(new Point(x1, y1), new Point(cx, cy), new Point(x2, y2), whisker, 0.7));
        var eyeBrush = new RadialGradientBrush
        {
            GradientStops =
            {
                new GradientStop { Color = Color.FromArgb(255, 255, 246, 170), Offset = 0 },
                new GradientStop { Color = Color.FromArgb(255, 255, 196, 60), Offset = 0.55 },
                new GradientStop { Color = Color.FromArgb(255, 214, 120, 20), Offset = 1 },
            },
        };
        _eyeScale.CenterY = 2.5;
        var leftEye = new Ellipse { Width = 7.5, Height = 5, Fill = eyeBrush, Opacity = 0, RenderTransform = _eyeScale };
        var rightEye = new Ellipse { Width = 7.5, Height = 5, Fill = eyeBrush, Opacity = 0, RenderTransform = _eyeScale };
        Canvas.SetLeft(leftEye, 18); Canvas.SetTop(leftEye, 29);
        Canvas.SetLeft(rightEye, 34.5); Canvas.SetTop(rightEye, 29);
        // Face (shown with the eyes when he turns toward you): pink nose with a soft highlight, the muzzle line and a small "w" mouth.
        var noseFigure = new PathFigure { StartPoint = new Point(27.2, 36.2), IsClosed = true, IsFilled = true };
        noseFigure.Segments.Add(new QuadraticBezierSegment { Point1 = new Point(30, 35.2), Point2 = new Point(32.8, 36.2) });
        noseFigure.Segments.Add(new QuadraticBezierSegment { Point1 = new Point(31.6, 38.6), Point2 = new Point(30, 39.4) });
        noseFigure.Segments.Add(new QuadraticBezierSegment { Point1 = new Point(28.4, 38.6), Point2 = new Point(27.2, 36.2) });
        var noseGeometry = new PathGeometry();
        noseGeometry.Figures.Add(noseFigure);
        _face.Children.Add(new Microsoft.UI.Xaml.Shapes.Path
        {
            Data = noseGeometry, Stroke = new SolidColorBrush(Color.FromArgb(200, 120, 40, 80)), StrokeThickness = 0.5,
            Fill = new LinearGradientBrush
            {
                StartPoint = new Point(0.5, 0), EndPoint = new Point(0.5, 1),
                GradientStops = { new GradientStop { Color = Color.FromArgb(255, 255, 170, 205), Offset = 0 }, new GradientStop { Color = Color.FromArgb(255, 214, 96, 150), Offset = 1 } },
            },
        });
        var noseHighlight = new Ellipse { Width = 1.6, Height = 0.9, Fill = new SolidColorBrush(Color.FromArgb(220, 255, 236, 246)) };
        Canvas.SetLeft(noseHighlight, 28.6);
        Canvas.SetTop(noseHighlight, 36.1);
        _face.Children.Add(noseHighlight);
        var mouthBrush = new SolidColorBrush(Color.FromArgb(190, 255, 170, 214));
        _face.Children.Add(new Line { X1 = 30, Y1 = 39.4, X2 = 30, Y2 = 41.2, Stroke = mouthBrush, StrokeThickness = 0.7 });
        _face.Children.Add(Curve(new Point(30, 41.2), new Point(28.6, 42.8), new Point(26.8, 41.8), mouthBrush, 0.7));
        _face.Children.Add(Curve(new Point(30, 41.2), new Point(31.4, 42.8), new Point(33.2, 41.8), mouthBrush, 0.7));
        foreach (var (x, y) in new[] { (24.5, 39.5), (23.0, 41.0), (35.5, 39.5), (37.0, 41.0) }) // whisker pads
        {
            var dot = new Ellipse { Width = 0.9, Height = 0.9, Fill = new SolidColorBrush(Color.FromArgb(120, 255, 200, 230)) };
            Canvas.SetLeft(dot, x);
            Canvas.SetTop(dot, y);
            _face.Children.Add(dot);
        }
        head.Children.Add(_face);
        head.Children.Add(leftEye);
        head.Children.Add(rightEye);
        _cat.Children.Add(head);
        return (leftEye, rightEye);
    }

    private static Canvas Ear(Point baseOuter, Point tip, Point baseInner, RotateTransform rotation, double pivotX, double pivotY, Brush rim)
    {
        rotation.CenterX = pivotX;
        rotation.CenterY = pivotY;
        // Rounded tip and slightly convex sides, then a pink inner ear and a few tufts drawn in the same geometry group.
        var outer = new PathFigure { StartPoint = baseOuter, IsClosed = true, IsFilled = true };
        var nearTipA = Lerp(baseOuter, tip, 0.86);
        var nearTipB = Lerp(baseInner, tip, 0.86);
        outer.Segments.Add(new QuadraticBezierSegment { Point1 = Offset(Lerp(baseOuter, tip, 0.5), baseOuter.X < baseInner.X ? -2 : 2, 0), Point2 = nearTipA });
        outer.Segments.Add(new QuadraticBezierSegment { Point1 = tip, Point2 = nearTipB });
        outer.Segments.Add(new QuadraticBezierSegment { Point1 = Lerp(baseInner, tip, 0.5), Point2 = baseInner });
        var geometry = new PathGeometry();
        geometry.Figures.Add(outer);
        var group = new Canvas { RenderTransform = rotation };
        group.Children.Add(new Microsoft.UI.Xaml.Shapes.Path { Data = geometry, Fill = new SolidColorBrush(FurColor), Stroke = rim, StrokeThickness = 1.4 });
        var innerFigure = new PathFigure { StartPoint = Lerp(baseOuter, baseInner, 0.22), IsClosed = true, IsFilled = true };
        innerFigure.Segments.Add(new QuadraticBezierSegment { Point1 = Lerp(Lerp(baseOuter, baseInner, 0.3), tip, 0.6), Point2 = Lerp(Lerp(baseOuter, baseInner, 0.5), tip, 0.78) });
        innerFigure.Segments.Add(new QuadraticBezierSegment { Point1 = Lerp(Lerp(baseOuter, baseInner, 0.7), tip, 0.6), Point2 = Lerp(baseOuter, baseInner, 0.78) });
        var innerGeometry = new PathGeometry();
        innerGeometry.Figures.Add(innerFigure);
        group.Children.Add(new Microsoft.UI.Xaml.Shapes.Path { Data = innerGeometry, Fill = new SolidColorBrush(Color.FromArgb(120, 150, 60, 110)) });
        var mid = Lerp(baseOuter, baseInner, 0.5);
        foreach (var t in new[] { 0.35, 0.5, 0.65 }) // ear tufts
        {
            var from = Lerp(Lerp(baseOuter, baseInner, t), mid, 0.2);
            group.Children.Add(new Line { X1 = from.X, Y1 = from.Y, X2 = from.X + (t - 0.5) * 4, Y2 = from.Y - 6, Stroke = new SolidColorBrush(Color.FromArgb(150, 255, 210, 236)), StrokeThickness = 0.6 });
        }
        return group;
    }

    private static Point Lerp(Point a, Point b, double t) => new(a.X + (b.X - a.X) * t, a.Y + (b.Y - a.Y) * t);
    private static Point Offset(Point p, double dx, double dy) => new(p.X + dx, p.Y + dy);

    private static Point[] Bezier(Point p0, Point p1, Point p2, Point p3, int steps)
    {
        var points = new Point[steps + 1];
        for (var i = 0; i <= steps; i++)
        {
            var t = (double)i / steps;
            var u = 1 - t;
            points[i] = new Point(
                u * u * u * p0.X + 3 * u * u * t * p1.X + 3 * u * t * t * p2.X + t * t * t * p3.X,
                u * u * u * p0.Y + 3 * u * u * t * p1.Y + 3 * u * t * t * p2.Y + t * t * t * p3.Y);
        }
        return points;
    }

    /// <summary>A filled ribbon along a centerline whose width tapers from <paramref name="startWidth"/> to <paramref name="endWidth"/>.</summary>
    private static Microsoft.UI.Xaml.Shapes.Path Tapered(Point[] line, double startWidth, double endWidth, Brush fill, Brush? stroke, double strokeWidth)
    {
        var left = new List<Point>();
        var right = new List<Point>();
        for (var i = 0; i < line.Length; i++)
        {
            var a = line[Math.Max(0, i - 1)];
            var b = line[Math.Min(line.Length - 1, i + 1)];
            var dx = b.X - a.X;
            var dy = b.Y - a.Y;
            var length = Math.Max(0.001, Math.Sqrt(dx * dx + dy * dy));
            var half = (startWidth + (endWidth - startWidth) * i / (line.Length - 1)) / 2;
            left.Add(new Point(line[i].X - dy / length * half, line[i].Y + dx / length * half));
            right.Add(new Point(line[i].X + dy / length * half, line[i].Y - dx / length * half));
        }
        var figure = new PathFigure { StartPoint = left[0], IsClosed = true, IsFilled = true };
        foreach (var point in left.Skip(1)) figure.Segments.Add(new LineSegment { Point = point });
        // Rounded tip.
        figure.Segments.Add(new ArcSegment { Point = right[^1], Size = new Size(endWidth / 2, endWidth / 2), SweepDirection = SweepDirection.Clockwise });
        foreach (var point in Enumerable.Reverse(right).Skip(1)) figure.Segments.Add(new LineSegment { Point = point });
        var geometry = new PathGeometry();
        geometry.Figures.Add(figure);
        return new Microsoft.UI.Xaml.Shapes.Path { Data = geometry, Fill = fill, Stroke = stroke, StrokeThickness = stroke is null ? 0 : strokeWidth, StrokeLineJoin = PenLineJoin.Round };
    }

    private static Microsoft.UI.Xaml.Shapes.Path Curve(Point from, Point control, Point to, Brush brush, double thickness)
    {
        var figure = new PathFigure { StartPoint = from };
        figure.Segments.Add(new QuadraticBezierSegment { Point1 = control, Point2 = to });
        var geometry = new PathGeometry();
        geometry.Figures.Add(figure);
        return new Microsoft.UI.Xaml.Shapes.Path { Data = geometry, Stroke = brush, StrokeThickness = thickness, StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round };
    }

    // ---------- animation ----------

    private void SeedStillPetals()
    {
        // Reduce motion: a still scene with petals resting on card tops.
        foreach (var surface in _surfaces.Take(12))
        {
            for (var i = 0; i < 4; i++)
            {
                var petal = Spawn();
                petal.X = surface.X + _random.NextDouble() * surface.Width;
                petal.Y = surface.Y - 3;
                Settle(petal);
            }
        }
    }

    private void Tick()
    {
        if (!App.IsMainWindowVisible || _content is null) { _lastTick = DateTime.UtcNow; return; }
        var now = DateTime.UtcNow;
        var dt = Math.Clamp((now - _lastTick).TotalSeconds, 0, 0.1);
        _lastTick = now;
        _time += dt;

        // Petals per second rise from a gentle 1.5 to a blizzard of ~40 at full load.
        _spawnDebt += dt * (1.5 + _load * _load * 38 + _load * 6);
        while (_spawnDebt >= 1 && _falling.Count < MaximumFalling && _blossomSpots.Count > 0)
        {
            _spawnDebt -= 1;
            var petal = Spawn();
            var spot = _blossomSpots[_random.Next(_blossomSpots.Count)];
            petal.X = _treeOrigin.X + (spot.X + (_random.NextDouble() - 0.5) * 30) * _treeScale;
            petal.Y = _treeOrigin.Y + (spot.Y + (_random.NextDouble() - 0.5) * 16) * _treeScale;
            _falling.Add(petal);
        }
        if (_spawnDebt > 3) _spawnDebt = 3;

        var width = ActualWidth;
        var height = ActualHeight;
        var wind = 14 + 22 * Math.Sin(_time * 0.37) + _load * 26;
        for (var i = _falling.Count - 1; i >= 0; i--)
        {
            var p = _falling[i];
            var previousY = p.Y;
            if (p.Vy < 34) p.Vy += 90 * dt; // gravity pulls kicked petals back down to a gentle drift
            p.X += (p.Vx + wind + Math.Sin(_time * p.Sway + p.Phase) * 20) * dt;
            p.Y += p.Vy * dt;
            p.Transform.Rotation += p.Spin * dt;
            p.Transform.ScaleX = 0.55 + 0.45 * Math.Abs(Math.Sin(_time * p.Sway * 1.4 + p.Phase)); // tumbling
            if (p.X > width + 20 || p.X < -20 || p.Y > height + 10) { Recycle(p); _falling.RemoveAt(i); continue; }
            if (LandingTop(p.X, previousY, p.Y) is { } top)
            {
                _falling.RemoveAt(i);
                p.Y = top - 2 - _random.NextDouble() * 2;
                Settle(p);
                continue;
            }
            Place(p);
        }

        // Kuro: breathing, tail swish (faster when busy), ear twitches, glances back.
        _breath.ScaleY = 1 + 0.018 * Math.Sin(_time * 1.6);
        _breath.ScaleX = 1 - 0.008 * Math.Sin(_time * 1.6);
        var tailSpeed = 1.1 + _load * 4.5 + (_threats > 0 ? 2 : 0);
        _tailRotation.Angle = Math.Sin(_time * tailSpeed) * (22 + _load * 12) + Math.Sin(_time * tailSpeed * 2.3) * 4;
        SweepPetals();

        // Tail tip curls with the swish and gives an extra flick now and then (more often when restless).
        if (_time >= _nextFlick)
        {
            _flickUntil = _time + 0.35;
            _nextFlick = _time + (_load > 0.55 || _threats > 0 ? 1.5 : 4) + _random.NextDouble() * 4;
        }
        var flick = _time < _flickUntil ? Math.Sin((_flickUntil - _time) / 0.35 * Math.PI) * 38 : 0;
        _tailTip.Angle = Math.Sin(_time * tailSpeed * 1.7 + 0.8) * 22 + flick;

        // Ears swivel independently toward sounds; both turn forward and slightly out when on guard.
        if (_time >= _nextLeftEar)
        {
            _leftEarUntil = _time + 0.6 + _random.NextDouble() * 1.4;
            _leftEarAngle = -8 - _random.NextDouble() * 16;
            _nextLeftEar = _time + 2 + _random.NextDouble() * (_threats > 0 ? 2 : 6);
        }
        if (_time >= _nextRightEar)
        {
            _rightEarUntil = _time + 0.6 + _random.NextDouble() * 1.4;
            _rightEarAngle = 8 + _random.NextDouble() * 16;
            _nextRightEar = _time + 2 + _random.NextDouble() * (_threats > 0 ? 2 : 6);
        }
        var leftTarget = _time < _leftEarUntil ? _leftEarAngle : _threats > 0 ? -5 : 0;
        var rightTarget = _time < _rightEarUntil ? _rightEarAngle : _threats > 0 ? 5 : 0;
        _leftEar.Angle += (leftTarget - _leftEar.Angle) * Math.Min(1, dt * 14);
        _rightEar.Angle += (rightTarget - _rightEar.Angle) * Math.Min(1, dt * 14);

        // Curious head tilts.
        if (_time >= _nextTilt)
        {
            _tiltUntil = _time + 1.2 + _random.NextDouble() * 1.5;
            _tiltTarget = (_random.NextDouble() < 0.5 ? -1 : 1) * (5 + _random.NextDouble() * 6);
            _nextTilt = _time + 7 + _random.NextDouble() * 10;
        }
        _headTilt.Angle += ((_time < _tiltUntil ? _tiltTarget : 0) - _headTilt.Angle) * Math.Min(1, dt * 4);

        // Faces you (owner request); now and then looks away at the blossoms for a moment, never while threats are open.
        if (_time >= _nextGlance)
        {
            _glanceUntil = _time + 2.2;
            _nextGlance = _time + 16 + _random.NextDouble() * 20;
        }
        var glancing = _time >= _glanceUntil || _threats > 0;
        _headShift.X += ((glancing ? -5 : 0) - _headShift.X) * Math.Min(1, dt * 6);
        SetEyes(glancing);
        // Quick blinks, and when calm a slow blink (a cat's sign of trust).
        if (_time >= _nextBlink)
        {
            _blinkUntil = _time + 0.14;
            _nextBlink = _time + 2.5 + _random.NextDouble() * 4;
        }
        if (_time >= _nextSlowBlink && glancing && _threats == 0 && _load < 0.4)
        {
            _slowBlinkUntil = _time + 1.4;
            _nextSlowBlink = _time + 25 + _random.NextDouble() * 20;
        }
        var openness = _time < _slowBlinkUntil ? 0.15 + 0.85 * Math.Abs(Math.Cos((_slowBlinkUntil - _time) / 1.4 * Math.PI)) : _time < _blinkUntil ? 0.1 : 1;
        _eyeScale.ScaleY = openness;
    }

    /// <summary>The top edge of the first card a petal crosses this frame, if any.</summary>
    private double? LandingTop(double x, double previousY, double y)
    {
        foreach (var surface in _surfaces)
        {
            if (surface.Y > y) break; // sorted by top
            if (surface.Y >= previousY && x >= surface.X && x <= surface.X + surface.Width) return surface.Y;
        }
        return null;
    }

    private void SetEyes(bool visible)
    {
        _leftEye.Opacity = visible ? 1 : 0;
        _face.Opacity = visible ? 1 : 0;
        _rightEye.Opacity = visible ? 1 : 0;
    }

    /// <summary>The tail tip pushes settled petals aside, so they scatter as Kuro swishes.</summary>
    private void SweepPetals()
    {
        var angle = _tailRotation.Angle * Math.PI / 180;
        var tipX = _catOrigin.X + (62 + 16 * Math.Cos(angle) - 64 * Math.Sin(angle)) * CatScale;
        var tipY = _catOrigin.Y + (108 + 16 * Math.Sin(angle) + 64 * Math.Cos(angle)) * CatScale;
        var baseX = _catOrigin.X + 62 * CatScale;
        var baseY = _catOrigin.Y + 108 * CatScale;
        for (var i = _settled.Count - 1; i >= 0; i--)
        {
            var p = _settled[i];
            // Petals near the tail tip, or resting right where the tail drapes over the card's edge.
            var near = Near(p, tipX, tipY, 18) || Near(p, (baseX + tipX) / 2, (baseY + tipY) / 2, 14);
            if (!near) continue;
            _settled.RemoveAt(i);
            p.Vx = (p.X >= tipX ? 1 : -1) * (40 + _random.NextDouble() * 50);
            p.Vy = -40 - _random.NextDouble() * 40;
            p.Y -= 5;
            _falling.Add(p);
        }
    }

    private static bool Near(Petal p, double x, double y, double radius) => (p.X - x) * (p.X - x) + (p.Y - y) * (p.Y - y) <= radius * radius;

    private Petal Spawn()
    {
        var shape = _pool.Count > 0 ? _pool.Dequeue() : new Ellipse { IsHitTestVisible = false };
        // A pooled shape may still belong to a layer from an earlier attach; never re-parent it.
        if (shape.Parent is { } parent && !ReferenceEquals(parent, _petalLayer)) shape = new Ellipse { IsHitTestVisible = false };
        var size = 4 + _random.NextDouble() * 4;
        shape.Width = size;
        shape.Height = size * 0.62;
        shape.Fill = _petalBrushes[_random.Next(_petalBrushes.Length)];
        shape.Opacity = 1;
        var transform = new CompositeTransform { CenterX = size / 2, CenterY = size * 0.31, Rotation = _random.NextDouble() * 360 };
        shape.RenderTransform = transform;
        if (shape.Parent is null && !_petalLayer.Children.Contains(shape))
        {
            try { _petalLayer.Children.Add(shape); }
            catch (System.Runtime.InteropServices.COMException)
            {
                shape = new Ellipse { IsHitTestVisible = false, Width = shape.Width, Height = shape.Height, Fill = shape.Fill, RenderTransform = transform };
                _petalLayer.Children.Add(shape);
            }
        }
        shape.Visibility = Visibility.Visible;
        return new Petal
        {
            Shape = shape, Transform = transform, Vx = -6 + _random.NextDouble() * 12, Vy = 22 + _random.NextDouble() * 22,
            Spin = (_random.NextDouble() - 0.5) * 220, Sway = 0.8 + _random.NextDouble() * 1.6, Phase = _random.NextDouble() * Math.PI * 2,
        };
    }

    private void Settle(Petal petal)
    {
        petal.Vx = petal.Vy = 0;
        petal.Transform.ScaleX = 1;
        petal.Shape.Opacity = 0.85;
        Place(petal);
        _settled.Add(petal);
        while (_settled.Count > MaximumSettled)
        {
            Recycle(_settled[0]);
            _settled.RemoveAt(0);
        }
    }

    private void Recycle(Petal petal)
    {
        petal.Shape.Visibility = Visibility.Collapsed;
        _pool.Enqueue(petal.Shape);
    }

    /// <summary>Moves a petal through its render transform only (composited, no layout pass).</summary>
    private static void Place(Petal petal)
    {
        petal.Transform.TranslateX = petal.X;
        petal.Transform.TranslateY = petal.Y;
    }

    private Color Blossom(byte alpha)
    {
        var palette = new[] { (255, 143, 200), (255, 111, 176), (247, 182, 217), (224, 90, 159), (255, 200, 228), (236, 120, 190) };
        var (r, g, b) = palette[_random.Next(palette.Length)];
        return Color.FromArgb(alpha, (byte)r, (byte)g, (byte)b);
    }

    private static LinearGradientBrush Gradient(Color from, Color to) => new()
    {
        StartPoint = new Point(0, 0), EndPoint = new Point(1, 1),
        GradientStops = { new GradientStop { Color = from, Offset = 0 }, new GradientStop { Color = to, Offset = 1 } },
    };
}
