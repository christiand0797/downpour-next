using Microsoft.UI;
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
/// "Sakura Sentinel": a procedurally drawn sunset with a cherry tree, misty mountains and Kuro, a black cat on a rock
/// ledge. Petals fall faster the busier the PC is; Kuro's tail swishes through the fallen petals (faster under load),
/// his ears twitch, he breathes, and now and then glances back. When threats are open he stays on guard with eyes
/// lit. Everything is vector-drawn so it stays sharp at any size; motion stops when Reduce motion is on or the page
/// is hidden. The load and mood are also stated in text, so nothing depends on seeing the animation.
/// </summary>
public sealed class BlossomScene : UserControl
{
    private const double SceneWidth = 1200;
    private const double SceneHeight = 320;
    private const double LedgeTop = 268;
    private const double LedgeLeft = 640;
    private const int MaximumFalling = 220;
    private const int MaximumSettled = 160;

    private readonly Canvas _canvas = new() { Width = SceneWidth, Height = SceneHeight };
    private readonly Canvas _petalLayer = new() { Width = SceneWidth, Height = SceneHeight, IsHitTestVisible = false };
    private readonly Random _random = new(29);
    private readonly List<Petal> _falling = [];
    private readonly List<Petal> _settled = [];
    private readonly Queue<Ellipse> _pool = new();
    private readonly List<Point> _blossomSpots = [];
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromMilliseconds(33) };
    private readonly Brush[] _petalBrushes;
    private readonly RotateTransform _tailRotation = new();
    private readonly RotateTransform _leftEar = new();
    private readonly RotateTransform _rightEar = new();
    private readonly ScaleTransform _breath = new() { CenterX = 0, CenterY = 52 };
    private readonly TranslateTransform _headShift = new();
    private readonly Ellipse _leftEye;
    private readonly Ellipse _rightEye;
    private readonly TextBlock _status;
    private readonly bool _animate;
    private double _load = 0.15;
    private int _threats;
    private double _time;
    private double _spawnDebt;
    private double _nextTwitch = 3;
    private double _twitchUntil;
    private double _nextGlance = 9;
    private double _glanceUntil;
    private DateTime _lastTick = DateTime.UtcNow;

    private sealed class Petal
    {
        public required Ellipse Shape { get; init; }
        public required CompositeTransform Transform { get; init; }
        public double X, Y, Vx, Vy, Spin, Sway, Phase, Age;
    }

    public BlossomScene()
    {
        Height = 260;
        HorizontalAlignment = HorizontalAlignment.Stretch;
        _animate = !AppPreferences.ReduceMotion && new Windows.UI.ViewManagement.UISettings().AnimationsEnabled;
        _petalBrushes =
        [
            Gradient(Color.FromArgb(255, 255, 196, 222), Color.FromArgb(255, 255, 122, 182)),
            Gradient(Color.FromArgb(255, 255, 214, 232), Color.FromArgb(255, 247, 150, 200)),
            Gradient(Color.FromArgb(255, 255, 160, 205), Color.FromArgb(255, 224, 82, 152)),
            Gradient(Color.FromArgb(235, 255, 236, 244), Color.FromArgb(235, 255, 176, 214)),
        ];

        DrawSky();
        DrawMountains();
        DrawTree();
        DrawLedge();
        (_leftEye, _rightEye) = DrawCat();
        _canvas.Children.Add(_petalLayer);

        _status = new TextBlock
        {
            FontFamily = new FontFamily("Bahnschrift"), FontSize = 12, CharacterSpacing = 120, Foreground = new SolidColorBrush(Color.FromArgb(235, 255, 240, 248)),
            Margin = new Thickness(18, 0, 0, 0), HorizontalAlignment = HorizontalAlignment.Left, VerticalAlignment = VerticalAlignment.Top, IsHitTestVisible = false,
        };
        var title = new TextBlock
        {
            Text = "SAKURA SENTINEL", FontFamily = new FontFamily("Bahnschrift"), FontSize = 11, FontWeight = FontWeights.SemiBold, CharacterSpacing = 300,
            Foreground = new SolidColorBrush(Color.FromArgb(255, 255, 214, 236)), Margin = new Thickness(18, 0, 0, 0), IsHitTestVisible = false,
        };
        var labelStack = new StackPanel { Spacing = 2, Padding = new Thickness(0, 10, 18, 10) };
        labelStack.Children.Add(title);
        labelStack.Children.Add(_status);
        // A soft dark backing keeps the status legible over blossoms, sky or sun.
        var labels = new Border
        {
            Child = labelStack, CornerRadius = new CornerRadius(0, 0, 6, 0), IsHitTestVisible = false,
            HorizontalAlignment = HorizontalAlignment.Left, VerticalAlignment = VerticalAlignment.Top,
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

        var frame = new Border
        {
            CornerRadius = new CornerRadius(4), BorderThickness = new Thickness(1),
            BorderBrush = (Brush)Application.Current.Resources["HudEdgeBrush"],
            Child = new Grid { Children = { new Viewbox { Stretch = Stretch.UniformToFill, Child = _canvas }, labels } },
        };
        Content = frame;
        AutomationProperties.SetName(this, "Sakura Sentinel: cherry blossom scene whose petals fall faster as system load rises");
        UpdateStatus();
        SeedSettledPetals();

        _timer.Tick += (_, _) => Tick();
        Loaded += (_, _) => { _lastTick = DateTime.UtcNow; if (_animate) _timer.Start(); };
        Unloaded += (_, _) => _timer.Stop();
    }

    /// <summary>Load 0–100 (CPU and memory combined by the caller); drives petal fall and tail speed.</summary>
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
        if (!_animate) SetEyes(_threats > 0);
    }

    private void UpdateStatus()
    {
        var mood = _threats > 0 ? $"on guard · {_threats} open threat{(_threats == 1 ? "" : "s")}"
            : _load < 0.25 ? "calm" : _load < 0.55 ? "curious" : _load < 0.8 ? "restless" : "hunting the storm";
        _status.Text = $"LOAD {_load * 100:0}%  ·  KURO IS {mood.ToUpperInvariant()}";
    }

    // ---------- static scenery ----------

    private void DrawSky()
    {
        _canvas.Children.Add(new Rectangle
        {
            Width = SceneWidth, Height = SceneHeight,
            Fill = new LinearGradientBrush
            {
                StartPoint = new Point(0, 0), EndPoint = new Point(0, 1),
                GradientStops =
                {
                    new GradientStop { Color = Color.FromArgb(255, 33, 12, 52), Offset = 0 },
                    new GradientStop { Color = Color.FromArgb(255, 104, 38, 110), Offset = 0.32 },
                    new GradientStop { Color = Color.FromArgb(255, 226, 98, 146), Offset = 0.56 },
                    new GradientStop { Color = Color.FromArgb(255, 255, 170, 128), Offset = 0.7 },
                    new GradientStop { Color = Color.FromArgb(255, 194, 120, 188), Offset = 0.86 },
                    new GradientStop { Color = Color.FromArgb(255, 92, 50, 120), Offset = 1 },
                },
            },
        });
        // A few early stars in the upper sky.
        for (var i = 0; i < 40; i++)
        {
            var size = _random.NextDouble() * 1.8 + 0.6;
            Add(new Ellipse { Width = size, Height = size, Fill = new SolidColorBrush(Color.FromArgb((byte)_random.Next(90, 200), 255, 236, 250)) },
                _random.NextDouble() * SceneWidth, _random.NextDouble() * 90);
        }
        // Sun with a soft halo.
        Add(new Ellipse
        {
            Width = 260, Height = 260,
            Fill = new RadialGradientBrush
            {
                GradientStops =
                {
                    new GradientStop { Color = Color.FromArgb(150, 255, 214, 170), Offset = 0 },
                    new GradientStop { Color = Color.FromArgb(60, 255, 150, 170), Offset = 0.45 },
                    new GradientStop { Color = Color.FromArgb(0, 255, 120, 170), Offset = 1 },
                },
            },
        }, 700 - 130, 196 - 130);
        Add(new Ellipse
        {
            Width = 74, Height = 74,
            Fill = new RadialGradientBrush
            {
                GradientStops =
                {
                    new GradientStop { Color = Color.FromArgb(255, 255, 255, 246), Offset = 0 },
                    new GradientStop { Color = Color.FromArgb(255, 255, 236, 206), Offset = 0.8 },
                    new GradientStop { Color = Color.FromArgb(255, 255, 206, 180), Offset = 1 },
                },
            },
        }, 700 - 37, 196 - 37);
    }

    private void DrawMountains()
    {
        var layers = new (double Base, double Amplitude, double Frequency, Color Color)[]
        {
            (214, 22, 0.011, Color.FromArgb(150, 190, 138, 200)),
            (232, 26, 0.017, Color.FromArgb(205, 150, 98, 170)),
            (252, 20, 0.023, Color.FromArgb(240, 104, 64, 136)),
        };
        var seed = 0.0;
        foreach (var (baseline, amplitude, frequency, color) in layers)
        {
            seed += 1.7;
            var figure = new PathFigure { StartPoint = new Point(0, SceneHeight), IsClosed = true, IsFilled = true };
            for (var x = 0.0; x <= SceneWidth; x += 12)
            {
                var y = baseline - amplitude * (0.6 * Math.Sin(x * frequency + seed) + 0.3 * Math.Sin(x * frequency * 2.3 + seed * 2) + 0.1 * Math.Sin(x * frequency * 5.1));
                figure.Segments.Add(new LineSegment { Point = new Point(x, y) });
            }
            figure.Segments.Add(new LineSegment { Point = new Point(SceneWidth, SceneHeight) });
            var geometry = new PathGeometry();
            geometry.Figures.Add(figure);
            _canvas.Children.Add(new Microsoft.UI.Xaml.Shapes.Path { Data = geometry, Fill = new SolidColorBrush(color) });
            // Mist drifting in front of each ridge.
            _canvas.Children.Add(new Rectangle
            {
                Width = SceneWidth, Height = 40, Opacity = 0.5,
                Fill = new LinearGradientBrush
                {
                    StartPoint = new Point(0, 0), EndPoint = new Point(0, 1),
                    GradientStops =
                    {
                        new GradientStop { Color = Color.FromArgb(0, 255, 220, 240), Offset = 0 },
                        new GradientStop { Color = Color.FromArgb(120, 255, 220, 240), Offset = 0.6 },
                        new GradientStop { Color = Color.FromArgb(0, 255, 220, 240), Offset = 1 },
                    },
                },
            });
            Canvas.SetTop(_canvas.Children[^1], baseline - 6);
        }
        // Blossoming bushes on the far left hill.
        for (var i = 0; i < 160; i++)
        {
            var x = 120 + _random.NextDouble() * 260;
            var y = 262 - Math.Sin((x - 120) / 260 * Math.PI) * 30 + _random.NextDouble() * 22;
            var size = 3 + _random.NextDouble() * 5;
            Add(new Ellipse { Width = size, Height = size, Fill = new SolidColorBrush(Blossom(150)) }, x, y);
        }
    }

    private void DrawTree()
    {
        var bark = new SolidColorBrush(Color.FromArgb(255, 46, 20, 44));
        var barkLight = new SolidColorBrush(Color.FromArgb(255, 84, 44, 78));
        // Trunk rising from the lower left and leaning over the scene.
        Branch(new Point(26, SceneHeight + 12), -70, 150, 40, 0, bark, barkLight);
        // A dense canopy band across the upper left, like blossoms hanging over the scene.
        for (var x = 0.0; x < 760; x += 16)
        {
            var reach = 1 - x / 760;
            if (_random.NextDouble() > 0.35 + reach * 0.6) continue;
            _blossomSpots.Add(new Point(x + _random.NextDouble() * 10, 6 + _random.NextDouble() * (40 + reach * 60)));
        }
        // Blossom clouds around every branch tip, drawn after branches so they sit on top.
        foreach (var spot in _blossomSpots.ToArray())
        {
            var count = _random.Next(10, 18);
            for (var i = 0; i < count; i++)
            {
                var angle = _random.NextDouble() * Math.PI * 2;
                var distance = Math.Sqrt(_random.NextDouble()) * 30;
                var size = 2.5 + _random.NextDouble() * 6.5;
                Add(new Ellipse { Width = size, Height = size, Fill = new SolidColorBrush(Blossom((byte)_random.Next(170, 255))) },
                    spot.X + Math.Cos(angle) * distance - size / 2, spot.Y + Math.Sin(angle) * distance * 0.7 - size / 2);
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
            _canvas.Children.Add(new Microsoft.UI.Xaml.Shapes.Path
            {
                Data = geometry, Stroke = brush, StrokeThickness = width, StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round,
            });
        }
        if (depth >= 2) _blossomSpots.Add(end);
        if (depth >= 5 || thickness < 1.4) { _blossomSpots.Add(end); return; }
        var children = depth == 0 ? 3 : _random.NextDouble() < 0.45 ? 3 : 2;
        for (var i = 0; i < children; i++)
        {
            // The canopy leans right toward the cat and the sun, like the reference painting.
            var spread = depth == 0 ? new[] { -26.0, 12.0, 44.0 }[i] : (_random.NextDouble() - 0.35) * 70;
            Branch(end, angleDegrees + spread + (depth == 0 ? 0 : 6), length * (0.62 + _random.NextDouble() * 0.2),
                thickness * 0.62, depth + 1, bark, barkLight);
        }
    }

    private void DrawLedge()
    {
        var figure = new PathFigure { StartPoint = new Point(LedgeLeft - 20, SceneHeight), IsClosed = true, IsFilled = true };
        foreach (var point in new[] { new Point(LedgeLeft, LedgeTop + 8), new Point(LedgeLeft + 60, LedgeTop - 2), new Point(820, LedgeTop - 6),
                     new Point(990, LedgeTop - 2), new Point(1050, LedgeTop + 10), new Point(1080, SceneHeight) })
            figure.Segments.Add(new LineSegment { Point = point });
        var geometry = new PathGeometry();
        geometry.Figures.Add(figure);
        _canvas.Children.Add(new Microsoft.UI.Xaml.Shapes.Path
        {
            Data = geometry,
            Fill = new LinearGradientBrush
            {
                StartPoint = new Point(0, 0), EndPoint = new Point(0, 1),
                GradientStops =
                {
                    new GradientStop { Color = Color.FromArgb(255, 118, 84, 120), Offset = 0 },
                    new GradientStop { Color = Color.FromArgb(255, 62, 38, 70), Offset = 0.25 },
                    new GradientStop { Color = Color.FromArgb(255, 30, 16, 38), Offset = 1 },
                },
            },
        });
        // Cracks and moss highlights.
        for (var i = 0; i < 14; i++)
        {
            var x = LedgeLeft + 30 + _random.NextDouble() * 360;
            Add(new Rectangle { Width = 14 + _random.NextDouble() * 40, Height = 1.2, Fill = new SolidColorBrush(Color.FromArgb(90, 20, 8, 26)) },
                x, LedgeTop + 8 + _random.NextDouble() * 34);
        }
    }

    private (Ellipse LeftEye, Ellipse RightEye) DrawCat()
    {
        var fur = new SolidColorBrush(Color.FromArgb(255, 10, 6, 16));
        const double baseX = 880, baseY = LedgeTop - 4;
        var cat = new Canvas { Width = 90, Height = 120 };
        Canvas.SetLeft(cat, baseX - 45);
        Canvas.SetTop(cat, baseY - 116);

        // Tail first so it sits behind the body; it hangs over the ledge and swishes.
        var tailFigure = new PathFigure { StartPoint = new Point(0, 0) };
        tailFigure.Segments.Add(new BezierSegment { Point1 = new Point(22, 6), Point2 = new Point(30, 34), Point3 = new Point(16, 64) });
        var tailGeometry = new PathGeometry();
        tailGeometry.Figures.Add(tailFigure);
        var tail = new Microsoft.UI.Xaml.Shapes.Path
        {
            Data = tailGeometry, Stroke = fur, StrokeThickness = 7, StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round,
            RenderTransform = _tailRotation,
        };
        Canvas.SetLeft(tail, 62);
        Canvas.SetTop(tail, 108);
        cat.Children.Add(tail);

        // Body: a rounded pear seen from behind, breathing gently.
        var body = new PathFigure { StartPoint = new Point(45, 52), IsClosed = true, IsFilled = true };
        body.Segments.Add(new BezierSegment { Point1 = new Point(80, 54), Point2 = new Point(86, 118), Point3 = new Point(45, 118) });
        body.Segments.Add(new BezierSegment { Point1 = new Point(4, 118), Point2 = new Point(10, 54), Point3 = new Point(45, 52) });
        var bodyGeometry = new PathGeometry();
        bodyGeometry.Figures.Add(body);
        var bodyShape = new Microsoft.UI.Xaml.Shapes.Path { Data = bodyGeometry, Fill = fur, RenderTransform = _breath };
        _breath.CenterX = 45;
        _breath.CenterY = 118;
        cat.Children.Add(bodyShape);

        // Head with twitching ears and whiskers; eyes appear when he glances back.
        var head = new Canvas { Width = 60, Height = 56, RenderTransform = _headShift };
        Canvas.SetLeft(head, 15);
        Canvas.SetTop(head, 6);
        head.Children.Add(Ear(new Point(10, 22), new Point(14, -2), new Point(28, 16), _leftEar, 18, 18));
        head.Children.Add(Ear(new Point(32, 16), new Point(46, -2), new Point(50, 22), _rightEar, 42, 18));
        var skull = new Ellipse { Width = 46, Height = 40, Fill = fur };
        Canvas.SetLeft(skull, 7);
        Canvas.SetTop(skull, 12);
        head.Children.Add(skull);
        var whisker = new SolidColorBrush(Color.FromArgb(150, 255, 236, 246));
        foreach (var (x1, y1, x2, y2) in new[] { (8.0, 36.0, -14.0, 32.0), (8.0, 39.0, -15.0, 41.0), (52.0, 36.0, 74.0, 32.0), (52.0, 39.0, 75.0, 41.0) })
            head.Children.Add(new Line { X1 = x1, Y1 = y1, X2 = x2, Y2 = y2, Stroke = whisker, StrokeThickness = 0.8 });
        var eyeBrush = new RadialGradientBrush
        {
            GradientStops = { new GradientStop { Color = Color.FromArgb(255, 255, 236, 140), Offset = 0 }, new GradientStop { Color = Color.FromArgb(255, 255, 170, 40), Offset = 1 } },
        };
        var leftEye = new Ellipse { Width = 7, Height = 5, Fill = eyeBrush, Opacity = 0 };
        var rightEye = new Ellipse { Width = 7, Height = 5, Fill = eyeBrush, Opacity = 0 };
        Canvas.SetLeft(leftEye, 18); Canvas.SetTop(leftEye, 28);
        Canvas.SetLeft(rightEye, 35); Canvas.SetTop(rightEye, 28);
        head.Children.Add(leftEye);
        head.Children.Add(rightEye);
        cat.Children.Add(head);
        _canvas.Children.Add(cat);
        return (leftEye, rightEye);
    }

    private static Microsoft.UI.Xaml.Shapes.Path Ear(Point a, Point tip, Point b, RotateTransform rotation, double pivotX, double pivotY)
    {
        var figure = new PathFigure { StartPoint = a, IsClosed = true, IsFilled = true };
        figure.Segments.Add(new LineSegment { Point = tip });
        figure.Segments.Add(new LineSegment { Point = b });
        var geometry = new PathGeometry();
        geometry.Figures.Add(figure);
        rotation.CenterX = pivotX;
        rotation.CenterY = pivotY;
        return new Microsoft.UI.Xaml.Shapes.Path { Data = geometry, Fill = new SolidColorBrush(Color.FromArgb(255, 10, 6, 16)), RenderTransform = rotation };
    }

    // ---------- animation ----------

    private void SeedSettledPetals()
    {
        for (var i = 0; i < 70; i++)
        {
            var petal = Spawn();
            petal.X = LedgeLeft + 20 + _random.NextDouble() * 380;
            petal.Y = Ground(petal.X) - _random.NextDouble() * 3;
            Settle(petal);
        }
        if (!_animate)
        {
            // Reduce motion: a still scene with a few petals frozen mid-air.
            for (var i = 0; i < 24; i++)
            {
                var petal = Spawn();
                petal.X = 150 + _random.NextDouble() * 900;
                petal.Y = 40 + _random.NextDouble() * 200;
                Place(petal);
                _falling.Add(petal);
            }
        }
    }

    private void Tick()
    {
        if (!App.IsMainWindowVisible) { _lastTick = DateTime.UtcNow; return; }
        var now = DateTime.UtcNow;
        var dt = Math.Clamp((now - _lastTick).TotalSeconds, 0, 0.1);
        _lastTick = now;
        _time += dt;

        // Petals per second rise from a gentle 1.5 to a blizzard of ~40 at full load.
        _spawnDebt += dt * (1.5 + _load * _load * 38 + _load * 6);
        while (_spawnDebt >= 1 && _falling.Count < MaximumFalling)
        {
            _spawnDebt -= 1;
            var petal = Spawn();
            var spot = _blossomSpots[_random.Next(_blossomSpots.Count)];
            petal.X = spot.X + (_random.NextDouble() - 0.5) * 30;
            petal.Y = spot.Y + (_random.NextDouble() - 0.5) * 16;
            _falling.Add(petal);
        }
        if (_spawnDebt > 3) _spawnDebt = 3;

        var wind = 18 + 26 * Math.Sin(_time * 0.37) + _load * 30;
        for (var i = _falling.Count - 1; i >= 0; i--)
        {
            var p = _falling[i];
            p.Age += dt;
            p.X += (p.Vx + wind + Math.Sin(_time * p.Sway + p.Phase) * 22) * dt;
            p.Y += p.Vy * dt;
            p.Transform.Rotation += p.Spin * dt;
            p.Transform.ScaleX = 0.55 + 0.45 * Math.Abs(Math.Sin(_time * p.Sway * 1.4 + p.Phase)); // tumbling
            if (p.X > SceneWidth + 20 || p.X < -20) { Recycle(p); _falling.RemoveAt(i); continue; }
            if (p.Y >= Ground(p.X)) { _falling.RemoveAt(i); p.Y = Ground(p.X) - _random.NextDouble() * 2; Settle(p); continue; }
            Place(p);
        }

        // Kuro: breathing, tail swish (faster when busy), ear twitches, glances back.
        _breath.ScaleY = 1 + 0.018 * Math.Sin(_time * 1.6);
        _breath.ScaleX = 1 - 0.008 * Math.Sin(_time * 1.6);
        var tailSpeed = 1.1 + _load * 4.5 + (_threats > 0 ? 2 : 0);
        _tailRotation.Angle = Math.Sin(_time * tailSpeed) * (22 + _load * 12) + Math.Sin(_time * tailSpeed * 2.3) * 4;
        SweepPetals();

        if (_time >= _nextTwitch)
        {
            _twitchUntil = _time + 0.18;
            _nextTwitch = _time + 2.5 + _random.NextDouble() * (_threats > 0 ? 2 : 6);
        }
        var twitch = _time < _twitchUntil;
        _leftEar.Angle = twitch ? -16 : _threats > 0 ? -4 : 0;
        _rightEar.Angle = twitch && _random.NextDouble() < 0.3 ? 14 : _threats > 0 ? 4 : 0;

        if (_time >= _nextGlance)
        {
            _glanceUntil = _time + 2.2;
            _nextGlance = _time + 14 + _random.NextDouble() * 18;
        }
        var glancing = _time < _glanceUntil || _threats > 0;
        _headShift.X += ((glancing ? -5 : 0) - _headShift.X) * Math.Min(1, dt * 6);
        SetEyes(glancing && Math.Abs(Math.Sin(_time * 2.7)) > 0.06); // occasional blink
    }

    private void SetEyes(bool visible)
    {
        _leftEye.Opacity = visible ? 1 : 0;
        _rightEye.Opacity = visible ? 1 : 0;
    }

    /// <summary>The tail tip pushes settled petals aside, so they scatter as Kuro swishes.</summary>
    private void SweepPetals()
    {
        var angle = _tailRotation.Angle * Math.PI / 180;
        var baseX = 880 - 45 + 62;
        var baseY = LedgeTop - 4 - 116 + 108;
        var tipX = baseX + 16 * Math.Cos(angle) - 64 * Math.Sin(angle);
        var tipY = baseY + 16 * Math.Sin(angle) + 64 * Math.Cos(angle);
        for (var i = _settled.Count - 1; i >= 0; i--)
        {
            var p = _settled[i];
            var dx = p.X - tipX;
            var dy = p.Y - tipY;
            if (dx * dx + dy * dy > 18 * 18) continue;
            _settled.RemoveAt(i);
            p.Vx = (dx >= 0 ? 1 : -1) * (40 + _random.NextDouble() * 50);
            p.Vy = -30 - _random.NextDouble() * 40;
            p.Y -= 4;
            _falling.Add(p);
        }
        // Kicked petals fall back with gravity.
        foreach (var p in _falling.Where(p => p.Vy < 20)) p.Vy += 120 * 0.033;
    }

    private static double Ground(double x) => x >= LedgeLeft && x <= 1050 ? LedgeTop - 2 : SceneHeight - 4;

    private Petal Spawn()
    {
        var shape = _pool.Count > 0 ? _pool.Dequeue() : new Ellipse { IsHitTestVisible = false };
        var size = 4 + _random.NextDouble() * 4;
        shape.Width = size;
        shape.Height = size * 0.62;
        shape.Fill = _petalBrushes[_random.Next(_petalBrushes.Length)];
        shape.Opacity = 1;
        var transform = new CompositeTransform { CenterX = size / 2, CenterY = size * 0.31, Rotation = _random.NextDouble() * 360 };
        shape.RenderTransform = transform;
        if (shape.Parent is null) _petalLayer.Children.Add(shape);
        shape.Visibility = Visibility.Visible;
        return new Petal
        {
            Shape = shape, Transform = transform, Vx = -6 + _random.NextDouble() * 12, Vy = 18 + _random.NextDouble() * 26,
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

    private static void Place(Petal petal)
    {
        Canvas.SetLeft(petal.Shape, petal.X);
        Canvas.SetTop(petal.Shape, petal.Y);
    }

    private void Add(UIElement element, double x, double y)
    {
        Canvas.SetLeft(element, x);
        Canvas.SetTop(element, y);
        _canvas.Children.Add(element);
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
