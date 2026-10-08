using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.UI;

namespace Downpour_Desktop;

/// <summary>
/// Kuro at play (owner request): fireflies drift and blink around him; when nothing needs attention he watches them,
/// pounces at one, lies down for a while, or rolls along his card to another clear spot. Poses are render transforms
/// on parts that already exist (whole cat, torso, head), so playing costs no layout. He stays sitting and alert while
/// threats are open; with reduced motion the fireflies stay still and he does not play.
/// </summary>
public sealed partial class BlossomScene
{
    private enum CatActivity { Sitting, Pouncing, LyingDown, Rolling }

    private const int FireflyCount = 4;
    private const double PounceDuration = 1.3;
    private const double RollDuration = 1.5;

    // Whole-cat pose in his own (unscaled) units: rolling, hops and pounces. Applied before CatScale.
    private readonly CompositeTransform _pose = new() { CenterX = 45, CenterY = 118 };
    // Extra head offset: follows a firefly and rests forward when lying down.
    private readonly TranslateTransform _headPose = new();
    private readonly Canvas _fireflyLayer = new() { IsHitTestVisible = false };
    private readonly List<Firefly> _fireflies = [];
    private readonly List<double> _freeSpots = [];
    private CatActivity _activity = CatActivity.Sitting;
    private double _activityStart;
    private double _activityEnd;
    private double _nextActivity = 10;
    private double _rollFrom;
    private double _rollTo;
    private double _rollDirection = 1;
    private double? _restX;
    private double _lie; // 0 sitting .. 1 fully lying
    private double _eyeCap = 1;
    private Firefly? _target;

    private sealed class Firefly
    {
        public required Canvas Visual { get; init; }
        public required TranslateTransform Move { get; init; }
        public double Ax, Ay, Fx, Fy, Phase, Blink;
        public double DartX, DartY, DartVx, DartVy;
        public double X, Y;
    }

    private string? ActivityMood => _activity switch
    {
        CatActivity.Pouncing => "chasing fireflies",
        CatActivity.LyingDown => "lounging",
        CatActivity.Rolling => "rolling around",
        _ => _target is not null ? "watching the fireflies" : null,
    };

    private void InitPlay()
    {
        var random = new Random(11);
        for (var i = 0; i < FireflyCount; i++)
        {
            var glow = new Ellipse
            {
                Width = 18, Height = 18,
                Fill = new RadialGradientBrush
                {
                    GradientStops =
                    {
                        new GradientStop { Color = Color.FromArgb(190, 222, 255, 140), Offset = 0 },
                        new GradientStop { Color = Color.FromArgb(70, 180, 255, 120), Offset = 0.45 },
                        new GradientStop { Color = Color.FromArgb(0, 160, 255, 110), Offset = 1 },
                    },
                },
            };
            var core = new Ellipse { Width = 3.6, Height = 3.6, Fill = new SolidColorBrush(Color.FromArgb(255, 252, 255, 205)) };
            Canvas.SetLeft(core, 7.2);
            Canvas.SetTop(core, 7.2);
            var move = new TranslateTransform();
            var visual = new Canvas { Width = 18, Height = 18, IsHitTestVisible = false, RenderTransform = move };
            visual.Children.Add(glow);
            visual.Children.Add(core);
            _fireflyLayer.Children.Add(visual);
            _fireflies.Add(new Firefly
            {
                Visual = visual, Move = move,
                Ax = 55 + random.NextDouble() * 70, Ay = 22 + random.NextDouble() * 30,
                Fx = 0.23 + random.NextDouble() * 0.3, Fy = 0.31 + random.NextDouble() * 0.35,
                Phase = random.NextDouble() * Math.PI * 2, Blink = 0.7 + random.NextDouble() * 0.9,
            });
        }
        _fireflyLayer.Visibility = Visibility.Collapsed;
    }

    /// <summary>Called once per frame after breathing and the tail are set, so poses can scale them.</summary>
    private void AnimatePlay(double dt)
    {
        var home = new Windows.Foundation.Point(_catOrigin.X + (45 + _pose.TranslateX) * CatScale, _catOrigin.Y + 40 * CatScale);
        _fireflyLayer.Visibility = _cat.Visibility;
        MoveFireflies(dt, home);

        if (_threats > 0 && _activity != CatActivity.Sitting && _activity != CatActivity.Rolling) StopActivity();
        if (_threats == 0 && _activity == CatActivity.Sitting && _time >= _nextActivity) StartActivity();

        var t = _activityEnd > _activityStart ? Math.Clamp((_time - _activityStart) / (_activityEnd - _activityStart), 0, 1) : 1;
        _pose.Rotation = 0;
        _pose.TranslateY = 0;
        _pose.ScaleX = _pose.ScaleY = 1;
        switch (_activity)
        {
            case CatActivity.Pouncing:
                Pounce(t);
                break;
            case CatActivity.Rolling:
                Roll(t);
                break;
        }
        if (_activity != CatActivity.Sitting && _activity != CatActivity.LyingDown && t >= 1) StopActivity();
        if (_activity == CatActivity.LyingDown && _time >= _activityEnd) StopActivity();

        // Lying down eases in and out; the torso flattens, the head rests forward, eyes get sleepy, breathing slows.
        var lieTarget = _activity == CatActivity.LyingDown ? 1 : 0;
        _lie += (lieTarget - _lie) * Math.Min(1, dt * 2.2);
        _breath.ScaleY *= 1 - 0.36 * _lie;
        _breath.ScaleX *= 1 + 0.2 * _lie;
        _eyeCap = 1 - 0.6 * _lie;

        // Head follows the nearest firefly a little; rests low and forward when lying.
        _target = _fireflies.MinBy(f => Math.Abs(f.X - home.X) + Math.Abs(f.Y - home.Y));
        var look = _target is null ? 0 : Math.Clamp((_target.X - home.X) / 18, -5, 5);
        _headPose.X += (look - _headPose.X) * Math.Min(1, dt * 3);
        _headPose.Y += (26 * _lie + (_target is not null && _target.Y < home.Y - 30 ? -1.5 : 0) - _headPose.Y) * Math.Min(1, dt * 3);
    }

    private void StartActivity()
    {
        if (!_animate) return;
        var roll = _random.NextDouble();
        if (roll < 0.45) Begin(CatActivity.Pouncing, PounceDuration);
        else if (roll < 0.75) Begin(CatActivity.LyingDown, 8 + _random.NextDouble() * 8);
        else if (RollTarget() is { } target)
        {
            _rollFrom = _pose.TranslateX;
            _rollTo = target;
            _rollDirection = _rollTo >= _rollFrom ? 1 : -1;
            Begin(CatActivity.Rolling, RollDuration);
        }
        else Begin(CatActivity.LyingDown, 6 + _random.NextDouble() * 6);
    }

    private void Begin(CatActivity activity, double duration)
    {
        _activity = activity;
        _activityStart = _time;
        _activityEnd = _time + duration;
        if (activity == CatActivity.Pouncing && _target is not null)
        {
            // The firefly sees him coming and darts away.
            var away = _target.X >= _catOrigin.X + 45 * CatScale ? 1 : -1;
            _target.DartVx += away * (90 + _random.NextDouble() * 60);
            _target.DartVy -= 40 + _random.NextDouble() * 50;
        }
        UpdateStatus();
    }

    private void StopActivity()
    {
        if (_activity == CatActivity.Rolling)
        {
            _pose.TranslateX = _rollTo;
            _restX = _catOrigin.X + _rollTo * CatScale;
        }
        _activity = CatActivity.Sitting;
        _nextActivity = _time + 14 + _random.NextDouble() * 18;
        UpdateStatus();
    }

    /// <summary>Crouch with a rear wiggle, leap toward the firefly, land.</summary>
    private void Pounce(double t)
    {
        var dx = _target is null ? 0 : Math.Clamp((_target.X - (_catOrigin.X + 45 * CatScale)) / CatScale, -34, 34);
        if (t < 0.32)
        {
            var crouch = t / 0.32;
            _pose.ScaleY = 1 - 0.12 * crouch;
            _pose.ScaleX = 1 + 0.06 * crouch;
            _pose.Rotation = Math.Sin(_time * 38) * 2.2 * crouch; // the wiggle before the jump
        }
        else if (t < 0.72)
        {
            var leap = (t - 0.32) / 0.4;
            _pose.TranslateY = -Math.Sin(leap * Math.PI) * 30;
            _pose.ScaleY = 1.08 - 0.08 * leap;
            _pose.ScaleX = 0.96;
            _pose.Rotation = dx * 0.12 * Math.Sin(leap * Math.PI);
        }
        else
        {
            var land = (t - 0.72) / 0.28;
            _pose.ScaleY = 1 - 0.07 * Math.Sin(land * Math.PI);
            _pose.ScaleX = 1 + 0.04 * Math.Sin(land * Math.PI);
        }
    }

    /// <summary>A full roll along the card to another clear spot.</summary>
    private void Roll(double t)
    {
        var eased = t * t * (3 - 2 * t);
        _pose.CenterY = 74;
        _pose.Rotation = _rollDirection * 360 * eased;
        _pose.TranslateX = _rollFrom + (_rollTo - _rollFrom) * eased;
        _pose.TranslateY = -Math.Sin(t * Math.PI) * 8;
        if (t >= 1) _pose.CenterY = 118;
    }

    /// <summary>Another clear spot on the card 40+ px away, as an offset from where he sits now.</summary>
    private double? RollTarget()
    {
        var current = _catOrigin.X + _pose.TranslateX * CatScale;
        var options = _freeSpots.Where(x => Math.Abs(x - current) >= 40).ToArray();
        if (options.Length == 0) return null;
        var pick = options[_random.Next(options.Length)];
        return (pick - _catOrigin.X) / CatScale;
    }

    private void MoveFireflies(double dt, Windows.Foundation.Point home)
    {
        foreach (var f in _fireflies)
        {
            // Darts decay back toward the lazy figure-eight they drift on.
            f.DartX += f.DartVx * dt;
            f.DartY += f.DartVy * dt;
            f.DartVx *= Math.Exp(-dt * 2.5);
            f.DartVy *= Math.Exp(-dt * 2.5);
            f.DartX *= Math.Exp(-dt * 0.45);
            f.DartY *= Math.Exp(-dt * 0.45);
            var t = _animate ? _time : 0;
            f.X = home.X + Math.Sin(t * f.Fx + f.Phase) * f.Ax + Math.Sin(t * f.Fx * 2.7 + f.Phase) * 10 + f.DartX;
            f.Y = home.Y - 24 + Math.Sin(t * f.Fy + f.Phase * 1.3) * f.Ay + Math.Cos(t * f.Fy * 3.1) * 6 + f.DartY;
            f.Move.X = f.X - 9;
            f.Move.Y = f.Y - 9;
            // Slow, uneven glow like a real firefly.
            var pulse = 0.5 + 0.5 * Math.Sin(t * f.Blink + f.Phase);
            f.Visual.Opacity = 0.18 + 0.82 * pulse * pulse;
        }
    }
}
