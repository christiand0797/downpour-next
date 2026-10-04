namespace Downpour_Desktop;

public static class StormModeController
{
    public static readonly string[] Modes = ["DRIZZLE", "STORM", "THUNDERSTORM", "HURRICANE"];

    public static event Action<int>? ModeChanged;

    public static int CurrentMode { get; private set; } = 1;
    public static bool IsManual { get; private set; }

    public static void Cycle()
    {
        IsManual = true;
        SetMode((CurrentMode + 1) % Modes.Length);
    }

    public static void SetAutomaticMode(int mode)
    {
        if (!IsManual) SetMode(mode);
    }

    public static void SetMode(int mode)
    {
        var boundedMode = Math.Clamp(mode, 0, Modes.Length - 1);
        if (CurrentMode == boundedMode) return;
        CurrentMode = boundedMode;
        ModeChanged?.Invoke(boundedMode);
    }
}
