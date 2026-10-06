using System.Runtime.InteropServices;

namespace Downpour_Desktop;

/// <summary>Raises a callback when a window receives WM_SIZE with SIZE_MINIMIZED, via a comctl32 window subclass.</summary>
internal sealed class MinimizeWatcher : IDisposable
{
    private const uint WmSize = 0x0005;
    private const int SizeMinimized = 1;
    private static readonly UIntPtr SubclassId = new(0x44504E54); // "DPNT"
    private readonly IntPtr _window;
    private readonly SubclassProcedure _procedure;
    private readonly Action _minimized;
    private bool _installed;

    public MinimizeWatcher(IntPtr window, Action minimized)
    {
        _window = window;
        _minimized = minimized;
        _procedure = Procedure; // kept in a field so the delegate is not collected
        _installed = window != IntPtr.Zero && SetWindowSubclass(window, _procedure, SubclassId, UIntPtr.Zero);
    }

    private IntPtr Procedure(IntPtr window, uint message, IntPtr wParam, IntPtr lParam, UIntPtr id, UIntPtr data)
    {
        if (message == WmSize && wParam.ToInt64() == SizeMinimized) _minimized();
        return DefSubclassProc(window, message, wParam, lParam);
    }

    public void Dispose()
    {
        if (!_installed) return;
        RemoveWindowSubclass(_window, _procedure, SubclassId);
        _installed = false;
    }

    private delegate IntPtr SubclassProcedure(IntPtr window, uint message, IntPtr wParam, IntPtr lParam, UIntPtr id, UIntPtr data);

    [DllImport("comctl32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowSubclass(IntPtr window, SubclassProcedure procedure, UIntPtr id, UIntPtr data);

    [DllImport("comctl32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RemoveWindowSubclass(IntPtr window, SubclassProcedure procedure, UIntPtr id);

    [DllImport("comctl32.dll")]
    private static extern IntPtr DefSubclassProc(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);
}
