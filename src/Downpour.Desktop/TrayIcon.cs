using System.Runtime.InteropServices;

namespace Downpour_Desktop;

/// <summary>
/// Notification-area icon with Show / Exit, ported from v29 _setup_tray_icon (pystray). Uses Shell_NotifyIconW on a
/// hidden window created on the UI thread, so callbacks arrive through the normal WinUI message loop. Re-adds itself
/// when Explorer restarts (TaskbarCreated).
/// </summary>
internal sealed class TrayIcon : IDisposable
{
    private const uint CallbackMessage = 0x8000 + 0x21; // WM_APP + 0x21
    private const uint NimAdd = 0, NimDelete = 2, NimSetVersion = 4;
    private const uint NifMessage = 0x1, NifIcon = 0x2, NifTip = 0x4, NifShowTip = 0x80;
    private const uint NotifyIconVersion4 = 4;
    private const uint NinSelect = 0x400, NinKeySelect = 0x401, WmContextMenu = 0x7B, WmLButtonDblClk = 0x203;
    private const uint MenuShow = 1, MenuExit = 2;
    private const string ClassName = "DownpourNextTrayWindow";

    private readonly WndProc _wndProc;
    private readonly uint _taskbarCreated;
    private readonly IntPtr _window;
    private readonly IntPtr _icon;
    private readonly string _tooltip;
    private bool _added;
    private bool _disposed;

    public event Action? ShowRequested;
    public event Action? ExitRequested;

    public bool IsVisible => _added;

    public TrayIcon(string iconPath, string tooltip)
    {
        _tooltip = tooltip.Length <= 127 ? tooltip : tooltip[..127];
        _wndProc = WindowProcedure; // kept in a field so the delegate is not collected
        _taskbarCreated = RegisterWindowMessageW("TaskbarCreated");
        var instance = GetModuleHandleW(null);
        var windowClass = new WndClassEx
        {
            cbSize = (uint)Marshal.SizeOf<WndClassEx>(),
            lpfnWndProc = Marshal.GetFunctionPointerForDelegate(_wndProc),
            hInstance = instance,
            lpszClassName = ClassName,
        };
        RegisterClassExW(ref windowClass); // Fails harmlessly if the class already exists.
        _window = CreateWindowExW(0, ClassName, "Downpour Next tray", 0, 0, 0, 0, 0, IntPtr.Zero, IntPtr.Zero, instance, IntPtr.Zero);
        // Unpackaged publishes compile Assets into .pri files, so prefer the icon embedded in the executable
        // (ApplicationIcon) and fall back to the loose file used by development builds.
        _icon = ExtractExecutableIcon();
        if (_icon == IntPtr.Zero && File.Exists(iconPath))
            _icon = LoadImageW(IntPtr.Zero, iconPath, 1, GetSystemMetrics(49), GetSystemMetrics(50), 0x10);
        Add();
    }

    private static IntPtr ExtractExecutableIcon()
    {
        var executable = Environment.ProcessPath;
        if (string.IsNullOrEmpty(executable)) return IntPtr.Zero;
        var small = new IntPtr[1];
        return ExtractIconExW(executable, 0, null, small, 1) > 0 ? small[0] : IntPtr.Zero;
    }

    private void Add()
    {
        if (_window == IntPtr.Zero || _icon == IntPtr.Zero) return;
        var data = Data();
        data.uFlags = NifMessage | NifIcon | NifTip | NifShowTip;
        _added = Shell_NotifyIconW(NimAdd, ref data);
        if (_added)
        {
            data.uVersionOrTimeout = NotifyIconVersion4;
            Shell_NotifyIconW(NimSetVersion, ref data);
        }
    }

    private NotifyIconData Data() => new()
    {
        cbSize = (uint)Marshal.SizeOf<NotifyIconData>(),
        hWnd = _window,
        uID = 1,
        uCallbackMessage = CallbackMessage,
        hIcon = _icon,
        szTip = _tooltip,
        szInfo = "",
        szInfoTitle = "",
    };

    private IntPtr WindowProcedure(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam)
    {
        if (message == _taskbarCreated && !_disposed)
        {
            _added = false;
            Add();
            return IntPtr.Zero;
        }
        if (message == CallbackMessage)
        {
            var notification = (uint)(lParam.ToInt64() & 0xFFFF);
            if (notification is NinSelect or NinKeySelect or WmLButtonDblClk) ShowRequested?.Invoke();
            else if (notification == WmContextMenu) ShowMenu();
            return IntPtr.Zero;
        }
        return DefWindowProcW(hwnd, message, wParam, lParam);
    }

    private void ShowMenu()
    {
        var menu = CreatePopupMenu();
        if (menu == IntPtr.Zero) return;
        try
        {
            AppendMenuW(menu, 0, MenuShow, "Show Downpour");
            AppendMenuW(menu, 0x800, 0, null); // separator
            AppendMenuW(menu, 0, MenuExit, "Exit");
            GetCursorPos(out var point);
            SetForegroundWindow(_window); // Required so the menu closes when focus moves away.
            var command = TrackPopupMenuEx(menu, 0x100 | 0x2, point.X, point.Y, _window, IntPtr.Zero);
            PostMessageW(_window, 0, IntPtr.Zero, IntPtr.Zero);
            if (command == MenuShow) ShowRequested?.Invoke();
            else if (command == MenuExit) ExitRequested?.Invoke();
        }
        finally
        {
            DestroyMenu(menu);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_added)
        {
            var data = Data();
            Shell_NotifyIconW(NimDelete, ref data);
            _added = false;
        }
        if (_window != IntPtr.Zero) DestroyWindow(_window);
        if (_icon != IntPtr.Zero) DestroyIcon(_icon);
    }

    private delegate IntPtr WndProc(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WndClassEx
    {
        public uint cbSize;
        public uint style;
        public IntPtr lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public IntPtr hInstance;
        public IntPtr hIcon;
        public IntPtr hCursor;
        public IntPtr hbrBackground;
        public string? lpszMenuName;
        public string lpszClassName;
        public IntPtr hIconSm;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NotifyIconData
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szTip;
        public uint dwState;
        public uint dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szInfo;
        public uint uVersionOrTimeout;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string szInfoTitle;
        public uint dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Point
    {
        public int X;
        public int Y;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Shell_NotifyIconW(uint message, ref NotifyIconData data);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern ushort RegisterClassExW(ref WndClassEx windowClass);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateWindowExW(uint exStyle, string className, string windowName, uint style, int x, int y,
        int width, int height, IntPtr parent, IntPtr menu, IntPtr instance, IntPtr param);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyWindow(IntPtr window);

    [DllImport("user32.dll")]
    private static extern IntPtr DefWindowProcW(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern uint RegisterWindowMessageW(string name);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandleW(string? moduleName);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadImageW(IntPtr instance, string name, uint type, int width, int height, uint load);

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int index);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern uint ExtractIconExW(string file, int index, IntPtr[]? large, IntPtr[]? small, uint icons);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr icon);

    [DllImport("user32.dll")]
    private static extern IntPtr CreatePopupMenu();

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AppendMenuW(IntPtr menu, uint flags, uint id, string? text);

    [DllImport("user32.dll")]
    private static extern uint TrackPopupMenuEx(IntPtr menu, uint flags, int x, int y, IntPtr window, IntPtr parameters);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyMenu(IntPtr menu);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetCursorPos(out Point point);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(IntPtr window);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostMessageW(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);
}
