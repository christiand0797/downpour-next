using System.Runtime.InteropServices;

namespace Downpour.Service;

internal interface IAmsiBackend
{
    int Initialize(string appName, out IntPtr context);
    void Uninitialize(IntPtr context);
    int ScanString(IntPtr context, string content, string name, IntPtr session, out int result);
    int ScanBuffer(IntPtr context, byte[] content, string name, IntPtr session, out int result);
}

/// <summary>Serializes context lifetime with scans and bounds retries when no provider is available.</summary>
internal sealed class AmsiSession(IAmsiBackend backend, TimeProvider? timeProvider = null)
{
    private readonly object _gate = new();
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private IntPtr _context;
    private DateTimeOffset _retryAt;
    public int LastInitializeResult { get; private set; }

    public bool Initialize(string appName = "DownpourNext")
    {
        lock (_gate)
        {
            if (_context != IntPtr.Zero) return true;
            if (_time.GetUtcNow() < _retryAt) return false;
            try { LastInitializeResult = backend.Initialize(appName, out _context); }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
            {
                LastInitializeResult = ex.HResult;
            }
            if (LastInitializeResult >= 0 && _context != IntPtr.Zero) return true;
            _context = IntPtr.Zero;
            if (LastInitializeResult >= 0) LastInitializeResult = unchecked((int)0x80004005);
            _retryAt = _time.GetUtcNow().AddSeconds(30);
            return false;
        }
    }

    public void Uninitialize()
    {
        lock (_gate)
        {
            if (_context != IntPtr.Zero) backend.Uninitialize(_context);
            _context = IntPtr.Zero;
            _retryAt = default;
        }
    }

    public AmsiScanOutcome ScanString(string content, string name = "script", IntPtr session = default)
    {
        ArgumentNullException.ThrowIfNull(content);
        lock (_gate)
        {
            if (!Initialize()) return new(LastInitializeResult, null);
            var hr = backend.ScanString(_context, content, name, session, out var result);
            return new(hr, hr >= 0 ? result : null);
        }
    }

    public AmsiScanOutcome ScanBuffer(byte[] content, string name = "buffer", IntPtr session = default)
    {
        ArgumentNullException.ThrowIfNull(content);
        lock (_gate)
        {
            if (!Initialize()) return new(LastInitializeResult, null);
            var hr = backend.ScanBuffer(_context, content, name, session, out var result);
            return new(hr, hr >= 0 ? result : null);
        }
    }
}

internal sealed class WindowsAmsiBackend : IAmsiBackend
{
    [DllImport("amsi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int AmsiInitialize(string appName, out IntPtr context);
    [DllImport("amsi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern void AmsiUninitialize(IntPtr context);
    [DllImport("amsi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int AmsiScanString(IntPtr context, string content, string name, IntPtr session, out int result);
    [DllImport("amsi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int AmsiScanBuffer(IntPtr context, IntPtr content, uint length, string name, IntPtr session, out int result);
    public int Initialize(string appName, out IntPtr context) => AmsiInitialize(appName, out context);
    public void Uninitialize(IntPtr context) => AmsiUninitialize(context);
    public int ScanString(IntPtr context, string content, string name, IntPtr session, out int result) => AmsiScanString(context, content, name, session, out result);
    public int ScanBuffer(IntPtr context, byte[] content, string name, IntPtr session, out int result)
    {
        var pinned = GCHandle.Alloc(content, GCHandleType.Pinned);
        try { return AmsiScanBuffer(context, pinned.AddrOfPinnedObject(), (uint)content.Length, name, session, out result); }
        finally { pinned.Free(); }
    }
}
