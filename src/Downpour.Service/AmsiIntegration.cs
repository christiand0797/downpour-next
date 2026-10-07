using System.Runtime.InteropServices;
using System.Text;

namespace Downpour.Service;

/// <summary>Windows AMSI (Antimalware Scan Interface) integration for script content scanning.</summary>
public static class AmsiIntegration
{
    private const string AmsiDll = "amsi.dll";

    [DllImport(AmsiDll, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern int AmsiInitialize(string appName, out IntPtr context);

    [DllImport(AmsiDll, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern int AmsiUninitialize(IntPtr context);

    [DllImport(AmsiDll, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern int AmsiScanString(IntPtr context, string content, string contentName, IntPtr session, out int result);

    [DllImport(AmsiDll, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern int AmsiScanBuffer(IntPtr context, IntPtr buffer, uint length, string contentName, IntPtr session, out int result); // ULONG is 32-bit on Windows

    public const int AMSI_RESULT_CLEAN = 0;
    public const int AMSI_RESULT_NOT_DETECTED = 1;
    public const int AMSI_RESULT_DETECTED = 32768;
    public const int AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384;
    public const int AMSI_RESULT_BLOCKED_BY_ADMIN_END = 32767;

    private static IntPtr _context = IntPtr.Zero;
    private static readonly object _initLock = new();
    private static bool _initialized = false;

    /// <summary>Initializes the AMSI context for the application.</summary>
    public static bool Initialize(string appName = "DownpourNext")
    {
        lock (_initLock)
        {
            if (_initialized) return true;

            var result = AmsiInitialize(appName, out _context);
            LastInitializeResult = result;
            if (result == 0) // S_OK
            {
                _initialized = true;
                return true;
            }
            return false;
        }
    }

    /// <summary>HRESULT from the most recent AmsiInitialize call (0 = success).</summary>
    public static int LastInitializeResult { get; private set; }

    /// <summary>Plain-language reason for an AmsiInitialize failure.</summary>
    public static string DescribeInitializeFailure(int hresult) => unchecked((uint)hresult) switch
    {
        0x80070103 => "no antimalware provider is registered with AMSI (Microsoft Defender or another AMSI-capable antivirus is turned off or not installed)",
        0x80070005 => "access to AMSI was denied",
        0x8007007E => "amsi.dll could not be loaded",
        _ => $"AmsiInitialize returned 0x{unchecked((uint)hresult):X8}",
    };

    /// <summary>Uninitializes the AMSI context.</summary>
    public static void Uninitialize()
    {
        lock (_initLock)
        {
            if (_initialized && _context != IntPtr.Zero)
            {
                AmsiUninitialize(_context);
                _context = IntPtr.Zero;
                _initialized = false;
            }
        }
    }

    /// <summary>Scans a string for malicious content using AMSI.</summary>
    /// <returns>AMSI result code (0=clean, 1=not detected, 32768=detected, etc.)</returns>
    public static int ScanString(string content, string contentName = "script", IntPtr session = default)
    {
        if (!_initialized || _context == IntPtr.Zero)
        {
            if (!Initialize()) return AMSI_RESULT_NOT_DETECTED;
        }

        var result = AmsiScanString(_context, content, contentName, session, out var amsiResult);
        if (result != 0) // Not S_OK
        {
            return AMSI_RESULT_NOT_DETECTED;
        }
        return amsiResult;
    }

    /// <summary>Scans a buffer for malicious content using AMSI.</summary>
    public static int ScanBuffer(byte[] buffer, string contentName = "buffer", IntPtr session = default)
    {
        if (!_initialized || _context == IntPtr.Zero)
        {
            if (!Initialize()) return AMSI_RESULT_NOT_DETECTED;
        }

        var pinned = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            var result = AmsiScanBuffer(_context, pinned.AddrOfPinnedObject(), (uint)buffer.Length, contentName, session, out var amsiResult);
            if (result != 0) return AMSI_RESULT_NOT_DETECTED;
            return amsiResult;
        }
        finally
        {
            if (pinned.IsAllocated) pinned.Free();
        }
    }

    /// <summary>Interprets an AMSI result code.</summary>
    public static AmsiVerdict InterpretResult(int result)
    {
        if (result == AMSI_RESULT_CLEAN) return AmsiVerdict.Clean;
        if (result == AMSI_RESULT_NOT_DETECTED) return AmsiVerdict.NotDetected;
        if (result == AMSI_RESULT_DETECTED) return AmsiVerdict.Detected;
        if (result >= AMSI_RESULT_BLOCKED_BY_ADMIN_START && result <= AMSI_RESULT_BLOCKED_BY_ADMIN_END) return AmsiVerdict.BlockedByAdmin;
        return AmsiVerdict.Unknown;
    }

    public enum AmsiVerdict
    {
        Clean = 0,
        NotDetected = 1,
        Detected = 32768,
        BlockedByAdmin = 16384,
        Unknown = -1
    }
}