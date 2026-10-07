namespace Downpour.Service;

/// <summary>A provider result exists only when AMSI completed the scan successfully.</summary>
public readonly record struct AmsiScanOutcome(int HResult, int? Result)
{
    public bool Succeeded => HResult >= 0 && Result.HasValue;
    public AmsiIntegration.AmsiVerdict Verdict => Succeeded
        ? AmsiIntegration.InterpretResult(Result!.Value) : AmsiIntegration.AmsiVerdict.Unknown;
}

/// <summary>Windows AMSI integration. Unavailable scans never mean clean or not detected.</summary>
public static class AmsiIntegration
{
    public const int AMSI_RESULT_CLEAN = 0;
    public const int AMSI_RESULT_NOT_DETECTED = 1;
    public const int AMSI_RESULT_DETECTED = 32768;
    public const int AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384;
    public const int AMSI_RESULT_BLOCKED_BY_ADMIN_END = 32767;
    public const int AMSI_RESULT_UNAVAILABLE = -1;
    private static readonly AmsiSession Session = new(new WindowsAmsiBackend());

    public static bool Initialize(string appName = "DownpourNext") => Session.Initialize(appName);
    public static int LastInitializeResult => Session.LastInitializeResult;
    public static void Uninitialize() => Session.Uninitialize();
    public static AmsiScanOutcome ScanStringWithStatus(string content, string contentName = "script", IntPtr session = default) =>
        Session.ScanString(content, contentName, session);
    public static AmsiScanOutcome ScanBufferWithStatus(byte[] buffer, string contentName = "buffer", IntPtr session = default) =>
        Session.ScanBuffer(buffer, contentName, session);
    public static int ScanString(string content, string contentName = "script", IntPtr session = default) =>
        ScanStringWithStatus(content, contentName, session).Result ?? AMSI_RESULT_UNAVAILABLE;
    public static int ScanBuffer(byte[] buffer, string contentName = "buffer", IntPtr session = default) =>
        ScanBufferWithStatus(buffer, contentName, session).Result ?? AMSI_RESULT_UNAVAILABLE;

    public static string DescribeInitializeFailure(int hresult) => unchecked((uint)hresult) switch
    {
        0x80070103 => "no antimalware provider is registered with AMSI (Microsoft Defender or another AMSI-capable antivirus is turned off or not installed)",
        0x80070005 => "access to AMSI was denied",
        0x8007007E => "amsi.dll could not be loaded",
        _ => $"AMSI returned 0x{unchecked((uint)hresult):X8}",
    };

    public static AmsiVerdict InterpretResult(int result)
    {
        if (result >= AMSI_RESULT_DETECTED) return AmsiVerdict.Detected;
        if (result is >= AMSI_RESULT_BLOCKED_BY_ADMIN_START and <= AMSI_RESULT_BLOCKED_BY_ADMIN_END) return AmsiVerdict.BlockedByAdmin;
        return result switch
        {
            AMSI_RESULT_CLEAN => AmsiVerdict.Clean,
            AMSI_RESULT_NOT_DETECTED => AmsiVerdict.NotDetected,
            _ => AmsiVerdict.Unknown,
        };
    }

    public enum AmsiVerdict { Clean = 0, NotDetected = 1, Detected = 32768, BlockedByAdmin = 16384, Unknown = -1 }
}
