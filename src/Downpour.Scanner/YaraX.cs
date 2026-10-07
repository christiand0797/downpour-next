using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Downpour.Scanner;

/// <summary>
/// Minimal binding to the YARA-X C API (yara_x.h at tag v1.21.0). Only the functions Downpour uses are declared.
/// The library is loaded from the scanner's own folder after its SHA-256 matches the hash pinned at build time.
/// </summary>
public static unsafe class YaraX
{
    public const string LibraryName = "yara_x_capi";
    public const int Success = 0, SyntaxError = 1, ScanTimeout = 4;
    public const uint RelaxedRegexSyntax = 2, DisableIncludes = 32;

    private static readonly object Gate = new();
    private static bool _resolverSet;
    private static IntPtr _library;

    public static string PinnedVersion => BuildMetadata("YaraXVersion") ?? "unknown";

    /// <summary>Verifies and loads the native library. Returns null on success, otherwise why it cannot be used.</summary>
    public static string? EnsureLoaded(string? directory = null)
    {
        lock (Gate)
        {
            if (_library != IntPtr.Zero) return null;
            var path = Path.Combine(directory ?? AppContext.BaseDirectory, LibraryName + ".dll");
            if (VerifyPinned(path) is { } problem) return problem;
            try
            {
                _library = NativeLibrary.Load(path);
            }
            catch (Exception ex) when (ex is DllNotFoundException or BadImageFormatException)
            {
                return $"The YARA-X library could not be loaded: {ex.Message}";
            }
            if (!_resolverSet)
            {
                NativeLibrary.SetDllImportResolver(typeof(YaraX).Assembly, (name, _, _) => name == LibraryName ? _library : IntPtr.Zero);
                _resolverSet = true;
            }
            return null;
        }
    }

    /// <summary>Returns null when <paramref name="path"/> is the pinned YARA-X library, otherwise why it must not be loaded.</summary>
    public static string? VerifyPinned(string path)
    {
        if (!File.Exists(path)) return "The YARA-X library is not installed with this build.";
        var expected = BuildMetadata("YaraXDllSha256");
        if (string.IsNullOrEmpty(expected)) return "No pinned YARA-X hash is embedded in this build.";
        byte[] hash;
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash).Equals(expected, StringComparison.OrdinalIgnoreCase)
            ? null : "The YARA-X library does not match the pinned hash and was not loaded.";
    }

    private static string? BuildMetadata(string key) =>
        typeof(YaraX).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>().FirstOrDefault(a => a.Key == key)?.Value;

    public static string LastError()
    {
        var pointer = yrx_last_error();
        return pointer == IntPtr.Zero ? "" : Marshal.PtrToStringUTF8(pointer) ?? "";
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct Metadata
    {
        [FieldOffset(0)] public IntPtr Identifier;
        [FieldOffset(8)] public int ValueType; // 0 i64, 1 f64, 2 bool, 3 string, 4 bytes
        [FieldOffset(16)] public long I64;
        [FieldOffset(16)] public double F64;
        [FieldOffset(16)] public byte Boolean;
        [FieldOffset(16)] public IntPtr String;
    }

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)] public static extern IntPtr yrx_last_error();
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)] public static extern int yrx_compiler_create(uint flags, out IntPtr compiler);
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)] public static extern void yrx_compiler_destroy(IntPtr compiler);
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)] public static extern int yrx_compiler_add_source_with_origin(IntPtr compiler, byte* source, byte* origin);
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)] public static extern int yrx_compiler_new_namespace(IntPtr compiler, byte* ns);
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)] public static extern IntPtr yrx_compiler_build(IntPtr compiler);
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)] public static extern int yrx_rules_count(IntPtr rules);
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)] public static extern void yrx_rules_destroy(IntPtr rules);
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)] public static extern int yrx_scanner_create(IntPtr rules, out IntPtr scanner);
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)] public static extern void yrx_scanner_destroy(IntPtr scanner);
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)] public static extern int yrx_scanner_set_timeout(IntPtr scanner, ulong seconds);
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)] public static extern int yrx_scanner_max_matches_per_pattern(IntPtr scanner, nuint count);
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)] public static extern int yrx_scanner_on_matching_rule(IntPtr scanner, delegate* unmanaged[Cdecl]<IntPtr, IntPtr, void> callback, IntPtr userData);
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)] public static extern int yrx_scanner_scan(IntPtr scanner, byte* data, nuint length);
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)] public static extern int yrx_rule_identifier(IntPtr rule, out IntPtr identifier, out nuint length);
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)] public static extern int yrx_rule_namespace(IntPtr rule, out IntPtr ns, out nuint length);
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)] public static extern int yrx_rule_iter_metadata(IntPtr rule, delegate* unmanaged[Cdecl]<Metadata*, IntPtr, void> callback, IntPtr userData);
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)] public static extern int yrx_rule_iter_tags(IntPtr rule, delegate* unmanaged[Cdecl]<IntPtr, IntPtr, void> callback, IntPtr userData);
}
