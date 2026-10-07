using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Downpour.Contracts;

namespace Downpour.Service;

/// <summary>
/// User-supplied intel API keys, encrypted with DPAPI for the current user (CryptProtectData) in the protected state
/// folder. Keys are never logged, returned over IPC, or exported; callers only learn which services are configured.
/// </summary>
public sealed class IntelKeyStore(string path)
{
    public const int MaximumKeyLength = 256;
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Downpour.Next.IntelKeys.v1");
    private readonly object _gate = new();

    public static IntelKeyStore CreateForCurrentUser()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DownpourNext", "state");
        SecureJournalDirectory.Ensure(root);
        var file = Path.Combine(root, "intel-keys.v1.json");
        SecureJournalDirectory.RestrictExistingFile(file);
        return new IntelKeyStore(file);
    }

    public IReadOnlyList<string> ConfiguredServices
    {
        get { lock (_gate) return Load().Keys.Where(IntelServices.All.Contains).OrderBy(name => name).ToArray(); }
    }

    public string? Get(string service)
    {
        lock (_gate)
        {
            if (!Load().TryGetValue(service, out var protectedValue)) return null;
            try
            {
                return Encoding.UTF8.GetString(Unprotect(Convert.FromBase64String(protectedValue)));
            }
            catch (Exception ex) when (ex is FormatException or CryptographicFailure)
            {
                return null;
            }
        }
    }

    /// <summary>Stores or (with a null or empty key) removes a key. Returns false for invalid input or a storage failure.</summary>
    public bool Set(string service, string? key)
    {
        if (!IntelServices.All.Contains(service)) return false;
        if (key is not null && (key.Length > MaximumKeyLength || key.Any(ch => char.IsControl(ch) || char.IsWhiteSpace(ch)))) return false;
        lock (_gate)
        {
            var values = Load();
            if (string.IsNullOrEmpty(key)) values.Remove(service);
            else values[service] = Convert.ToBase64String(Protect(Encoding.UTF8.GetBytes(key)));
            return Save(values);
        }
    }

    private Dictionary<string, string> Load()
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > 16 * 1024 || (info.Attributes & FileAttributes.ReparsePoint) != 0) return new(StringComparer.Ordinal);
            return JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllBytes(path)) ?? new(StringComparer.Ordinal);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return new(StringComparer.Ordinal);
        }
    }

    private bool Save(Dictionary<string, string> values)
    {
        var temporary = path + ".tmp";
        try
        {
            File.WriteAllBytes(temporary, JsonSerializer.SerializeToUtf8Bytes(values));
            File.Move(temporary, path, overwrite: true);
            SecureJournalDirectory.RestrictExistingFile(path);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            try { File.Delete(temporary); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            return false;
        }
    }

    internal static byte[] Protect(byte[] data) => Transform(data, protect: true);

    internal static byte[] Unprotect(byte[] data) => Transform(data, protect: false);

    private static byte[] Transform(byte[] data, bool protect)
    {
        var input = Pin(data);
        var entropy = Pin(Entropy);
        try
        {
            var ok = protect
                ? CryptProtectData(ref input.Blob, null, ref entropy.Blob, IntPtr.Zero, IntPtr.Zero, 0x1 /* UI_FORBIDDEN */, out var output)
                : CryptUnprotectData(ref input.Blob, IntPtr.Zero, ref entropy.Blob, IntPtr.Zero, IntPtr.Zero, 0x1, out output);
            if (!ok) throw new CryptographicFailure();
            try
            {
                var result = new byte[output.cbData];
                Marshal.Copy(output.pbData, result, 0, output.cbData);
                return result;
            }
            finally
            {
                LocalFree(output.pbData);
            }
        }
        finally
        {
            input.Handle.Free();
            entropy.Handle.Free();
        }
    }

    private static (DataBlob Blob, GCHandle Handle) Pin(byte[] data)
    {
        var handle = GCHandle.Alloc(data, GCHandleType.Pinned);
        return (new DataBlob { cbData = data.Length, pbData = handle.AddrOfPinnedObject() }, handle);
    }

    internal sealed class CryptographicFailure : Exception;

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int cbData;
        public IntPtr pbData;
    }

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(ref DataBlob dataIn, string? description, ref DataBlob entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob dataOut);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(ref DataBlob dataIn, IntPtr description, ref DataBlob entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob dataOut);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
