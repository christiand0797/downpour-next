using Downpour.Core;

namespace Downpour.Service;

/// <summary>
/// Shared, cached Authenticode check: an embedded signature first, then the Windows catalog database (where most
/// Windows and vendor driver files, including audio effect DLLs, are signed). Results are cached per path, size and
/// write time, so repeated checks of an unchanged file are free. Read-only; revocation is not fetched online.
/// </summary>
public sealed class FileSignatureChecker : IDisposable
{
    private const int MaximumCached = 2048;
    private readonly object _gate = new();
    private readonly Dictionary<string, (long Length, DateTime Written, PersistenceSignature? Result)> _cache = new(StringComparer.OrdinalIgnoreCase);
    private CatalogSignatureVerifier? _catalog;
    private bool _catalogTried;

    /// <summary>Null when the file cannot be read or checked; the caller then keeps its stricter default.</summary>
    public PersistenceSignature? Check(string path)
    {
        FileInfo info;
        try
        {
            info = new FileInfo(path);
            if (!info.Exists) return null;
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException or System.Security.SecurityException)
        {
            return null;
        }

        lock (_gate)
        {
            if (_cache.TryGetValue(path, out var hit) && hit.Length == info.Length && hit.Written == info.LastWriteTimeUtc) return hit.Result;
            var result = Verify(path);
            if (_cache.Count >= MaximumCached) _cache.Clear();
            _cache[path] = (info.Length, info.LastWriteTimeUtc, result);
            return result;
        }
    }

    private PersistenceSignature? Verify(string path)
    {
        try
        {
            if (AuthenticodeVerifier.VerifyEmbeddedSignature(path, out var signer))
                return new(true, signer, AuthenticodeVerifier.IsMicrosoftSignerName(signer));
            if (!_catalogTried)
            {
                _catalog = CatalogSignatureVerifier.TryCreate(out _);
                _catalogTried = true;
            }
            if (_catalog?.Verify(path) is { } catalog)
            {
                if (catalog.IsSigned) return new(true, catalog.SignerName, AuthenticodeVerifier.IsMicrosoftSignerName(catalog.SignerName));
                if (catalog.Status.StartsWith("Unknown", StringComparison.Ordinal)) return null;
            }
            return new(false, null, false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or System.Runtime.InteropServices.COMException)
        {
            return null;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _catalog?.Dispose();
            _catalog = null;
        }
    }
}
