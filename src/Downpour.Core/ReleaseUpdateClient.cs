using System.Buffers;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;

namespace Downpour.Core;

public sealed record DownpourRelease(Version Version, string Tag, Uri DownloadUri, string Sha256, long Size, string ReleaseUrl);
public sealed record UpdateCheckResult(bool UpdateAvailable, Version CurrentVersion, Version LatestVersion, DownpourRelease? Release);

/// <summary>Checks only the configured Downpour Next GitHub repository and downloads one exact release asset.</summary>
public sealed class ReleaseUpdateClient : IDisposable
{
    public const string Repository = "christiand0797/downpour-next";
    public const string AssetPrefix = "DownpourNext-win-x64-";
    public const long MaximumPackageBytes = 512L * 1024 * 1024;
    private static readonly Uri LatestReleaseEndpoint = new("https://api.github.com/repos/christiand0797/downpour-next/releases/latest");
    private static readonly HashSet<string> DownloadHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "github.com", "release-assets.githubusercontent.com"
    };
    private readonly HttpClient _http;
    private readonly bool _ownsClient;

    public ReleaseUpdateClient(HttpClient? httpClient = null)
    {
        if (httpClient is not null)
        {
            _http = httpClient;
            return;
        }

        _http = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false, AutomaticDecompression = DecompressionMethods.None })
        {
            Timeout = TimeSpan.FromSeconds(20)
        };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("DownpourNext-Updater/1.0");
        _http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        _ownsClient = true;
    }

    public async Task<UpdateCheckResult> CheckAsync(Version currentVersion, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(currentVersion);
        using var response = await _http.GetAsync(LatestReleaseEndpoint, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
            throw new InvalidOperationException("The Downpour Next release is unavailable. The repository may be private; public in-app updates require anonymous release access.");
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength is > 131072)
            throw new InvalidDataException("The release metadata exceeded the 128 KiB limit.");
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var body = await ReadBoundedAsync(stream, 131072, cancellationToken).ConfigureAwait(false);
        var release = ParseLatestRelease(body);
        var updateAvailable = release.Version > currentVersion;
        return new UpdateCheckResult(updateAvailable, currentVersion, release.Version, updateAvailable ? release : null);
    }

    public async Task DownloadVerifiedPackageAsync(DownpourRelease release, string targetPath, IProgress<long>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(release);
        ValidateRelease(release);
        var fullTarget = Path.GetFullPath(targetPath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullTarget)!);
        var current = release.DownloadUri;
        HttpResponseMessage? response = null;
        try
        {
            for (var redirect = 0; redirect <= 4; redirect++)
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, current);
                response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
                if (!IsRedirect(response.StatusCode)) break;
                var location = response.Headers.Location;
                response.Dispose();
                response = null;
                if (redirect == 4 || location is null) throw new InvalidDataException("The release download redirected too many times.");
                current = location.IsAbsoluteUri ? location : new Uri(current, location);
                if (!IsAllowedDownloadUri(current)) throw new InvalidDataException("The release download redirected to an untrusted host.");
            }

            if (response is null) throw new InvalidDataException("The release download did not return a response.");
            using (response)
            {
                response.EnsureSuccessStatusCode();
                if (response.Content.Headers.ContentLength is long length && length != release.Size)
                    throw new InvalidDataException("The release package size does not match release metadata.");
                await using var input = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                await using var output = new FileStream(fullTarget, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.Asynchronous | FileOptions.SequentialScan);
                using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                var buffer = ArrayPool<byte>.Shared.Rent(65536);
                long total = 0;
                try
                {
                    int count;
                    while ((count = await input.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false)) > 0)
                    {
                        total += count;
                        if (total > MaximumPackageBytes || total > release.Size) throw new InvalidDataException("The release package exceeded its declared size limit.");
                        hasher.AppendData(buffer, 0, count);
                        await output.WriteAsync(buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
                        progress?.Report(total);
                    }
                    await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                    if (total != release.Size) throw new InvalidDataException("The release package was truncated.");
                    var digest = Convert.ToHexString(hasher.GetHashAndReset());
                    if (!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(digest), Convert.FromHexString(release.Sha256)))
                        throw new InvalidDataException("The downloaded release package failed its SHA-256 check.");
                }
                catch
                {
                    output.Close();
                    File.Delete(fullTarget);
                    throw;
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
                }
            }
        }
        finally
        {
            response?.Dispose();
        }
    }

    public static DownpourRelease ParseLatestRelease(ReadOnlySpan<byte> json)
    {
        using var document = JsonDocument.Parse(json.ToArray(), new JsonDocumentOptions { MaxDepth = 12, AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow });
        RejectDuplicateProperties(document.RootElement);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object || GetRequiredBoolean(root, "draft") || GetRequiredBoolean(root, "prerelease"))
            throw new InvalidDataException("The GitHub response is not a stable, published release.");

        var tag = GetString(root, "tag_name", 32);
        if (!TryParseReleaseVersion(tag, out var version)) throw new InvalidDataException("The release tag is not a supported stable version.");
        var releaseUrl = GetString(root, "html_url", 512);
        if (!Uri.TryCreate(releaseUrl, UriKind.Absolute, out var releaseUri) || releaseUri.Scheme != Uri.UriSchemeHttps ||
            !releaseUri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase) || releaseUri.AbsolutePath != $"/{Repository}/releases/tag/{tag}")
            throw new InvalidDataException("The release page does not match the fixed Downpour Next repository.");

        if (!root.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array || assets.GetArrayLength() > 32)
            throw new InvalidDataException("The release asset list is invalid.");
        var expectedName = $"{AssetPrefix}{version}.zip";
        JsonElement found = default;
        var matches = 0;
        foreach (var asset in assets.EnumerateArray())
        {
            if (asset.ValueKind != JsonValueKind.Object) continue;
            RejectDuplicateProperties(asset);
            if (GetString(asset, "name", 160) != expectedName) continue;
            if (GetString(asset, "state", 32) != "uploaded" || GetString(asset, "content_type", 128) != "application/zip")
                throw new InvalidDataException("The release package is not a completed ZIP asset.");
            found = asset;
            matches++;
        }
        if (matches != 1) throw new InvalidDataException("The release must contain exactly one expected Windows x64 package.");
        var size = GetInt64(found, "size");
        if (size is < 1 or > MaximumPackageBytes) throw new InvalidDataException("The release package size is outside the supported limit.");
        var digest = GetString(found, "digest", 80);
        if (!digest.StartsWith("sha256:", StringComparison.Ordinal) || digest.Length != 71 || !IsHex(digest.AsSpan(7)))
            throw new InvalidDataException("The release package is missing its SHA-256 digest.");
        var download = GetString(found, "browser_download_url", 1024);
        var expectedPath = $"/{Repository}/releases/download/{tag}/{expectedName}";
        if (!Uri.TryCreate(download, UriKind.Absolute, out var downloadUri) || !IsAllowedDownloadUri(downloadUri) || downloadUri.Host != "github.com" || downloadUri.AbsolutePath != expectedPath)
            throw new InvalidDataException("The release package URL does not match the fixed repository and asset.");
        return new DownpourRelease(version!, tag, downloadUri, digest[7..].ToUpperInvariant(), size, releaseUrl);
    }

    private static void ValidateRelease(DownpourRelease release)
    {
        if (!TryParseReleaseVersion(release.Tag, out var version) || version != release.Version ||
            release.Size is < 1 or > MaximumPackageBytes || release.Sha256.Length != 64 || !IsHex(release.Sha256.AsSpan()))
            throw new InvalidDataException("The release metadata is invalid.");
        var expectedName = $"{AssetPrefix}{version}.zip";
        if (!IsAllowedDownloadUri(release.DownloadUri) || release.DownloadUri.Host != "github.com" ||
            release.DownloadUri.AbsolutePath != $"/{Repository}/releases/download/{release.Tag}/{expectedName}")
            throw new InvalidDataException("The release URL does not match the fixed repository asset.");
    }

    private static bool TryParseReleaseVersion(string tag, out Version? version)
    {
        version = null;
        if (tag.Length is < 5 or > 32 || tag[0] != 'v') return false;
        var value = tag.AsSpan(1);
        if (tag.Count(character => character == '.') != 2 || !Version.TryParse(value, out var parsed) || parsed.Build < 0 || parsed.Revision != -1) return false;
        version = parsed;
        return true;
    }

    private static bool IsAllowedDownloadUri(Uri uri) => uri.IsAbsoluteUri && uri.Scheme == Uri.UriSchemeHttps && uri.IsDefaultPort &&
        string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Fragment) && DownloadHosts.Contains(uri.Host);
    private static bool IsRedirect(HttpStatusCode code) => code is HttpStatusCode.MovedPermanently or HttpStatusCode.Redirect or HttpStatusCode.SeeOther or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect;
    private static bool IsHex(ReadOnlySpan<char> value) => value.Length > 0 && value.ToString().All(Uri.IsHexDigit);

    private static string GetString(JsonElement element, string name, int maxLength)
    {
        if (!element.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String) throw new InvalidDataException($"Release field '{name}' is missing or invalid.");
        var result = value.GetString()!;
        if (result.Length is < 1 || result.Length > maxLength || result.Any(char.IsControl)) throw new InvalidDataException($"Release field '{name}' is outside its allowed bounds.");
        return result;
    }

    private static bool GetRequiredBoolean(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value)) throw new InvalidDataException($"Release field '{name}' is missing or invalid.");
        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => throw new InvalidDataException($"Release field '{name}' is missing or invalid.")
        };
    }
    private static long GetInt64(JsonElement element, string name) => element.TryGetProperty(name, out var value) && value.TryGetInt64(out var result) ? result : throw new InvalidDataException($"Release field '{name}' is missing or invalid.");

    private static void RejectDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new InvalidDataException("The release metadata contains duplicate fields.");
                RejectDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray()) RejectDuplicateProperties(item);
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(Stream input, int limit, CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var buffer = ArrayPool<byte>.Shared.Rent(8192);
        try
        {
            int count;
            while ((count = await input.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false)) > 0)
            {
                if (output.Length + count > limit) throw new InvalidDataException("Release metadata exceeded its size limit.");
                output.Write(buffer, 0, count);
            }
            return output.ToArray();
        }
        finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
    }

    public void Dispose() { if (_ownsClient) _http.Dispose(); }
}

public static class UpdateArchive
{
    public const int MaximumFiles = 2000;
    public const long MaximumExpandedBytes = 1024L * 1024 * 1024;

    /// <summary>Extracts a verified package into a new staging directory without allowing traversal or links.</summary>
    public static IReadOnlyDictionary<string, string> ExtractToStage(string archivePath, string stagePath)
    {
        var stage = Path.GetFullPath(stagePath);
        if (Directory.Exists(stage) || File.Exists(stage)) throw new IOException("The update staging directory already exists.");
        Directory.CreateDirectory(stage);
        var hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        long expanded = 0;
        try
        {
            using var archive = ZipFile.OpenRead(archivePath);
            if (archive.Entries.Count is < 1 or > MaximumFiles) throw new InvalidDataException("The update package contains an invalid number of entries.");
            foreach (var entry in archive.Entries)
            {
                var normalized = entry.FullName.Replace('\\', '/');
                if (normalized.Length > 512 || normalized.StartsWith('/') || normalized.Contains(':') || normalized.Split('/').Any(part => part is ".." or "."))
                    throw new InvalidDataException("The update package contains an unsafe path.");
                if ((entry.ExternalAttributes >> 16 & 0xF000) == 0xA000 || (entry.ExternalAttributes & 0x400) != 0)
                    throw new InvalidDataException("Symbolic links and reparse points are not accepted in updates.");
                var target = Path.GetFullPath(Path.Combine(stage, normalized.Replace('/', Path.DirectorySeparatorChar)));
                if (!target.StartsWith(stage + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("The update path escaped its staging directory.");
                if (normalized.EndsWith('/')) { Directory.CreateDirectory(target); continue; }
                if (normalized.Split('/').Any(part => part.Equals(".downpour-update", StringComparison.OrdinalIgnoreCase)))
                    throw new InvalidDataException("The package contains a reserved update path.");
                if (entry.Length < 0 || entry.Length > MaximumExpandedBytes || expanded + entry.Length > MaximumExpandedBytes)
                    throw new InvalidDataException("The update package expands beyond its size limit.");
                expanded += entry.Length;
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                using var input = entry.Open();
                using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                var buffer = ArrayPool<byte>.Shared.Rent(65536);
                long written = 0;
                try
                {
                    int count;
                    while ((count = input.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        written += count;
                        if (written > entry.Length || written > MaximumExpandedBytes) throw new InvalidDataException("An update file exceeded its declared size.");
                        sha.AppendData(buffer, 0, count);
                        output.Write(buffer, 0, count);
                    }
                    if (written != entry.Length) throw new InvalidDataException("An update file was truncated during extraction.");
                    hashes.Add(normalized, Convert.ToHexString(sha.GetHashAndReset()));
                }
                finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
            }
            if (!hashes.ContainsKey("Downpour.Desktop.exe") || !hashes.ContainsKey("service/Downpour.Service.exe"))
                throw new InvalidDataException("The package is missing a required Downpour executable.");
            return hashes;
        }
        catch
        {
            try { Directory.Delete(stage, recursive: true); } catch { }
            throw;
        }
    }
}
