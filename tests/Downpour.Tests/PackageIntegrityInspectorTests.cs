using System.Security.Cryptography;
using System.Text;
using Downpour.Core;
using Newtonsoft.Json.Linq;

namespace Downpour.Tests;

public sealed class PackageIntegrityInspectorTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "DownpourIntegrityTests-" + Guid.NewGuid().ToString("N"));
    public PackageIntegrityInspectorTests() { Directory.CreateDirectory(Path.Combine(_root, "service")); }
    public void Dispose() { Directory.Delete(_root, true); }

    [Fact]
    public async Task RealBytesMatchWithoutChangingFiles()
    {
        var manifest = CreateManifest();
        Save(manifest);
        var result = await PackageIntegrityInspector.InspectAsync(_root, "0.1.16");
        Assert.Equal("Matches local manifest", result.Status);
        Assert.Equal(2, result.MatchingFiles);
        Assert.Equal(2, result.CheckedFiles);
        Assert.Equal(11, result.BytesHashed);
        Assert.Empty(result.Findings);
        Assert.Equal("desktop", File.ReadAllText(Path.Combine(_root, "Downpour.Desktop.exe")));
        Assert.Contains("not publisher authenticity", result.Scope);
        Assert.Equal(64, result.ManifestSha256!.Length);
    }

    [Fact]
    public async Task DetectsSameSizeTamperingAndMissingFiles()
    {
        Save(CreateManifest());
        File.WriteAllText(Path.Combine(_root, "Downpour.Desktop.exe"), "changed");
        File.Delete(Path.Combine(_root, "service/Downpour.Service.exe"));
        var result = await PackageIntegrityInspector.InspectAsync(_root, "0.1.16");
        Assert.Equal("Differences or unavailable files", result.Status);
        Assert.Equal(0, result.MatchingFiles);
        Assert.Equal(2, result.CheckedFiles);
        Assert.Contains(result.Findings, f => f.Status == "SHA-256 mismatch");
        Assert.Contains(result.Findings, f => f.Status == "Missing");
    }

    [Fact]
    public async Task SizeMismatchIsNotHashedOrAccepted()
    {
        Save(CreateManifest());
        File.WriteAllText(Path.Combine(_root, "Downpour.Desktop.exe"), "longer bytes");
        var result = await PackageIntegrityInspector.InspectAsync(_root, "0.1.16");
        Assert.Equal(1, result.MatchingFiles);
        Assert.Equal(4, result.BytesHashed);
        Assert.Contains(result.Findings, f => f.Status == "Size mismatch");
    }

    [Theory]
    [InlineData("../outside.txt")]
    [InlineData("/outside.txt")]
    [InlineData("C:/outside.txt")]
    [InlineData("service/../outside.txt")]
    [InlineData("service//outside.txt")]
    [InlineData("service\\outside.txt")]
    [InlineData("service/data:stream")]
    [InlineData("service/NUL.txt")]
    [InlineData("service/COM1")]
    [InlineData("service/file.")]
    [InlineData("service/file ")]
    [InlineData(".downpour-update/state.json")]
    [InlineData("release-manifest.json")]
    public async Task RejectsPathsBeforeReadingAnyListedFile(string path)
    {
        var manifest = CreateManifest();
        manifest["files"]![0]!["path"] = path;
        Save(manifest);
        var result = await PackageIntegrityInspector.InspectAsync(_root, "0.1.16");
        Assert.Equal("Invalid manifest", result.Status);
        Assert.Equal(0, result.CheckedFiles);
        Assert.Equal(0, result.BytesHashed);
    }

    [Fact]
    public async Task RejectsCaseAliasedPathsUnknownFieldsAndOversizeBudget()
    {
        var manifest = CreateManifest();
        ((JArray)manifest["files"]!).Add(new JObject((JObject)manifest["files"]![0]!) { ["path"] = "DOWNPOUR.DESKTOP.EXE" });
        Save(manifest);
        Assert.Equal("Invalid manifest", (await PackageIntegrityInspector.InspectAsync(_root, "0.1.16")).Status);
        manifest = CreateManifest(); manifest["autoExecute"] = true; Save(manifest);
        Assert.Equal("Invalid manifest", (await PackageIntegrityInspector.InspectAsync(_root, "0.1.16")).Status);
        manifest = CreateManifest(); manifest["files"]![0]!["bytes"] = PackageIntegrityInspector.MaximumFileBytes + 1; Save(manifest);
        Assert.Equal("Invalid manifest", (await PackageIntegrityInspector.InspectAsync(_root, "0.1.16")).Status);
    }

    [Fact]
    public async Task RejectsWrongVersionMissingRequiredFileAndMalformedHash()
    {
        var manifest = CreateManifest(); Save(manifest);
        Assert.Equal("Invalid manifest", (await PackageIntegrityInspector.InspectAsync(_root, "0.1.17")).Status);
        manifest["files"]![0]!["sha256"] = "not-a-hash"; Save(manifest);
        Assert.Equal("Invalid manifest", (await PackageIntegrityInspector.InspectAsync(_root, "0.1.16")).Status);
        manifest = CreateManifest(); manifest["files"]![0]!["path"] = "other.exe"; Save(manifest);
        Assert.Equal("Invalid manifest", (await PackageIntegrityInspector.InspectAsync(_root, "0.1.16")).Status);
    }

    [Fact]
    public async Task DuplicatePropertiesTrailingDataAndOversizeManifestFailClosed()
    {
        var text = CreateManifest().ToString();
        File.WriteAllText(Path.Combine(_root, "release-manifest.json"), text.Replace("\"schemaVersion\": 1", "\"schemaVersion\": 1, \"schemaVersion\": 1"));
        Assert.Equal("Invalid manifest", (await PackageIntegrityInspector.InspectAsync(_root, "0.1.16")).Status);
        File.WriteAllText(Path.Combine(_root, "release-manifest.json"), text + " {}");
        Assert.Equal("Invalid manifest", (await PackageIntegrityInspector.InspectAsync(_root, "0.1.16")).Status);
        File.WriteAllText(Path.Combine(_root, "release-manifest.json"), new string(' ', PackageIntegrityInspector.MaximumManifestBytes + 1));
        Assert.Equal("Invalid manifest", (await PackageIntegrityInspector.InspectAsync(_root, "0.1.16")).Status);
    }

    [Fact]
    public async Task AbsentManifestIsUnavailableAndCancellationPropagates()
    {
        Assert.Equal("Unavailable", (await PackageIntegrityInspector.InspectAsync(_root, "0.1.16")).Status);
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => PackageIntegrityInspector.InspectAsync(_root, "0.1.16", cancellationToken: cancel.Token));
    }

    [Fact]
    public async Task CancellationAfterManifestReadNeverReportsAMatch()
    {
        Save(CreateManifest());
        using var cancel = new CancellationTokenSource();
        var progress = new InlineProgress(_ => cancel.Cancel());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => PackageIntegrityInspector.InspectAsync(_root, "0.1.16", progress, cancel.Token));
    }

    [Fact]
    public async Task FileCountAndTotalByteBudgetsFailBeforeFileReads()
    {
        var manifest = CreateManifest();
        var files = (JArray)manifest["files"]!;
        for (var i = 0; i < PackageIntegrityInspector.MaximumFiles; i++)
            files.Add(new JObject { ["path"] = $"extra{i}.bin", ["bytes"] = 0, ["sha256"] = new string('a', 64) });
        Save(manifest);
        var result = await PackageIntegrityInspector.InspectAsync(_root, "0.1.16");
        Assert.Equal("Invalid manifest", result.Status);
        Assert.Equal(0, result.CheckedFiles);
        manifest = CreateManifest(); files = (JArray)manifest["files"]!;
        for (var i = 0; i < 5; i++)
            files.Add(new JObject { ["path"] = $"extra{i}.bin", ["bytes"] = PackageIntegrityInspector.MaximumFileBytes, ["sha256"] = new string('a', 64) });
        Save(manifest);
        result = await PackageIntegrityInspector.InspectAsync(_root, "0.1.16");
        Assert.Equal("Invalid manifest", result.Status);
        Assert.Equal(0, result.CheckedFiles);
    }

    [SymbolicLinkFact]
    public async Task RejectsLinkedDirectoriesAndManifest()
    {
        var manifest = CreateManifest();
        Directory.CreateSymbolicLink(Path.Combine(_root, "alias"), Path.Combine(_root, "service"));
        var copy = new JObject((JObject)manifest["files"]![1]!) { ["path"] = "alias/Downpour.Service.exe" };
        ((JArray)manifest["files"]!).Add(copy);
        Save(manifest);
        var result = await PackageIntegrityInspector.InspectAsync(_root, "0.1.16");
        Assert.Equal(2, result.MatchingFiles);
        Assert.Contains(result.Findings, f => f.RelativePath.StartsWith("alias/") && f.Status == "Unsafe path or link");
        var path = Path.Combine(_root, "release-manifest.json");
        var target = Path.Combine(_root, "baseline.json");
        File.Move(path, target);
        File.CreateSymbolicLink(path, target);
        result = await PackageIntegrityInspector.InspectAsync(_root, "0.1.16");
        Assert.Equal("Invalid manifest", result.Status);
        Assert.Equal(0, result.CheckedFiles);
    }

    private JObject CreateManifest()
    {
        var files = new JArray();
        foreach (var (path, text) in new[] { ("Downpour.Desktop.exe", "desktop"), ("service/Downpour.Service.exe", "data") })
        {
            File.WriteAllText(Path.Combine(_root, path), text, new UTF8Encoding(false));
            var raw = Encoding.UTF8.GetBytes(text);
            files.Add(new JObject { ["path"] = path, ["bytes"] = raw.Length, ["sha256"] = Convert.ToHexString(SHA256.HashData(raw)).ToLowerInvariant() });
        }
        return new() { ["schemaVersion"] = 1, ["version"] = "0.1.16", ["sourceCommit"] = new string('a', 40), ["files"] = files };
    }
    private void Save(JObject manifest) => File.WriteAllText(Path.Combine(_root, "release-manifest.json"), manifest.ToString(), new UTF8Encoding(false));
    private sealed class InlineProgress(Action<string> callback) : IProgress<string> { public void Report(string value) => callback(value); }
}

/// <summary>Reports a real skip when Windows lacks Developer Mode/SeCreateSymbolicLinkPrivilege.</summary>
internal sealed class SymbolicLinkFactAttribute : FactAttribute
{
    public SymbolicLinkFactAttribute()
    {
        var root = Path.Combine(Path.GetTempPath(), "DownpourLinkCapability-" + Guid.NewGuid().ToString("N"));
        var target = Path.Combine(root, "target");
        var link = Path.Combine(root, "link");
        try
        {
            Directory.CreateDirectory(target);
            Directory.CreateSymbolicLink(link, target);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or PlatformNotSupportedException or IOException)
        { Skip = "Symbolic-link fixtures require Windows Developer Mode or SeCreateSymbolicLinkPrivilege."; }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }
}
