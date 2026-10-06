using Downpour.Contracts;
using Downpour.Core;
using Downpour.Service;

namespace Downpour.Tests;

public sealed class DriverPackageInventoryProviderTests
{
    [Fact]
    public void ParseInfVersionResolvesStringTokensAndSplitsDriverVer()
    {
        const string inf = """
            ; comment line
            [Version]
            Signature="$WINDOWS NT$"
            Class=Net ; trailing comment
            Provider=%ProviderName%
            DriverVer=05/14/2024,10.0.22621.1 ; date,version

            [Strings]
            ProviderName="Contoso; Ltd"
            """;

        var info = DriverPackageInventoryProvider.ParseInfVersion(inf);

        Assert.Equal("Net", info.Class);
        Assert.Equal("Contoso; Ltd", info.Provider);
        Assert.Equal("10.0.22621.1", info.Version);
        Assert.Equal("05/14/2024", info.Date);
    }

    [Fact]
    public void ParseInfVersionToleratesMissingSectionsAndUnresolvedTokens()
    {
        var empty = DriverPackageInventoryProvider.ParseInfVersion("garbage without sections");
        Assert.Equal(InfVersionInfo.Empty, empty);

        var unresolved = DriverPackageInventoryProvider.ParseInfVersion("[Version]\nProvider=%Missing%\nDriverVer=01/01/2020");
        Assert.Equal("%Missing%", unresolved.Provider);
        Assert.Equal("", unresolved.Version);
        Assert.Equal("01/01/2020", unresolved.Date);
    }

    [Theory]
    [InlineData("oem12.inf", true)]
    [InlineData("machine.inf", true)]
    [InlineData("..\\evil.inf", false)]
    [InlineData("dir/oem1.inf", false)]
    [InlineData("oem1.sys", false)]
    [InlineData(".inf", false)]
    public void IsSafeInfNameRejectsPathsAndNonInfNames(string name, bool expected) =>
        Assert.Equal(expected, DriverPackageInventoryProvider.IsSafeInfName(name));

    [Fact]
    public void ClassifyOnlyTreatsTrustedCatalogSignatureAsSigned()
    {
        Assert.False(SignatureResult.Classify(catalogFound: false, 0, null).IsSigned);
        Assert.StartsWith("Not signed", SignatureResult.Classify(false, 0, null).Status);

        var valid = SignatureResult.Classify(true, 0, "Microsoft Windows");
        Assert.True(valid.IsSigned);
        Assert.Equal("Microsoft Windows", valid.SignerName);

        foreach (var failure in new uint[] { 0x800B0100, 0x800B0101, 0x800B010C, 0x800B0109, 0x80096010, 0x800B0111, 0x80004005 })
        {
            var result = SignatureResult.Classify(true, failure, "Someone");
            Assert.False(result.IsSigned);
            Assert.False(result.Status.StartsWith("Valid", StringComparison.Ordinal));
        }

        Assert.StartsWith("Unknown", SignatureResult.Unknown("x").Status);
        Assert.False(SignatureResult.Unknown("x").IsSigned);
    }

    [Fact]
    public void InboxInfVerifiesAgainstSystemCatalog()
    {
        var machineInf = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "INF", "machine.inf");
        Assert.True(File.Exists(machineInf), "machine.inf ships with every Windows installation.");

        using var verifier = CatalogSignatureVerifier.TryCreate(out var error);
        Assert.True(verifier is not null, error);
        var result = verifier!.Verify(machineInf);

        Assert.True(result.IsSigned, result.Status);
        Assert.False(string.IsNullOrWhiteSpace(result.SignerName));
    }

    [Fact]
    public void UnsignedFileIsReportedAsNotSigned()
    {
        var path = Path.Combine(Path.GetTempPath(), $"downpour-unsigned-{Guid.NewGuid():N}.inf");
        File.WriteAllText(path, "[Version]\nSignature=\"$WINDOWS NT$\"\n");
        try
        {
            using var verifier = CatalogSignatureVerifier.TryCreate(out _);
            var result = verifier!.Verify(path);
            Assert.False(result.IsSigned);
            Assert.StartsWith("Not signed", result.Status);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void CaptureReturnsBoundedVerifiedInventory()
    {
        var snapshot = new DriverPackageInventoryProvider().Capture();

        Assert.Equal(1, snapshot.SchemaVersion);
        Assert.Equal(snapshot.PackageCount, snapshot.Packages.Count);
        Assert.InRange(snapshot.Packages.Count, 1, DriverPackageInventoryProvider.MaximumPackages);
        Assert.Equal(snapshot.Packages.Count, snapshot.Packages.Select(p => p.InfFile).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Contains(snapshot.Packages, package => package.IsSigned);
        Assert.All(snapshot.Packages, package =>
        {
            Assert.True(DriverPackageInventoryProvider.IsSafeInfName(package.InfFile));
            Assert.False(string.IsNullOrEmpty(package.SignatureStatus));
            if (package.IsSigned) Assert.Equal("Valid catalog signature", package.SignatureStatus);
        });
        Assert.True(DriverPackageInventoryClient.IsValid(snapshot));
    }

    [Fact]
    public void ClientRejectsInconsistentOrOversizedSnapshots()
    {
        var entry = new DriverPackageEntry("oem1.inf", "x.inf", "Net", "P", "1.0", "01/01/2024", "PCI\\VEN", true, "S", "Valid catalog signature");
        var good = new DriverPackageInventorySnapshot(1, DateTimeOffset.UtcNow, 1, [entry], []);
        Assert.True(DriverPackageInventoryClient.IsValid(good));
        Assert.False(DriverPackageInventoryClient.IsValid(good with { PackageCount = 2 }));
        Assert.False(DriverPackageInventoryClient.IsValid(good with { SchemaVersion = 2 }));
        Assert.False(DriverPackageInventoryClient.IsValid(good with { Packages = [entry with { ProviderName = new string('x', 1025) }] }));
        Assert.False(DriverPackageInventoryClient.IsValid(null));
    }
}
