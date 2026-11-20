using System.Security.Cryptography;
using System.Text;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class FollowUpTrustFoundationsTests
{
    [Fact]
    public void SignedReleasesAreTrustedAndTamperedOnesAreRefused()
    {
        var verified = ReleaseTrustPolicy.Decide(ReleaseSignatureStatus.Valid, requiresSignature: true);
        Assert.Equal(ReleaseTrustState.Verified, verified.State);
        Assert.True(verified.AllowsInstall);

        var unsignedRelease = ReleaseTrustPolicy.Decide(ReleaseSignatureStatus.Unsigned, requiresSignature: true);
        Assert.Equal(ReleaseTrustState.Untrusted, unsignedRelease.State);
        Assert.False(unsignedRelease.AllowsInstall, "A signed channel must fail closed.");

        var unsignedDev = ReleaseTrustPolicy.Decide(ReleaseSignatureStatus.Unsigned, requiresSignature: false);
        Assert.Equal(ReleaseTrustState.UnsignedDevelopment, unsignedDev.State);
        Assert.True(unsignedDev.AllowsInstall);

        var tampered = ReleaseTrustPolicy.Decide(ReleaseSignatureStatus.Invalid, requiresSignature: false);
        Assert.Equal(ReleaseTrustState.Untrusted, tampered.State);
        Assert.False(tampered.AllowsInstall, "An invalid signature is interference, not a missing key.");
    }

    [Fact]
    public void TrustInputsMustMatchTheirPinsAndUnexpectedFilesAreRefused()
    {
        var expected = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["rules/one.yml"] = new string('a', 64),
            ["catalog.json"] = new string('b', 64),
        };
        var actual = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["rules/one.yml"] = new string('a', 64),
            ["catalog.json"] = new string('c', 64),
            ["rules/dropped.yml"] = new string('d', 64),
        };

        var violations = TrustedContentIntegrity.Verify(expected, actual);
        Assert.Equal(2, violations.Count);
        Assert.Contains(violations, violation => violation.RelativePath == "catalog.json" && violation.Problem.Contains("pinned hash"));
        Assert.Contains(violations, violation => violation.RelativePath == "rules/dropped.yml" && violation.Problem.Contains("unexpected"));
        Assert.Empty(TrustedContentIntegrity.Verify(expected, expected));
        Assert.Contains(TrustedContentIntegrity.Verify(expected, new Dictionary<string, string>()),
            violation => violation.Problem.Contains("missing"));
    }

    [Fact]
    public void AuditAnchorDetectsTruncationAndRewriting()
    {
        var anchor = AuditAnchorPolicy.CreateAnchor(DateTimeOffset.Parse("2026-11-20T00:00:00Z"), "head-a", 100);
        Assert.Null(AuditAnchorPolicy.VerifyContinuity(null, "anything", 5));
        Assert.Null(AuditAnchorPolicy.VerifyContinuity(anchor, "head-a", 100));
        Assert.Null(AuditAnchorPolicy.VerifyContinuity(anchor, "head-b", 140));
        Assert.Contains("truncated", AuditAnchorPolicy.VerifyContinuity(anchor, "head-a", 99));
        Assert.Contains("rewritten", AuditAnchorPolicy.VerifyContinuity(anchor, "head-b", 100));
    }

    [Fact]
    public void CasePackPreviewExcludesUserContentAndSecrets()
    {
        var preview = CasePackRedaction.Preview(["processName", "commandLine", "apiKey", "sourceId", "scriptBlockText"]);
        Assert.True(CasePackRedaction.IsExportable(preview, "processName"));
        Assert.True(CasePackRedaction.IsExportable(preview, "sourceId"));
        Assert.False(CasePackRedaction.IsExportable(preview, "commandLine"));
        Assert.False(CasePackRedaction.IsExportable(preview, "apiKey"));
        Assert.False(preview.Single(field => field.Name == "commandLine").Included);
        Assert.All(preview.Where(field => !field.Included), field => Assert.False(string.IsNullOrWhiteSpace(field.Reason)));
    }

    [Fact]
    public void CasePacksCanBeSignedAndVerified()
    {
        using var key = RSA.Create(2048);
        var pack = Encoding.UTF8.GetBytes("{\"case\":\"pack\"}");
        var signature = CasePackSignature.Sign(pack, key);
        var publicKey = key.ExportSubjectPublicKeyInfoPem();

        Assert.Equal(ReleaseSignatureStatus.Valid, CasePackSignature.Verify(pack, signature, publicKey));
        Assert.Equal(ReleaseSignatureStatus.Unsigned, CasePackSignature.Verify(pack, null, publicKey));
        Assert.Equal(ReleaseSignatureStatus.Invalid, CasePackSignature.Verify(Encoding.UTF8.GetBytes("{\"case\":\"other\"}"), signature, publicKey));
        Assert.Contains("cannot be proven", CasePackSignature.Describe(ReleaseSignatureStatus.Unsigned));
    }

    [Fact]
    public void DiagnosticsRedactPathsHeadersAndTokens()
    {
        var path = @"C:\Users\alice\AppData\Local\DownpourNext\state\log.jsonl";
        var redactedPath = DiagnosticsBundle.Redact(path);
        Assert.DoesNotContain("alice", redactedPath, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("%USERPROFILE%", redactedPath);

        Assert.DoesNotContain("abcd1234", DiagnosticsBundle.Redact("Auth-Key: abcd1234"));
        var token = new string('A', 48);
        Assert.DoesNotContain(token, DiagnosticsBundle.Redact($"token {token} end"));

        var sections = new[]
        {
            new DiagnosticSection("service", Enumerable.Range(0, 80).Select(index => $"line {index}").ToArray()),
            new DiagnosticSection("feeds", Enumerable.Range(0, 500).Select(index => $"feed {index}").ToArray()),
        };
        var built = DiagnosticsBundle.Build(sections);
        Assert.True(built[0].Lines.Count <= DiagnosticsBundle.MaximumLinesPerSection + 1);
        Assert.True(built.Sum(section => section.Lines.Count) <= DiagnosticsBundle.MaximumTotalLines + 2);
        Assert.Contains(built[0].Lines, line => line.Contains("truncated"));
    }

    [Fact]
    public void ShippedComponentsAreMatchedAgainstAdvisories()
    {
        var components = new[]
        {
            new ShippedComponent("Newtonsoft.Json", "13.0.1"),
            new ShippedComponent("Other.Library", "1.2.3"),
        };
        var advisories = new[]
        {
            new ComponentAdvisory("GHSA-test-0001", "newtonsoft.json",
                new ComponentRange(VersionStartIncluding: "13.0.0", VersionEndExcluding: "13.0.3"), "HIGH"),
            new ComponentAdvisory("GHSA-test-0002", "Other.Library", new ComponentRange(VersionEndExcluding: "1.0.0"), "LOW"),
        };

        var risks = ComponentVulnerabilityMatcher.Match(components, advisories);
        var risk = Assert.Single(risks);
        Assert.Equal("GHSA-test-0001", risk.AdvisoryId);
        Assert.Contains("13.0.1", risk.Analysis);

        Assert.True(ComponentVulnerabilityMatcher.IsInRange("13.0.2", advisories[0].Range));
        Assert.False(ComponentVulnerabilityMatcher.IsInRange("13.0.3", advisories[0].Range), "An excluded end bound must not match.");
        Assert.False(ComponentVulnerabilityMatcher.IsInRange("12.9.9", advisories[0].Range));
        Assert.False(ComponentVulnerabilityMatcher.IsInRange("1.0.0", new ComponentRange()), "A bound-less advisory is malformed, not universal.");
    }

    [Fact]
    public void PipeAclsRefuseBroadLocalGroups()
    {
        Assert.Empty(ServiceIdentityPolicy.ValidatePipeAcl([new AclPrincipal("current user", "S-1-5-21-1-2-3-1001")]));
        var broad = ServiceIdentityPolicy.ValidatePipeAcl([
            new AclPrincipal("Everyone", "S-1-1-0"),
            new AclPrincipal("Authenticated Users", "S-1-5-11"),
        ]);
        Assert.Equal(2, broad.Count);
        Assert.Contains(broad, problem => problem.Contains("Everyone"));
        Assert.Contains(ServiceIdentityPolicy.ValidatePipeAcl([]), problem => problem.Contains("no principal"));
        Assert.NotEmpty(ServiceIdentityPolicy.InstalledModeRequirements());
    }
}
