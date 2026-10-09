using Downpour.Core;

namespace Downpour.Tests;

public sealed class HardeningFixesTests
{
    private sealed class FakeHost : IFixHost
    {
        public readonly Dictionary<(string, string), RegistryReading> Values = new();
        public readonly Dictionary<int, bool> Accounts = new() { [500] = false, [501] = false };
        public readonly Dictionary<int, bool> Firewall = new() { [1] = true, [2] = true, [4] = false };
        public readonly Dictionary<string, long> Defender = new() { ["MAPSReporting"] = 0, ["PUAProtection"] = 0, ["DisableRealtimeMonitoring"] = 1 };
        public readonly Dictionary<string, int> Asr = new();
        public int CurrentRid = 1001;
        public string? FailOnWrite;
        public string? FailAfterWriteOnce;
        public string? FailOnDelete;
        public int SignatureUpdates;

        public RegistryReading? Read(string path, string name) => Values.GetValueOrDefault((path, name));
        public void WriteDword(string path, string name, long value)
        {
            Fail(name); Values[(path, name)] = new("dword", value, "");
            if (name == FailAfterWriteOnce) { FailAfterWriteOnce = null; throw new IOException("failure after mutation"); }
        }
        public void WriteString(string path, string name, string value) { Fail(name); Values[(path, name)] = new("string", 0, value); }
        public void Delete(string path, string name)
        {
            if (name == FailOnDelete) throw new IOException("rollback failed");
            Values.Remove((path, name));
        }
        public IReadOnlyList<string> SubKeys(string path) => ["Tcpip_{A}", "Tcpip_{B}", "Other"];
        public bool? AccountDisabled(int rid) => Accounts.TryGetValue(rid, out var v) ? v : null;
        public void SetAccountDisabled(int rid, bool disabled) => Accounts[rid] = disabled;
        public bool CurrentUserIs(int rid) => rid == CurrentRid;
        public bool? FirewallEnabled(int profile) => Firewall.GetValueOrDefault(profile);
        public void SetFirewallEnabled(int profile, bool enabled) => Firewall[profile] = enabled;
        public long? DefenderPreference(string name) => Defender.TryGetValue(name, out var v) ? v : null;
        public void SetDefenderPreference(string name, long value) => Defender[name] = value;
        public int? AsrRuleAction(string ruleId) => Asr.TryGetValue(ruleId, out var v) ? v : null;
        public void SetAsrRule(string ruleId, int? action) { if (action is { } a) Asr[ruleId] = a; else Asr.Remove(ruleId); }
        public void UpdateDefenderSignatures() => SignatureUpdates++;
        private void Fail(string name) { if (name == FailOnWrite) throw new IOException("simulated failure"); }
    }

    private static readonly DateTimeOffset Now = new(2026, 10, 8, 0, 0, 0, TimeSpan.Zero);
    private const string Lsa = @"SYSTEM\CurrentControlSet\Control\Lsa";

    [Fact]
    public void BackupWriteFailurePreventsTheSystemChange()
    {
        var host = new FakeHost();
        var result = HardeningFixes.Apply(host, ["ntlmv1"], "b1", Now, out var backup,
            _ => throw new IOException("disk full"));
        Assert.False(Assert.Single(result.Outcomes).Applied);
        Assert.Empty(host.Values);
        Assert.Empty(backup.Entries);
    }

    [Fact]
    public void EachOperationHasAnIndependentCumulativeBackupBeforeMutation()
    {
        var host = new FakeHost();
        var snapshots = new List<FixBackup>();
        HardeningFixes.Apply(host, ["ntlmv1", "lm-hash"], "b1", Now, out var backup, pending =>
        {
            var next = pending.Entries.Last();
            Assert.Null(host.Read(next.Path, next.Name));
            snapshots.Add(pending);
        });
        Assert.Equal(2, snapshots.Count);
        Assert.Single(snapshots[0].Entries);
        Assert.Equal(2, snapshots[1].Entries.Count);
        Assert.Equal(backup.Entries, snapshots[1].Entries);
        // The latest durable snapshot remains usable if the process exits before finalization.
        var undo = HardeningFixes.Undo(host, snapshots[1], Now);
        Assert.All(undo.Outcomes, o => Assert.True(o.Applied));
        Assert.Empty(host.Values);
    }

    [Fact]
    public void AnOperationThatThrowsAfterMutationIsStillRolledBack()
    {
        var host = new FakeHost { FailAfterWriteOnce = "LmCompatibilityLevel" };
        host.Values[(Lsa, "LmCompatibilityLevel")] = new("dword", 1, "");
        var result = HardeningFixes.Apply(host, ["ntlmv1"], "b1", Now, out var backup);
        Assert.False(Assert.Single(result.Outcomes).Applied);
        Assert.Equal(1, host.Values[(Lsa, "LmCompatibilityLevel")].Number);
        Assert.Empty(backup.Entries);
    }

    [Fact]
    public void FailedRollbackRetainsBackupForAnotherUndoAttempt()
    {
        var host = new FakeHost { FailAfterWriteOnce = "LmCompatibilityLevel", FailOnDelete = "LmCompatibilityLevel" };
        var result = HardeningFixes.Apply(host, ["ntlmv1"], "b1", Now, out var backup);
        Assert.False(Assert.Single(result.Outcomes).Applied);
        Assert.Single(backup.Entries);
        Assert.Equal("ntlmv1", Assert.Single(backup.FixIds));
        Assert.Equal(5, host.Values[(Lsa, "LmCompatibilityLevel")].Number);
        host.FailOnDelete = null;
        Assert.True(Assert.Single(HardeningFixes.Undo(host, backup, Now).Outcomes).Applied);
        Assert.Empty(host.Values);
    }

    [Fact]
    public void UnknownFixesAreRefusedWithoutAnyChange()
    {
        var host = new FakeHost();
        var result = HardeningFixes.Apply(host, ["format-c", "../uac"], "b1", Now, out var backup);

        Assert.All(result.Outcomes, o => Assert.False(o.Applied));
        Assert.Empty(host.Values);
        Assert.Empty(backup.Entries);
    }

    [Fact]
    public void ApplyThenUndoRestoresEveryValueIncludingAbsentOnes()
    {
        var host = new FakeHost();
        host.Values[(Lsa, "LmCompatibilityLevel")] = new("dword", 1, "");
        var result = HardeningFixes.Apply(host, ["ntlmv1", "wdigest", "firewall", "defender-cloud", "netbios", "asr-rules"], "b1", Now, out var backup);

        Assert.All(result.Outcomes, o => Assert.True(o.Applied, o.Message));
        Assert.Equal(5, host.Values[(Lsa, "LmCompatibilityLevel")].Number);
        Assert.True(host.Firewall[4]);
        Assert.Equal(2, host.Defender["MAPSReporting"]);
        Assert.Equal(2, host.Values.Count(v => v.Key.Item2 == "NetbiosOptions"));
        Assert.Equal(HardeningFixes.AsrRules.Count, host.Asr.Count);

        var undo = HardeningFixes.Undo(host, backup, Now);
        Assert.All(undo.Outcomes, o => Assert.True(o.Applied, o.Message));
        Assert.Equal(1, host.Values[(Lsa, "LmCompatibilityLevel")].Number);
        Assert.False(host.Values.ContainsKey((@"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential")));
        Assert.False(host.Firewall[4]);
        Assert.Equal(0, host.Defender["MAPSReporting"]);
        Assert.DoesNotContain(host.Values, v => v.Key.Item2 == "NetbiosOptions");
        Assert.Empty(host.Asr);
    }

    [Fact]
    public void AFixThatFailsPartWayIsRolledBack()
    {
        var host = new FakeHost { FailOnWrite = "PromptOnSecureDesktop" };
        host.Values[(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")] = new("dword", 0, "");

        var result = HardeningFixes.Apply(host, ["uac"], "b1", Now, out var backup);

        Assert.False(Assert.Single(result.Outcomes).Applied);
        Assert.Equal(0, host.Values[(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")].Number);
        Assert.False(host.Values.ContainsKey((@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin")));
        Assert.Empty(backup.Entries);
    }

    [Fact]
    public void TheSignedInBuiltInAdministratorIsNeverDisabled()
    {
        var host = new FakeHost { CurrentRid = 500 };
        var result = HardeningFixes.Apply(host, ["builtin-admin", "guest"], "b1", Now, out _);

        Assert.False(result.Outcomes.Single(o => o.FixId == "builtin-admin").Applied);
        Assert.False(host.Accounts[500]);
        Assert.True(host.Accounts[501]);
    }

    [Fact]
    public void StoredPasswordIsDeletedButNeverBackedUp()
    {
        const string winlogon = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        var host = new FakeHost();
        host.Values[(winlogon, "AutoAdminLogon")] = new("string", 0, "1");
        host.Values[(winlogon, "DefaultPassword")] = new("string", 0, "hunter2");

        HardeningFixes.Apply(host, ["autologon"], "b1", Now, out var backup);

        Assert.False(host.Values.ContainsKey((winlogon, "DefaultPassword")));
        Assert.DoesNotContain(backup.Entries, e => e.PreviousText == "hunter2");
        HardeningFixes.Undo(host, backup, Now);
        Assert.Equal("1", host.Values[(winlogon, "AutoAdminLogon")].Text);
        Assert.False(host.Values.ContainsKey((winlogon, "DefaultPassword")));
    }

    [Fact]
    public void UnexpectedRegistryTypesAreLeftAlone()
    {
        var host = new FakeHost();
        host.Values[(Lsa, "NoLMHash")] = new("other", 0, "");
        var result = HardeningFixes.Apply(host, ["lm-hash"], "b1", Now, out _);
        Assert.False(Assert.Single(result.Outcomes).Applied);
        Assert.Equal("other", host.Values[(Lsa, "NoLMHash")].Kind);
    }

    [Fact]
    public void EveryFixMatchesAHardeningCheckAndIsReversibleExceptSignatureUpdates()
    {
        var checkIds = HardeningPostureEvaluator.Evaluate(new PostureReadings())
            .Concat(HardeningPostureEvaluator.EvaluateExtended(new PostureReadings(), Now)).Select(c => c.Id).ToHashSet();
        Assert.All(HardeningFixes.All, f => Assert.Contains(f.Id, checkIds));
        Assert.Equal(HardeningFixes.All.Count, HardeningFixes.All.Select(f => f.Id).Distinct().Count());
    }

    [Theory]
    [InlineData(new[] { "apply", "0123456789abcdef0123456789abcdef", "uac,llmnr" }, true)]
    [InlineData(new[] { "undo", "0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210" }, true)]
    [InlineData(new[] { "updates", "0123456789abcdef0123456789abcdef", "drivers" }, true)]
    [InlineData(new[] { "apply", "0123456789abcdef0123456789abcdef", "uac,cmd.exe" }, false)]
    [InlineData(new[] { "updates", "0123456789abcdef0123456789abcdef", "C:\\evil" }, false)]
    [InlineData(new[] { "undo", "..\\..\\x", "fedcba9876543210fedcba9876543210" }, false)]
    [InlineData(new[] { "shell", "0123456789abcdef0123456789abcdef", "x" }, false)]
    [InlineData(new[] { "apply", "0123456789abcdef0123456789abcdef" }, false)]
    public void FixerCommandLineIsStrictlyValidated(string[] args, bool valid) =>
        Assert.Equal(valid, FixerProtocol.IsValidCommand(args, out _));
}
