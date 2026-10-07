using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Downpour.Contracts;

namespace Downpour.Scanner;

/// <summary>
/// Compiled rule set plus one reusable scanner. Each rule file is compiled alone first so a broken file is reported and
/// excluded instead of failing the whole set; files YARA-X rejects in strict mode are retried with YARA-compatible
/// regex syntax (v29 used a "lenient compile"). Includes are disabled. Not thread-safe: one scan at a time.
/// </summary>
public sealed unsafe partial class YaraEngine : IDisposable
{
    public const int MaximumRuleFileBytes = 1024 * 1024;
    public const int ScanTimeoutSeconds = 10;
    private const int MaximumMatchesPerScan = 100;
    private IntPtr _rules;
    private IntPtr _scanner;
    private readonly List<YaraRuleMatch> _matches = [];

    public int RuleCount { get; }

    /// <summary>"namespace:rule" keys measured as noisy on clean system files (see tools/yara_rule_quality.py).</summary>
    public IReadOnlySet<string> LowConfidence { get; set; } = new HashSet<string>(StringComparer.Ordinal);
    public IReadOnlyList<YaraRuleFileStatus> RuleFiles { get; }

    private YaraEngine(IntPtr rules, IntPtr scanner, int ruleCount, IReadOnlyList<YaraRuleFileStatus> files)
    {
        _rules = rules;
        _scanner = scanner;
        RuleCount = ruleCount;
        RuleFiles = files;
    }

    [GeneratedRegex(@"^T\d{4}(\.\d{3})?$", RegexOptions.CultureInvariant)]
    private static partial Regex TechniquePattern();

    public static YaraEngine LoadDirectory(string directory)
    {
        var files = Directory.Exists(directory)
            ? Directory.EnumerateFiles(directory, "*.yar").OrderBy(f => f, StringComparer.OrdinalIgnoreCase).Take(200)
                .Select(path => (Name: Path.GetFileName(path), Source: new FileInfo(path).Length <= MaximumRuleFileBytes ? File.ReadAllText(path) : null))
                .ToArray()
            : [];
        return Compile(files);
    }

    public static YaraEngine Compile(IReadOnlyList<(string Name, string? Source)> files)
    {
        var report = new List<YaraRuleFileStatus>();
        var accepted = new List<(string Name, string Source)>();
        var anyRelaxed = false;
        foreach (var (name, source) in files)
        {
            if (source is null)
            {
                report.Add(new(name, false, 0, false, "The file exceeds the 1 MiB rule size limit."));
                continue;
            }
            var (count, error) = TryCompileAlone(name, source, YaraX.DisableIncludes);
            var relaxed = false;
            if (error is not null)
            {
                var (relaxedCount, relaxedError) = TryCompileAlone(name, source, YaraX.DisableIncludes | YaraX.RelaxedRegexSyntax);
                if (relaxedError is null)
                {
                    (count, error, relaxed) = (relaxedCount, null, true);
                    anyRelaxed = true;
                }
            }
            report.Add(new(name, error is null, count, relaxed, error));
            if (error is null) accepted.Add((name, source));
        }

        var flags = YaraX.DisableIncludes | (anyRelaxed ? YaraX.RelaxedRegexSyntax : 0);
        Check(YaraX.yrx_compiler_create(flags, out var compiler), "create the compiler");
        IntPtr rules;
        try
        {
            foreach (var (name, source) in accepted)
            {
                using var ns = Utf8(Path.GetFileNameWithoutExtension(name));
                using var src = Utf8(source);
                using var origin = Utf8(name);
                Check(YaraX.yrx_compiler_new_namespace(compiler, ns.Pointer), "create a namespace");
                Check(YaraX.yrx_compiler_add_source_with_origin(compiler, src.Pointer, origin.Pointer), $"add {name}");
            }
            rules = YaraX.yrx_compiler_build(compiler);
        }
        finally
        {
            YaraX.yrx_compiler_destroy(compiler);
        }
        if (rules == IntPtr.Zero) throw new InvalidOperationException("YARA-X did not build the rule set.");
        if (YaraX.yrx_scanner_create(rules, out var scanner) != YaraX.Success)
        {
            YaraX.yrx_rules_destroy(rules);
            throw new InvalidOperationException("YARA-X could not create a scanner: " + YaraX.LastError());
        }
        YaraX.yrx_scanner_set_timeout(scanner, ScanTimeoutSeconds);
        YaraX.yrx_scanner_max_matches_per_pattern(scanner, 1000);
        return new YaraEngine(rules, scanner, Math.Max(0, YaraX.yrx_rules_count(rules)), report);
    }

    private static (int Count, string? Error) TryCompileAlone(string name, string source, uint flags)
    {
        if (YaraX.yrx_compiler_create(flags, out var compiler) != YaraX.Success) return (0, "The compiler could not be created.");
        try
        {
            using var src = Utf8(source);
            using var origin = Utf8(name);
            if (YaraX.yrx_compiler_add_source_with_origin(compiler, src.Pointer, origin.Pointer) != YaraX.Success)
                return (0, Bound(YaraX.LastError(), 600));
            var rules = YaraX.yrx_compiler_build(compiler);
            if (rules == IntPtr.Zero) return (0, "The rules could not be built.");
            var count = YaraX.yrx_rules_count(rules);
            YaraX.yrx_rules_destroy(rules);
            return (Math.Max(0, count), null);
        }
        finally
        {
            YaraX.yrx_compiler_destroy(compiler);
        }
    }

    /// <summary>Scans an in-memory buffer. Returns the status ("matched", "clean", "timeout", "error") and matches.</summary>
    public (string Status, string? Message, IReadOnlyList<YaraRuleMatch> Matches) Scan(ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_scanner == IntPtr.Zero, this);
        _matches.Clear();
        var handle = GCHandle.Alloc(this);
        try
        {
            YaraX.yrx_scanner_on_matching_rule(_scanner, &OnMatchingRule, GCHandle.ToIntPtr(handle));
            int result;
            fixed (byte* pointer = data) result = YaraX.yrx_scanner_scan(_scanner, pointer, (nuint)data.Length);
            var matches = _matches.ToArray();
            return result switch
            {
                YaraX.Success => (matches.Length > 0 ? "matched" : "clean", null, matches),
                YaraX.ScanTimeout => ("timeout", $"The scan exceeded {ScanTimeoutSeconds} seconds.", matches),
                _ => ("error", Bound(YaraX.LastError(), 300), matches),
            };
        }
        finally
        {
            YaraX.yrx_scanner_on_matching_rule(_scanner, null, IntPtr.Zero);
            handle.Free();
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
    private static void OnMatchingRule(IntPtr rule, IntPtr userData)
    {
        if (GCHandle.FromIntPtr(userData).Target is not YaraEngine engine || engine._matches.Count >= MaximumMatchesPerScan) return;
        var name = YaraX.yrx_rule_identifier(rule, out var identifier, out var length) == YaraX.Success ? Text(identifier, length) : "";
        var ns = YaraX.yrx_rule_namespace(rule, out var nsPointer, out var nsLength) == YaraX.Success ? Text(nsPointer, nsLength) : "";
        var state = new RuleDetails();
        var detailHandle = GCHandle.Alloc(state);
        try
        {
            YaraX.yrx_rule_iter_metadata(rule, &OnMetadata, GCHandle.ToIntPtr(detailHandle));
            YaraX.yrx_rule_iter_tags(rule, &OnTag, GCHandle.ToIntPtr(detailHandle));
        }
        finally
        {
            detailHandle.Free();
        }
        engine._matches.Add(new YaraRuleMatch(Bound(name, 128), Bound(ns, 64), NormalizeSeverity(state.Severity),
            Bound(state.Description ?? "", 300), state.Technique ?? "", state.Tags.Take(16).ToArray(), engine.LowConfidence.Contains(ns + ":" + name) || engine.LowConfidence.Contains(RuleQuality.AllRules)));
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
    private static void OnMetadata(YaraX.Metadata* metadata, IntPtr userData)
    {
        if (GCHandle.FromIntPtr(userData).Target is not RuleDetails details || metadata->ValueType != 3) return;
        var key = Marshal.PtrToStringUTF8(metadata->Identifier) ?? "";
        var value = Marshal.PtrToStringUTF8(metadata->String) ?? "";
        switch (key)
        {
            case "severity": details.Severity = value; break;
            case "description": details.Description = value; break;
            case "mitre_attack" or "mitre":
                var first = value.Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries).FirstOrDefault(token => TechniquePattern().IsMatch(token));
                details.Technique ??= first;
                break;
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
    private static void OnTag(IntPtr tag, IntPtr userData)
    {
        if (GCHandle.FromIntPtr(userData).Target is RuleDetails details && details.Tags.Count < 16)
            details.Tags.Add(Bound(Marshal.PtrToStringUTF8(tag) ?? "", 64));
    }

    /// <summary>v29 rule severities are critical/high/medium. Rules without one wait in Possible Threats (MEDIUM).</summary>
    public static string NormalizeSeverity(string? severity) => severity?.Trim().ToUpperInvariant() switch
    {
        "CRITICAL" => "CRITICAL",
        "HIGH" => "HIGH",
        "LOW" => "LOW",
        _ => "MEDIUM",
    };

    private sealed class RuleDetails
    {
        public string? Severity, Description, Technique;
        public List<string> Tags { get; } = [];
    }

    private static string Text(IntPtr pointer, nuint length) =>
        pointer == IntPtr.Zero ? "" : Encoding.UTF8.GetString((byte*)pointer, (int)Math.Min(length, 4096u));

    private static string Bound(string value, int max) => value.Length <= max ? value : value[..max];

    private static void Check(int result, string what)
    {
        if (result != YaraX.Success) throw new InvalidOperationException($"YARA-X could not {what}: {YaraX.LastError()}");
    }

    private static NativeUtf8 Utf8(string value) => new(value);

    private readonly struct NativeUtf8 : IDisposable
    {
        public byte* Pointer { get; }
        public NativeUtf8(string value) => Pointer = (byte*)Marshal.StringToCoTaskMemUTF8(value);
        public void Dispose() => Marshal.FreeCoTaskMem((IntPtr)Pointer);
    }

    public void Dispose()
    {
        if (_scanner != IntPtr.Zero) YaraX.yrx_scanner_destroy(_scanner);
        if (_rules != IntPtr.Zero) YaraX.yrx_rules_destroy(_rules);
        _scanner = _rules = IntPtr.Zero;
    }
}
