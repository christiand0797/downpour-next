using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Downpour.Service;

public sealed record SigmaLogSource(string? Category, string? Product, string? Service);

public sealed record SigmaRule(
    string Id,
    string Title,
    string Level,
    string? Description,
    IReadOnlyList<SigmaDetection> Detection,
    IReadOnlyList<string> Tags,
    IReadOnlyDictionary<string, object> Raw,
    string? Condition = null,
    bool IsSupported = true,
    string? UnsupportedReason = null,
    SigmaLogSource? LogSource = null);

public sealed record SigmaDetection(
    string Name,
    IReadOnlyDictionary<string, object> Condition);

public sealed record SigmaMatch(
    string RuleId,
    string RuleTitle,
    string Level,
    string MatchedText,
    int MatchIndex);

public sealed record SigmaLoadReport(
    int TotalRulesFound,
    int ValidRulesLoaded,
    int UnsupportedRulesCount,
    IReadOnlyDictionary<string, int> UnsupportedModifiers,
    IReadOnlyDictionary<string, int> UnsupportedConditions,
    IReadOnlyList<string> Issues);

public static class SigmaEngine
{
    private static readonly IDeserializer YamlDeserializer = new DeserializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    private static readonly Regex DocumentSplitRegex = new(@"(?m)^---\s*$", RegexOptions.Compiled);

    private static readonly HashSet<string> SupportedModifiers = new(StringComparer.OrdinalIgnoreCase)
    {
        "contains",
        "startswith",
        "beginswith",
        "endswith",
        "re",
        "regex",
        "windash",
        "all"
    };

    private static readonly ConcurrentDictionary<string, Regex?> RegexCache = new(StringComparer.Ordinal);

    public static SigmaLoadReport LastLoadReport { get; private set; } = new(0, 0, 0,
        new Dictionary<string, int>(), new Dictionary<string, int>(), Array.Empty<string>());

    public static string GetDefaultRulesDirectory()
    {
        var baseDir = AppContext.BaseDirectory;
        var dir = Path.Combine(baseDir, "sigma_rules");
        if (Directory.Exists(dir))
            return dir;

        var current = new DirectoryInfo(baseDir);
        while (current != null)
        {
            var candidate = Path.Combine(current.FullName, "src", "Downpour.Service", "sigma_rules");
            if (Directory.Exists(candidate))
                return candidate;
            current = current.Parent;
        }

        return dir;
    }

    public static List<SigmaRule> LoadBundledRules(string? directoryPath = null)
    {
        return LoadBundledRules(out _, directoryPath);
    }

    public static List<SigmaRule> LoadBundledRules(out SigmaLoadReport report, string? directoryPath = null)
    {
        var dir = directoryPath ?? GetDefaultRulesDirectory();
        if (!Directory.Exists(dir))
        {
            report = new SigmaLoadReport(0, 0, 0,
                new Dictionary<string, int>(), new Dictionary<string, int>(),
                new[] { $"Bundled rules directory not found: {dir}" });
            LastLoadReport = report;
            return [];
        }

        var files = Directory.GetFiles(dir, "*.yml", SearchOption.TopDirectoryOnly)
            .Concat(Directory.GetFiles(dir, "*.yaml", SearchOption.TopDirectoryOnly))
            .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return LoadFromYamlFiles(files, out report);
    }

    public static List<SigmaRule> LoadFromYaml(string yamlContent)
    {
        return LoadFromYaml(yamlContent, out _);
    }

    public static List<SigmaRule> LoadFromYaml(string yamlContent, out SigmaLoadReport report)
    {
        var collector = new LoadReportCollector();
        var rules = ParseYamlDocuments(yamlContent, collector);
        report = collector.ToReport();
        LastLoadReport = report;
        return rules;
    }

    public static List<SigmaRule> LoadFromYamlFiles(IEnumerable<string> filePaths)
    {
        return LoadFromYamlFiles(filePaths, out _);
    }

    public static List<SigmaRule> LoadFromYamlFiles(IEnumerable<string> filePaths, out SigmaLoadReport report)
    {
        var collector = new LoadReportCollector();
        var allRules = new List<SigmaRule>();

        foreach (var path in filePaths)
        {
            if (!File.Exists(path)) continue;
            try
            {
                var content = File.ReadAllText(path);
                var rules = ParseYamlDocuments(content, collector);
                allRules.AddRange(rules);
            }
            catch (Exception ex)
            {
                collector.AddIssue($"Error reading {Path.GetFileName(path)}: {ex.Message}");
            }
        }

        report = collector.ToReport();
        LastLoadReport = report;
        return allRules;
    }

    private static List<SigmaRule> ParseYamlDocuments(string yamlContent, LoadReportCollector collector)
    {
        if (string.IsNullOrWhiteSpace(yamlContent))
            return [];

        var rules = new List<SigmaRule>();
        var documents = DocumentSplitRegex.Split(yamlContent);

        foreach (var doc in documents)
        {
            if (string.IsNullOrWhiteSpace(doc)) continue;
            try
            {
                var raw = YamlDeserializer.Deserialize<Dictionary<string, object>>(doc);
                if (raw == null || raw.Count == 0) continue;

                collector.IncrementTotal();

                var id = GetString(raw, "id") ?? GetString(raw, "title") ?? Guid.NewGuid().ToString("N");
                var title = GetString(raw, "title") ?? id;
                var level = GetString(raw, "level") ?? "medium";
                var description = GetString(raw, "description");
                var tags = GetStringList(raw, "tags");
                var logSource = ParseLogSource(raw);

                var detectionObj = GetDict(raw, "detection");
                string? conditionStr = null;
                var detections = new List<SigmaDetection>();
                var isSupported = true;
                string? unsupportedReason = null;

                if (detectionObj != null)
                {
                    if (detectionObj.TryGetValue("condition", out var condVal) && condVal is string condStr)
                    {
                        conditionStr = condStr.Trim();
                    }

                    // Check for unsupported condition syntax/aggregations
                    if (!string.IsNullOrEmpty(conditionStr))
                    {
                        if (conditionStr.Contains('|') || conditionStr.Contains("count(", StringComparison.OrdinalIgnoreCase) ||
                            conditionStr.Contains("near", StringComparison.OrdinalIgnoreCase))
                        {
                            isSupported = false;
                            unsupportedReason = $"Unsupported condition syntax: {conditionStr}";
                            collector.RecordUnsupportedCondition(conditionStr, id, title);
                        }
                    }

                    foreach (var kvp in detectionObj)
                    {
                        if (kvp.Key.Equals("condition", StringComparison.OrdinalIgnoreCase) ||
                            kvp.Key.Equals("timeframe", StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        var condDict = BuildConditionDict(kvp.Value, out var unsupportedMod);
                        if (unsupportedMod != null)
                        {
                            isSupported = false;
                            unsupportedReason = $"Unsupported modifier: {unsupportedMod}";
                            collector.RecordUnsupportedModifier(unsupportedMod, id, title);
                        }

                        if (condDict.Count > 0)
                        {
                            detections.Add(new SigmaDetection(kvp.Key, condDict));
                        }
                    }
                }

                if (detections.Count == 0 && isSupported)
                {
                    isSupported = false;
                    unsupportedReason = "No detection criteria defined";
                    collector.AddIssue($"Rule '{id}' ('{title}'): no detection criteria defined");
                }

                var rule = new SigmaRule(
                    id,
                    title,
                    level,
                    description,
                    detections,
                    tags,
                    raw,
                    conditionStr,
                    isSupported,
                    unsupportedReason,
                    logSource);

                if (isSupported)
                {
                    collector.IncrementValid();
                }

                rules.Add(rule);
            }
            catch (Exception ex)
            {
                collector.AddIssue($"Error parsing YAML document: {ex.Message}");
            }
        }

        return rules;
    }

    private static SigmaLogSource? ParseLogSource(Dictionary<string, object> raw)
    {
        var lsDict = GetDict(raw, "logsource");
        if (lsDict == null) return null;

        var category = GetString(lsDict, "category");
        var product = GetString(lsDict, "product");
        var service = GetString(lsDict, "service");
        return new SigmaLogSource(category, product, service);
    }

    public static IReadOnlyList<SigmaMatch> Match(string? text, IEnumerable<SigmaRule>? rules)
    {
        if (string.IsNullOrEmpty(text) || rules == null)
            return Array.Empty<SigmaMatch>();

        var eventFields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["CommandLine"] = text,
            ["ScriptBlockText"] = text,
            ["message"] = text
        };

        // Extract executable token if present
        var firstToken = ExtractFirstToken(text);
        if (!string.IsNullOrEmpty(firstToken))
        {
            eventFields["Image"] = firstToken;
        }

        return MatchEvent(eventFields, rules);
    }

    public static IReadOnlyList<SigmaMatch> MatchProcess(
        string? image,
        string? cmdline,
        string? parentImage,
        string? user,
        IEnumerable<SigmaRule>? rules)
    {
        if (rules == null) return Array.Empty<SigmaMatch>();

        var eventFields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Image"] = image ?? string.Empty,
            ["CommandLine"] = cmdline ?? string.Empty,
            ["ParentImage"] = parentImage ?? string.Empty,
            ["User"] = user ?? string.Empty,
            ["message"] = $"{image ?? ""} {cmdline ?? ""}".Trim()
        };

        return MatchEvent(eventFields, rules, RuleFilter.ProcessOnly);
    }

    public static IReadOnlyList<SigmaMatch> MatchScriptBlock(string? scriptText, IEnumerable<SigmaRule>? rules)
    {
        if (string.IsNullOrEmpty(scriptText) || rules == null)
            return Array.Empty<SigmaMatch>();

        var eventFields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["ScriptBlockText"] = scriptText,
            ["CommandLine"] = scriptText,
            ["message"] = scriptText
        };

        return MatchEvent(eventFields, rules, RuleFilter.ScriptOnly);
    }

    private enum RuleFilter { None, ProcessOnly, ScriptOnly }

    public static IReadOnlyList<SigmaMatch> MatchEvent(
        IReadOnlyDictionary<string, string> eventFields,
        IEnumerable<SigmaRule>? rules)
    {
        return MatchEvent(eventFields, rules, RuleFilter.None);
    }

    private static IReadOnlyList<SigmaMatch> MatchEvent(
        IReadOnlyDictionary<string, string> eventFields,
        IEnumerable<SigmaRule>? rules,
        RuleFilter filter)
    {
        if (rules == null || eventFields.Count == 0)
            return Array.Empty<SigmaMatch>();

        var matches = new List<SigmaMatch>();

        foreach (var rule in rules)
        {
            if (!rule.IsSupported) continue;

            if (filter == RuleFilter.ProcessOnly && rule.LogSource != null)
            {
                var cat = rule.LogSource.Category;
                if (!string.IsNullOrEmpty(cat) && !cat.Equals("process_creation", StringComparison.OrdinalIgnoreCase))
                    continue;
            }
            else if (filter == RuleFilter.ScriptOnly && rule.LogSource != null)
            {
                var cat = rule.LogSource.Category;
                var svc = rule.LogSource.Service;
                var isScript = (cat != null && (cat.Equals("ps_script", StringComparison.OrdinalIgnoreCase) ||
                                                cat.Equals("script_block", StringComparison.OrdinalIgnoreCase) ||
                                                cat.Equals("ps_classicstart", StringComparison.OrdinalIgnoreCase))) ||
                               (svc != null && svc.Equals("powershell", StringComparison.OrdinalIgnoreCase));
                if (!isScript && !string.IsNullOrEmpty(cat))
                    continue;
            }

            var selectionResults = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            string? firstMatchedSnippet = null;
            var firstMatchIndex = -1;

            foreach (var detection in rule.Detection)
            {
                var (isMatch, snippet, index) = EvaluateSelection(detection.Condition, eventFields);
                selectionResults[detection.Name] = isMatch;

                if (isMatch && firstMatchedSnippet == null)
                {
                    firstMatchedSnippet = snippet;
                    firstMatchIndex = index;
                }
            }

            var ruleMatches = EvaluateRuleCondition(rule.Condition, selectionResults);
            if (ruleMatches)
            {
                matches.Add(new SigmaMatch(
                    rule.Id,
                    rule.Title,
                    rule.Level,
                    firstMatchedSnippet ?? rule.Title,
                    firstMatchIndex >= 0 ? firstMatchIndex : 0));
            }
        }

        return matches;
    }

    private static (bool IsMatch, string? Snippet, int Index) EvaluateSelection(
        IReadOnlyDictionary<string, object> conditionDict,
        IReadOnlyDictionary<string, string> eventFields)
    {
        if (conditionDict.Count == 0) return (false, null, -1);

        if (conditionDict.TryGetValue("_items", out var itemsObj) && itemsObj is List<Dictionary<string, object>> itemList)
        {
            foreach (var subMap in itemList)
            {
                var (isMatch, snippet, index) = EvaluateFieldMap(subMap, eventFields);
                if (isMatch)
                {
                    return (true, snippet, index);
                }
            }
            return (false, null, -1);
        }

        return EvaluateFieldMap(conditionDict, eventFields);
    }

    private static (bool IsMatch, string? Snippet, int Index) EvaluateFieldMap(
        IReadOnlyDictionary<string, object> fieldMap,
        IReadOnlyDictionary<string, string> eventFields)
    {
        string? firstSnippet = null;
        var firstIndex = -1;

        foreach (var (rawKey, expectedValue) in fieldMap)
        {
            if (rawKey.Equals("_items", StringComparison.OrdinalIgnoreCase)) continue;

            var (fieldName, modifiers) = ParseFieldAndModifiers(rawKey);

            string? actualValue = null;
            if (!string.IsNullOrEmpty(fieldName))
            {
                foreach (var (ek, ev) in eventFields)
                {
                    if (string.Equals(ek, fieldName, StringComparison.OrdinalIgnoreCase))
                    {
                        actualValue = ev;
                        break;
                    }
                }

                // Fallback for image checks against full command line / text
                if (string.IsNullOrEmpty(actualValue) && fieldName.Equals("Image", StringComparison.OrdinalIgnoreCase))
                {
                    if (eventFields.TryGetValue("CommandLine", out var cl) || eventFields.TryGetValue("message", out cl))
                    {
                        actualValue = ExtractFirstToken(cl);
                    }
                }
            }
            else
            {
                // Field-less operator: evaluate across all available fields
                eventFields.TryGetValue("message", out actualValue);
                if (string.IsNullOrEmpty(actualValue))
                    eventFields.TryGetValue("CommandLine", out actualValue);
                if (string.IsNullOrEmpty(actualValue))
                    eventFields.TryGetValue("ScriptBlockText", out actualValue);
            }

            var (fieldMatches, snippet, index) = MatchFieldValues(actualValue ?? string.Empty, expectedValue, modifiers);
            if (!fieldMatches)
            {
                return (false, null, -1);
            }

            if (firstSnippet == null && snippet != null)
            {
                firstSnippet = snippet;
                firstIndex = index;
            }
        }

        return (true, firstSnippet, firstIndex);
    }

    private static (bool Matches, string? Snippet, int Index) MatchFieldValues(
        string actual,
        object expectedValue,
        List<string> modifiers)
    {
        var requireAll = modifiers.Contains("all", StringComparer.OrdinalIgnoreCase);
        var expectedStrings = ExtractExpectedStrings(expectedValue);

        if (expectedStrings.Count == 0)
        {
            return (false, null, -1);
        }

        string? firstSnippet = null;
        var firstIndex = -1;
        var matchCount = 0;

        foreach (var expected in expectedStrings)
        {
            var (singleMatch, snippet, index) = MatchSingleValue(actual, expected, modifiers);
            if (singleMatch)
            {
                matchCount++;
                if (firstSnippet == null)
                {
                    firstSnippet = snippet;
                    firstIndex = index;
                }
                if (!requireAll)
                {
                    return (true, firstSnippet, firstIndex);
                }
            }
            else if (requireAll)
            {
                return (false, null, -1);
            }
        }

        return requireAll ? (matchCount == expectedStrings.Count, firstSnippet, firstIndex) : (false, null, -1);
    }

    private static (bool Match, string? Snippet, int Index) MatchSingleValue(
        string actual,
        string expected,
        List<string> modifiers)
    {
        if (string.IsNullOrEmpty(actual)) return (false, null, -1);

        var hasWindash = modifiers.Contains("windash", StringComparer.OrdinalIgnoreCase);
        var hasStartsWith = modifiers.Contains("startswith", StringComparer.OrdinalIgnoreCase) ||
                            modifiers.Contains("beginswith", StringComparer.OrdinalIgnoreCase);
        var hasEndsWith = modifiers.Contains("endswith", StringComparer.OrdinalIgnoreCase);
        var hasRegex = modifiers.Contains("re", StringComparer.OrdinalIgnoreCase) ||
                       modifiers.Contains("regex", StringComparer.OrdinalIgnoreCase);
        var hasContains = modifiers.Contains("contains", StringComparer.OrdinalIgnoreCase) ||
                          (!hasWindash && !hasStartsWith && !hasEndsWith && !hasRegex && modifiers.Count > 0);

        if (hasWindash)
        {
            var idx = 0;
            while ((idx = actual.IndexOf(expected, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
            {
                var isBoundary = idx == 0 ||
                    actual[idx - 1] == '-' ||
                    actual[idx - 1] == '/' ||
                    char.IsWhiteSpace(actual[idx - 1]);

                if (isBoundary)
                {
                    return (true, actual.Substring(idx, expected.Length), idx);
                }
                idx += expected.Length;
            }
            return (false, null, -1);
        }

        if (hasRegex)
        {
            try
            {
                var regex = RegexCache.GetOrAdd(expected, p => new Regex(p, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)));
                if (regex != null)
                {
                    var m = regex.Match(actual);
                    if (m.Success)
                    {
                        return (true, m.Value, m.Index);
                    }
                }
            }
            catch { }
            return (false, null, -1);
        }

        if (hasStartsWith)
        {
            if (actual.StartsWith(expected, StringComparison.OrdinalIgnoreCase))
            {
                return (true, expected, 0);
            }
            return (false, null, -1);
        }

        if (hasEndsWith)
        {
            if (actual.EndsWith(expected, StringComparison.OrdinalIgnoreCase))
            {
                var idx = actual.Length - expected.Length;
                return (true, expected, idx);
            }
            return (false, null, -1);
        }

        if (hasContains)
        {
            var idx = actual.IndexOf(expected, StringComparison.OrdinalIgnoreCase);
            if (idx >= 0)
            {
                return (true, actual.Substring(idx, expected.Length), idx);
            }
            return (false, null, -1);
        }

        // Default: exact case-insensitive match
        if (string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
        {
            return (true, actual, 0);
        }

        return (false, null, -1);
    }

    private static List<string> ExtractExpectedStrings(object val)
    {
        var list = new List<string>();
        if (val is string s)
        {
            list.Add(s);
        }
        else if (val is IEnumerable<object> objList)
        {
            foreach (var item in objList)
            {
                if (item != null) list.Add(item.ToString()!);
            }
        }
        else if (val != null)
        {
            list.Add(val.ToString()!);
        }
        return list;
    }

    private static (string FieldName, List<string> Modifiers) ParseFieldAndModifiers(string rawKey)
    {
        var cleanKey = rawKey.Split('#')[0];
        var parts = cleanKey.Split('|', StringSplitOptions.TrimEntries);

        if (SupportedModifiers.Contains(parts[0]))
        {
            return (string.Empty, parts.Select(p => p.ToLowerInvariant()).ToList());
        }

        var fieldName = parts[0];
        var modifiers = new List<string>();
        for (var i = 1; i < parts.Length; i++)
        {
            modifiers.Add(parts[i].ToLowerInvariant());
        }

        return (fieldName, modifiers);
    }

    private static bool EvaluateRuleCondition(string? condition, Dictionary<string, bool> selections)
    {
        if (string.IsNullOrWhiteSpace(condition))
        {
            // Default: 1 of them (any selection matches)
            return selections.Values.Any(v => v);
        }

        try
        {
            var tokens = TokenizeCondition(condition);
            var parser = new ConditionParser(tokens, selections);
            return parser.Parse();
        }
        catch
        {
            // Fallback on parser failure: 1 of them
            return selections.Values.Any(v => v);
        }
    }

    private static List<string> TokenizeCondition(string condition)
    {
        var tokens = new List<string>();
        var i = 0;
        var s = condition.Trim();

        while (i < s.Length)
        {
            if (char.IsWhiteSpace(s[i]))
            {
                i++;
                continue;
            }

            if (s[i] == '(' || s[i] == ')')
            {
                tokens.Add(s[i].ToString());
                i++;
                continue;
            }

            // Check for "N of <pattern>" or "all of <pattern>"
            var remaining = s[i..];
            var ofMatch = Regex.Match(remaining, @"^(\d+|all)\s+of\s+([a-zA-Z0-9_*]+)", RegexOptions.IgnoreCase);
            if (ofMatch.Success)
            {
                tokens.Add(ofMatch.Value.ToLowerInvariant());
                i += ofMatch.Length;
                continue;
            }

            if (remaining.StartsWith("and", StringComparison.OrdinalIgnoreCase) &&
                (remaining.Length == 3 || !char.IsLetterOrDigit(remaining[3])))
            {
                tokens.Add("and");
                i += 3;
                continue;
            }

            if (remaining.StartsWith("or", StringComparison.OrdinalIgnoreCase) &&
                (remaining.Length == 2 || !char.IsLetterOrDigit(remaining[2])))
            {
                tokens.Add("or");
                i += 2;
                continue;
            }

            if (remaining.StartsWith("not", StringComparison.OrdinalIgnoreCase) &&
                (remaining.Length == 3 || !char.IsLetterOrDigit(remaining[3])))
            {
                tokens.Add("not");
                i += 3;
                continue;
            }

            // Identifier
            var start = i;
            while (i < s.Length && (char.IsLetterOrDigit(s[i]) || s[i] == '_' || s[i] == '*'))
            {
                i++;
            }

            if (i > start)
            {
                tokens.Add(s[start..i]);
            }
            else
            {
                // Single special character
                tokens.Add(s[i].ToString());
                i++;
            }
        }

        return tokens;
    }

    private sealed class ConditionParser
    {
        private readonly List<string> _tokens;
        private readonly Dictionary<string, bool> _selections;
        private int _pos;

        public ConditionParser(List<string> tokens, Dictionary<string, bool> selections)
        {
            _tokens = tokens;
            _selections = selections;
            _pos = 0;
        }

        private string? Peek() => _pos < _tokens.Count ? _tokens[_pos] : null;

        private string? Next() => _pos < _tokens.Count ? _tokens[_pos++] : null;

        public bool Parse() => Expr();

        private bool Expr()
        {
            var val = Term();
            while (string.Equals(Peek(), "or", StringComparison.OrdinalIgnoreCase))
            {
                Next();
                var rhs = Term();
                val = val || rhs;
            }
            return val;
        }

        private bool Term()
        {
            var val = Factor();
            while (string.Equals(Peek(), "and", StringComparison.OrdinalIgnoreCase))
            {
                Next();
                var rhs = Factor();
                val = val && rhs;
            }
            return val;
        }

        private bool Factor()
        {
            var tok = Peek();
            if (tok == null) return false;

            if (tok == "(")
            {
                Next();
                var val = Expr();
                if (Peek() == ")") Next();
                return val;
            }

            if (string.Equals(tok, "not", StringComparison.OrdinalIgnoreCase))
            {
                Next();
                return !Factor();
            }

            Next();

            // Evaluate "N of pattern" clause
            var ofMatch = Regex.Match(tok, @"^(\d+|all)\s+of\s+([a-zA-Z0-9_*]+)$", RegexOptions.IgnoreCase);
            if (ofMatch.Success)
            {
                var quantStr = ofMatch.Groups[1].Value.ToLowerInvariant();
                var target = ofMatch.Groups[2].Value.ToLowerInvariant();

                List<string> matchingKeys;
                if (target == "them")
                {
                    matchingKeys = _selections.Keys.ToList();
                }
                else if (target.EndsWith('*'))
                {
                    var prefix = target.TrimEnd('*');
                    matchingKeys = _selections.Keys
                        .Where(k => k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        .ToList();
                }
                else
                {
                    matchingKeys = _selections.Keys
                        .Where(k => string.Equals(k, target, StringComparison.OrdinalIgnoreCase))
                        .ToList();
                }

                if (matchingKeys.Count == 0) return false;

                var hits = matchingKeys.Count(k => _selections.TryGetValue(k, out var m) && m);
                if (quantStr == "all")
                {
                    return hits == matchingKeys.Count;
                }
                if (int.TryParse(quantStr, out var needed))
                {
                    return hits >= needed;
                }
                return false;
            }

            // Identifier
            foreach (var (k, v) in _selections)
            {
                if (string.Equals(k, tok, StringComparison.OrdinalIgnoreCase))
                {
                    return v;
                }
            }

            return false;
        }
    }

    private static string? ExtractFirstToken(string text)
    {
        var trimmed = text.Trim();
        if (string.IsNullOrEmpty(trimmed)) return null;

        if (trimmed.StartsWith('\"'))
        {
            var close = trimmed.IndexOf('\"', 1);
            if (close > 1) return trimmed[1..close];
        }

        var space = trimmed.IndexOfAny(new[] { ' ', '\t' });
        return space > 0 ? trimmed[..space] : trimmed;
    }

    private static Dictionary<string, object> BuildConditionDict(object value, out string? unsupportedModifier)
    {
        unsupportedModifier = null;
        var combined = new Dictionary<string, object>();

        if (value is Dictionary<string, object> dict)
        {
            foreach (var (k, v) in dict)
            {
                ValidateModifier(k, ref unsupportedModifier);
                combined[k] = v;
            }
        }
        else if (value is Dictionary<object, object> objDict)
        {
            foreach (var (k, v) in objDict)
            {
                var keyStr = k.ToString()!;
                ValidateModifier(keyStr, ref unsupportedModifier);
                combined[keyStr] = v;
            }
        }
        else if (value is List<object> list)
        {
            // List of dicts (OR condition inside selection)
            var itemList = new List<Dictionary<string, object>>();
            for (var i = 0; i < list.Count; i++)
            {
                var item = list[i];
                if (item is Dictionary<string, object> itemDict)
                {
                    var subMap = new Dictionary<string, object>();
                    foreach (var (k, v) in itemDict)
                    {
                        ValidateModifier(k, ref unsupportedModifier);
                        subMap[k] = v;
                        combined[$"{k}#{i}"] = v;
                    }
                    itemList.Add(subMap);
                }
                else if (item is Dictionary<object, object> itemObjDict)
                {
                    var subMap = new Dictionary<string, object>();
                    foreach (var (k, v) in itemObjDict)
                    {
                        var keyStr = k.ToString()!;
                        ValidateModifier(keyStr, ref unsupportedModifier);
                        subMap[keyStr] = v;
                        combined[$"{keyStr}#{i}"] = v;
                    }
                    itemList.Add(subMap);
                }
                else if (item is string strItem)
                {
                    var subMap = new Dictionary<string, object> { ["contains"] = strItem };
                    itemList.Add(subMap);
                    combined[$"contains#{i}"] = strItem;
                }
            }
            if (itemList.Count > 0)
            {
                combined["_items"] = itemList;
            }
        }

        return combined;
    }

    private static void ValidateModifier(string rawKey, ref string? unsupportedModifier)
    {
        var cleanKey = rawKey.Split('#')[0];
        var parts = cleanKey.Split('|', StringSplitOptions.TrimEntries);
        if (parts.Length > 0)
        {
            var startIndex = SupportedModifiers.Contains(parts[0]) ? 0 : 1;
            for (var i = startIndex; i < parts.Length; i++)
            {
                var mod = parts[i].ToLowerInvariant();
                if (!SupportedModifiers.Contains(mod))
                {
                    unsupportedModifier ??= mod;
                }
            }
        }
    }

    private static string? GetString(Dictionary<string, object> dict, string key)
    {
        if (dict.TryGetValue(key, out var val) && val is string s)
            return s;
        return null;
    }

    private static List<string> GetStringList(Dictionary<string, object> dict, string key)
    {
        if (dict.TryGetValue(key, out var val))
        {
            if (val is List<object> list)
            {
                return list.Select(o => o?.ToString()).Where(s => s != null).Cast<string>().ToList();
            }
            if (val is IEnumerable<object> enumList)
            {
                return enumList.Select(o => o?.ToString()).Where(s => s != null).Cast<string>().ToList();
            }
        }
        return [];
    }

    private static Dictionary<string, object>? GetDict(Dictionary<string, object> dict, string key)
    {
        if (dict.TryGetValue(key, out var val))
        {
            if (val is Dictionary<string, object> d) return d;
            if (val is Dictionary<object, object> objDict)
            {
                return objDict.ToDictionary(kvp => kvp.Key.ToString()!, kvp => kvp.Value);
            }
        }
        return null;
    }

    public static List<SigmaRule> GetBuiltinRules()
    {
        const string yaml = """
            ---
            id: "sigma-powershell-encoded-command"
            title: "PowerShell Encoded Command"
            level: "high"
            description: "Detects PowerShell encoded commands in script blocks"
            tags: ["attack.t1059.001", "attack.t1027"]
            detection:
              encoded_command:
                contains|windash: "-encodedcommand"
              condition: encoded_command

            ---
            id: "sigma-powershell-bypass"
            title: "PowerShell Execution Policy Bypass"
            level: "high"
            description: "Detects PowerShell execution policy bypass attempts"
            tags: ["attack.t1059.001", "attack.t1562.001"]
            detection:
              bypass:
                contains|windash: "-executionpolicy"
                contains: "bypass"
              condition: bypass

            ---
            id: "sigma-powershell-download-cradle"
            title: "PowerShell Download Cradle"
            level: "high"
            description: "Detects PowerShell download cradles (IEX, Invoke-Expression, etc.)"
            tags: ["attack.t1059.001", "attack.t1105"]
            detection:
              download_cradle:
                - contains: "iex"
                - contains: "invoke-expression"
                - contains: "downloadstring"
                - contains: "downloadfile"
                - contains: "webclient"
                - contains: "net.webclient"
              condition: download_cradle

            ---
            id: "sigma-powershell-obfuscation"
            title: "PowerShell Obfuscation Techniques"
            level: "medium"
            description: "Detects common PowerShell obfuscation patterns"
            tags: ["attack.t1059.001", "attack.t1027"]
            detection:
              obfuscation:
                - contains: ".replace("
                - contains: "-join"
                - contains: "[char]"
                - contains: "[string]"
                - contains: "frombase64string"
              condition: obfuscation

            ---
            id: "sigma-powershell-amsi-bypass"
            title: "PowerShell AMSI Bypass"
            level: "critical"
            description: "Detects known AMSI bypass techniques"
            tags: ["attack.t1562.001", "attack.t1059.001"]
            detection:
              amsi_bypass:
                - contains: "amsiinitfailed"
                - contains: "amsicontext"
                - contains: "amsiscanbuffer"
                - contains: "reflection.assembly"
                - contains: "getfield"
                - contains: "setvalue"
              condition: amsi_bypass

            ---
            id: "sigma-powershell-wmi"
            title: "PowerShell WMI/Lateral Movement"
            level: "high"
            description: "Detects PowerShell WMI usage for lateral movement"
            tags: ["attack.t1047", "attack.t1021.004"]
            detection:
              wmi:
                - contains: "get-wmiobject"
                - contains: "invoke-wmimethod"
                - contains: "\\root\\cimv2"
                - contains: "win32_process"
              condition: wmi
            """;

        return LoadFromYaml(yaml);
    }

    private sealed class LoadReportCollector
    {
        private int _total;
        private int _valid;
        private readonly ConcurrentDictionary<string, int> _unsupportedModifiers = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, int> _unsupportedConditions = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<string> _issues = new();
        private readonly object _lock = new();

        public void IncrementTotal() => Interlocked.Increment(ref _total);

        public void IncrementValid() => Interlocked.Increment(ref _valid);

        public void RecordUnsupportedModifier(string modifier, string ruleId, string title)
        {
            _unsupportedModifiers.AddOrUpdate(modifier, 1, (_, count) => count + 1);
            lock (_lock)
            {
                _issues.Add($"Rule '{ruleId}' ('{title}'): unsupported modifier '{modifier}'");
            }
        }

        public void RecordUnsupportedCondition(string condition, string ruleId, string title)
        {
            _unsupportedConditions.AddOrUpdate(condition, 1, (_, count) => count + 1);
            lock (_lock)
            {
                _issues.Add($"Rule '{ruleId}' ('{title}'): unsupported condition '{condition}'");
            }
        }

        public void AddIssue(string issue)
        {
            lock (_lock)
            {
                _issues.Add(issue);
            }
        }

        public SigmaLoadReport ToReport()
        {
            var unsupportedCount = _total - _valid;
            return new SigmaLoadReport(
                _total,
                _valid,
                unsupportedCount > 0 ? unsupportedCount : 0,
                new Dictionary<string, int>(_unsupportedModifiers),
                new Dictionary<string, int>(_unsupportedConditions),
                _issues.ToArray());
        }
    }
}