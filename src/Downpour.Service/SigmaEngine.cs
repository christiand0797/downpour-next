using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Downpour.Contracts;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Downpour.Service;

public sealed record SigmaRule(
    string Id,
    string Title,
    string Level,
    string? Description,
    IReadOnlyList<SigmaDetection> Detection,
    IReadOnlyList<string> Tags,
    IReadOnlyDictionary<string, object> Raw);

public sealed record SigmaDetection(
    string Name,
    IReadOnlyDictionary<string, object> Condition);

public sealed record SigmaMatch(
    string RuleId,
    string RuleTitle,
    string Level,
    string MatchedText,
    int MatchIndex);

public static class SigmaEngine
{
    private static readonly IDeserializer YamlDeserializer = new DeserializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    private static readonly Regex RegexSpecialChars = new(@"([\^\$\.\|\?\*\+\(\)\[\]\{\}\\])", RegexOptions.Compiled);

    private static readonly ConcurrentDictionary<string, List<SigmaRule>> RuleCache = new();

    public static List<SigmaRule> LoadFromYaml(string yamlContent)
    {
        if (string.IsNullOrWhiteSpace(yamlContent))
            return [];

        var rules = new List<SigmaRule>();
        var documents = yamlContent.Split(new[] { "\n---\n", "\n---\r\n" }, StringSplitOptions.RemoveEmptyEntries);

        foreach (var doc in documents)
        {
            if (string.IsNullOrWhiteSpace(doc)) continue;
            try
            {
                var raw = YamlDeserializer.Deserialize<Dictionary<string, object>>(doc);
                if (raw == null) continue;

                var id = GetString(raw, "id") ?? GetString(raw, "title") ?? Guid.NewGuid().ToString("N");
                var title = GetString(raw, "title") ?? id;
                var level = GetString(raw, "level") ?? "medium";
                var description = GetString(raw, "description");
                var tags = GetStringList(raw, "tags");
                var detection = ParseDetection(raw);

                rules.Add(new SigmaRule(id, title, level, description, detection, tags, raw));
            }
            catch { }
        }

        return rules;
    }

    public static List<SigmaRule> LoadFromYamlFiles(IEnumerable<string> filePaths)
    {
        var allRules = new List<SigmaRule>();
        foreach (var path in filePaths)
        {
            if (!File.Exists(path)) continue;
            try
            {
                var content = File.ReadAllText(path);
                allRules.AddRange(LoadFromYaml(content));
            }
            catch { }
        }
        return allRules;
    }

    public static IReadOnlyList<SigmaMatch> Match(string? text, IEnumerable<SigmaRule>? rules)
    {
        if (string.IsNullOrEmpty(text) || rules == null)
            return Array.Empty<SigmaMatch>();

        var matches = new List<SigmaMatch>();
        foreach (var rule in rules)
        {
            foreach (var detection in rule.Detection)
            {
                var condition = detection.Condition;
                if (condition == null) continue;

                // Pass the entire condition dictionary for this detection to EvaluateCondition
                var matchResults = EvaluateCondition(text, detection.Name, condition);
                if (matchResults.Count > 0)
                {
                    foreach (var match in matchResults)
                    {
                        matches.Add(new SigmaMatch(
                            rule.Id,
                            rule.Title,
                            rule.Level,
                            match.MatchedText,
                            match.MatchIndex));
                    }
                }
            }
        }
        return matches;
    }

    private static List<SigmaMatch> EvaluateCondition(string text, string field, object value)
    {
        var results = new List<SigmaMatch>();

        if (value is string strValue)
        {
            results.AddRange(MatchString(text, strValue));
        }
        else if (value is Dictionary<string, object> dictValue)
        {
            if (dictValue.TryGetValue("contains", out var containsObj))
            {
                if (containsObj is string containsStr)
                {
                    results.AddRange(MatchString(text, containsStr));
                }
                else if (containsObj is List<object> containsList)
                {
                    foreach (var item in containsList.OfType<string>())
                    {
                        results.AddRange(MatchString(text, item));
                    }
                }
                else if (containsObj is List<string> containsStrList)
                {
                    foreach (var item in containsStrList)
                    {
                        results.AddRange(MatchString(text, item));
                    }
                }
            }
            else if (dictValue.TryGetValue("contains|windash", out var windashObj))
            {
                // Sigma "contains|windash" - pattern must be at word boundary preceded by dash
                if (windashObj is string windashStr)
                {
                    results.AddRange(MatchWindash(text, windashStr));
                }
                else if (windashObj is List<object> windashList)
                {
                    foreach (var item in windashList.OfType<string>())
                    {
                        results.AddRange(MatchWindash(text, item));
                    }
                }
                else if (windashObj is List<string> windashStrList)
                {
                    foreach (var item in windashStrList)
                    {
                        results.AddRange(MatchWindash(text, item));
                    }
                }
            }
            else if (dictValue.TryGetValue("startswith", out var startsObj))
            {
                if (startsObj is string startsStr)
                {
                    results.AddRange(MatchStartsWith(text, startsStr));
                }
                else if (startsObj is List<object> startsList)
                {
                    foreach (var item in startsList.OfType<string>())
                    {
                        results.AddRange(MatchStartsWith(text, item));
                    }
                }
                else if (startsObj is List<string> startsStrList)
                {
                    foreach (var item in startsStrList)
                    {
                        results.AddRange(MatchStartsWith(text, item));
                    }
                }
            }
            else if (dictValue.TryGetValue("endswith", out var endsObj))
            {
                if (endsObj is string endsStr)
                {
                    results.AddRange(MatchEndsWith(text, endsStr));
                }
                else if (endsObj is List<object> endsList)
                {
                    foreach (var item in endsList.OfType<string>())
                    {
                        results.AddRange(MatchEndsWith(text, item));
                    }
                }
                else if (endsObj is List<string> endsStrList)
                {
                    foreach (var item in endsStrList)
                    {
                        results.AddRange(MatchEndsWith(text, item));
                    }
                }
            }
            else if (dictValue.TryGetValue("re", out var reObj))
            {
                if (reObj is string reStr)
                {
                    results.AddRange(MatchRegex(text, reStr));
                }
                else if (reObj is List<object> reList)
                {
                    foreach (var item in reList.OfType<string>())
                    {
                        results.AddRange(MatchRegex(text, item));
                    }
                }
                else if (reObj is List<string> reStrList)
                {
                    foreach (var item in reStrList)
                    {
                        results.AddRange(MatchRegex(text, item));
                    }
                }
            }
            else if (dictValue.TryGetValue("all", out var allObj))
            {
                if (allObj is List<object> allList)
                {
                    var allMatches = new List<SigmaMatch>();
                    var allPass = true;
                    foreach (var item in allList)
                    {
                        var subMatches = EvaluateCondition(text, field, item);
                        if (subMatches.Count == 0)
                        {
                            allPass = false;
                            break;
                        }
                        allMatches.AddRange(subMatches);
                    }
                    if (allPass) results.AddRange(allMatches);
                }
            }
            else if (dictValue.TryGetValue("any", out var anyObj))
            {
                if (anyObj is List<object> anyList)
                {
                    foreach (var item in anyList)
                    {
                        results.AddRange(EvaluateCondition(text, field, item));
                    }
                }
            }
        }
        else if (value is List<object> listValue)
        {
            foreach (var item in listValue)
            {
                results.AddRange(EvaluateCondition(text, field, item));
            }
        }

        return results;
    }

    private static List<SigmaMatch> MatchString(string text, string pattern)
    {
        var results = new List<SigmaMatch>();
        var index = 0;
        var comparison = StringComparison.OrdinalIgnoreCase;
        while ((index = text.IndexOf(pattern, index, comparison)) >= 0)
        {
            var matched = text.Substring(index, pattern.Length);
            results.Add(new SigmaMatch("", "", "", matched, index));
            index += pattern.Length;
        }
        return results;
    }

    private static List<SigmaMatch> MatchStartsWith(string text, string pattern)
    {
        var results = new List<SigmaMatch>();
        if (text.StartsWith(pattern, StringComparison.OrdinalIgnoreCase))
        {
            results.Add(new SigmaMatch("", "", "", pattern, 0));
        }
        return results;
    }

    private static List<SigmaMatch> MatchEndsWith(string text, string pattern)
    {
        var results = new List<SigmaMatch>();
        if (text.EndsWith(pattern, StringComparison.OrdinalIgnoreCase))
        {
            var index = text.Length - pattern.Length;
            results.Add(new SigmaMatch("", "", "", pattern, index));
        }
        return results;
    }

    private static List<SigmaMatch> MatchWindash(string text, string pattern)
    {
        var results = new List<SigmaMatch>();
        var index = 0;
        var comparison = StringComparison.OrdinalIgnoreCase;
        while ((index = text.IndexOf(pattern, index, comparison)) >= 0)
        {
            // Check if pattern is at word boundary preceded by dash or start of string
            var isWordBoundary = index == 0 || 
                (index > 0 && (text[index - 1] == '-' || text[index - 1] == ' ' || text[index - 1] == '\t'));
            if (isWordBoundary)
            {
                var matched = text.Substring(index, pattern.Length);
                results.Add(new SigmaMatch("", "", "", matched, index));
            }
            index += pattern.Length;
        }
        return results;
    }

    private static List<SigmaMatch> MatchRegex(string text, string pattern)
    {
        var results = new List<SigmaMatch>();
        try
        {
            var regex = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
            foreach (Match match in regex.Matches(text))
            {
                if (match.Success)
                {
                    results.Add(new SigmaMatch("", "", "", match.Value, match.Index));
                }
            }
        }
        catch { }
        return results;
    }

    private static string? GetString(Dictionary<string, object> dict, string key)
    {
        if (dict.TryGetValue(key, out var value) && value is string s)
            return s;
        return null;
    }

    private static List<string> GetStringList(Dictionary<string, object> dict, string key)
    {
        if (dict.TryGetValue(key, out var value))
        {
            if (value is List<object> list)
            {
                return list.OfType<string>().ToList();
            }
            if (value is IEnumerable<object> enumList)
            {
                return enumList.OfType<string>().ToList();
            }
        }
        return [];
    }

    private static Dictionary<string, object>? GetDict(Dictionary<string, object> dict, string key)
    {
        if (dict.TryGetValue(key, out var value) && value is Dictionary<object, object> objDict)
        {
            return objDict.ToDictionary(kvp => kvp.Key.ToString()!, kvp => kvp.Value);
        }
        if (dict.TryGetValue(key, out var value2) && value2 is Dictionary<string, object> strDict)
        {
            return strDict;
        }
        return null;
    }

    private static List<SigmaDetection> ParseDetection(Dictionary<string, object> raw)
    {
        var detections = new List<SigmaDetection>();
        if (raw.TryGetValue("detection", out var detectionObj))
        {
            if (detectionObj is Dictionary<string, object> detectionDict)
            {
                foreach (var kvp in detectionDict)
                {
                    if (kvp.Key == "condition") continue;
                    
                    var conditionDict = BuildConditionDict(kvp.Value);
                    if (conditionDict.Count > 0)
                    {
                        detections.Add(new SigmaDetection(kvp.Key, conditionDict));
                    }
                }
            }
            else if (detectionObj is Dictionary<object, object> objDetectionDict)
            {
                foreach (var kvp in objDetectionDict)
                {
                    if (kvp.Key.ToString() == "condition") continue;
                    
                    var conditionDict = BuildConditionDict(kvp.Value);
                    if (conditionDict.Count > 0)
                    {
                        detections.Add(new SigmaDetection(kvp.Key.ToString()!, conditionDict));
                    }
                }
            }
        }
        return detections;
    }

    private static Dictionary<string, object> BuildConditionDict(object value)
    {
        var combinedDict = new Dictionary<string, object>();
        
        if (value is List<object> list)
        {
            // Handle multiple conditions with same operator (e.g., multiple "contains")
            var containsList = new List<string>();
            var startsWithList = new List<string>();
            var endsWithList = new List<string>();
            var regexList = new List<string>();
            
            foreach (var item in list)
            {
                if (item is Dictionary<string, object> itemDict)
                {
                    foreach (var itemKvp in itemDict)
                    {
                        if (itemKvp.Value is string strVal)
                        {
                            switch (itemKvp.Key.ToLowerInvariant())
                            {
                                case "contains":
                                    containsList.Add(strVal);
                                    break;
                                case "startswith":
                                    startsWithList.Add(strVal);
                                    break;
                                case "endswith":
                                    endsWithList.Add(strVal);
                                    break;
                                case "re":
                                    regexList.Add(strVal);
                                    break;
                            }
                        }
                    }
                }
                else if (item is Dictionary<object, object> objItemDict)
                {
                    foreach (var itemKvp in objItemDict)
                    {
                        if (itemKvp.Value is string strVal)
                        {
                            switch (itemKvp.Key.ToString()!.ToLowerInvariant())
                            {
                                case "contains":
                                    containsList.Add(strVal);
                                    break;
                                case "startswith":
                                    startsWithList.Add(strVal);
                                    break;
                                case "endswith":
                                    endsWithList.Add(strVal);
                                    break;
                                case "re":
                                    regexList.Add(strVal);
                                    break;
                            }
                        }
                    }
                }
            }
            
            if (containsList.Count > 0) combinedDict["contains"] = containsList;
            if (startsWithList.Count > 0) combinedDict["startswith"] = startsWithList;
            if (endsWithList.Count > 0) combinedDict["endswith"] = endsWithList;
            if (regexList.Count > 0) combinedDict["re"] = regexList;
        }
        else if (value is Dictionary<string, object> conditionDict)
        {
            foreach (var itemKvp in conditionDict)
            {
                combinedDict[itemKvp.Key] = itemKvp.Value;
            }
        }
        else if (value is Dictionary<object, object> objDict)
        {
            foreach (var itemKvp in objDict)
            {
                combinedDict[itemKvp.Key.ToString()!] = itemKvp.Value;
            }
        }
            
        return combinedDict;
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
                contains: "iex"
                contains: "invoke-expression"
                contains: "downloadstring"
                contains: "downloadfile"
                contains: "webclient"
                contains: "net.webclient"
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
}