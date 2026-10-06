using System.Text.RegularExpressions;

namespace Downpour.Core;

public sealed record ServiceRisk(string Level, IReadOnlyList<string> Indicators);

/// <summary>
/// Service risk rules from v29 downpour_remote_access.py SmartServicesScanner (remote-access service names and
/// vectors), plus the checks v29's UI claimed but did not implement: unquoted image paths with spaces (T1574.009)
/// and service binaries in locations standard users can write to (T1574.010). Unsigned-binary detection is not done.
/// </summary>
public static partial class ServiceRiskAnalyzer
{
    public const string Clean = "Clean";
    public static readonly IReadOnlyList<string> Levels = ["Critical", "High", "Medium", "Low", Clean];

    /// <summary>SmartServicesScanner._SUSPICIOUS_NAMES.</summary>
    public static readonly IReadOnlySet<string> SuspiciousNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "remoteregistry", "termservice", "tlntsvr", "snmptrap", "w3svc", "msftpsvc", "simptcp", "xblgamesave" };

    /// <summary>REMOTE_ACCESS_VECTORS keys and risk (downpour_remote_access.py lines 35-47). v29 matched them as substrings.</summary>
    public static readonly IReadOnlyList<(string Vector, string Level)> RemoteAccessVectors =
    [
        ("rdp", "High"), ("vnc", "Medium"), ("teamviewer", "Medium"), ("anydesk", "Medium"), ("ssh", "Medium"),
        ("telnet", "High"), ("reverse_tcp", "Critical"), ("cobalt_strike", "Critical"), ("metasploit", "Critical"),
        ("ngrok", "High"), ("winrm", "High"),
    ];

    public static ServiceRisk Analyze(string serviceName, string imagePath, string startupType, Func<string, bool> isWritableByStandardUsers)
    {
        var indicators = new List<string>();
        var level = Clean;
        var disabled = startupType == "Disabled";

        // v29 rules. A disabled built-in such as RemoteRegistry is reported but rated Low, because v29 rated it High
        // on every Windows Pro machine regardless of whether it could run.
        if (SuspiciousNames.Contains(serviceName))
        {
            indicators.Add(startupType == "Automatic" ? "Auto-start remote-access service" : "Known remote-access service");
            level = Raise(level, disabled ? "Low" : "High");
        }
        // v29 enumerated kernel drivers too, so inbox drivers such as rdpbus.sys matched "rdp". A driver is not a
        // remote-access service exposure, so the substring vectors apply to service executables only.
        var isDriver = ExecutablePath(imagePath).EndsWith(".sys", StringComparison.OrdinalIgnoreCase);
        foreach (var (vector, vectorLevel) in isDriver ? [] : RemoteAccessVectors)
        {
            if (serviceName.Contains(vector, StringComparison.OrdinalIgnoreCase) || imagePath.Contains(vector, StringComparison.OrdinalIgnoreCase))
            {
                indicators.Add($"Matches remote-access vector: {vector}");
                level = Raise(level, disabled ? "Low" : vectorLevel);
                break;
            }
        }

        var executable = ExecutablePath(imagePath);
        if (IsUnquotedWithSpaces(imagePath))
        {
            // Exploitable when an attacker can create a file at one of the truncated paths.
            var writableParent = UnquotedCandidateDirectories(imagePath).FirstOrDefault(isWritableByStandardUsers);
            indicators.Add(writableParent is null
                ? "Unquoted image path with spaces"
                : $"Unquoted image path with spaces; standard users can write to {writableParent}");
            level = Raise(level, writableParent is null ? "Medium" : "High");
        }
        if (executable.Length > 0 && Path.GetDirectoryName(executable) is { Length: > 0 } directory)
        {
            if (StagingPath().IsMatch(executable))
            {
                indicators.Add("Service binary is in a temporary, download, or public folder");
                level = Raise(level, "High");
            }
            else if (isWritableByStandardUsers(directory))
            {
                indicators.Add($"Standard users can write to the service binary folder {directory}");
                level = Raise(level, disabled ? "Medium" : "High");
            }
        }
        return new ServiceRisk(level, indicators);
    }

    /// <summary>Resolves the executable path from a service ImagePath (quoted, unquoted, \SystemRoot\ or relative driver paths).</summary>
    public static string ExecutablePath(string imagePath)
    {
        var value = Environment.ExpandEnvironmentVariables(imagePath.Trim());
        if (value.Length == 0) return "";
        if (value[0] == '"')
        {
            var end = value.IndexOf('"', 1);
            return end > 1 ? value[1..end] : "";
        }
        var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (value.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) value = Path.Combine(systemRoot, value[12..]);
        else if (value.StartsWith(@"\??\", StringComparison.Ordinal)) value = value[4..];
        else if (value.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase)) value = Path.Combine(systemRoot, value);
        var exe = ExeEnd().Match(value);
        return exe.Success ? value[..(exe.Index + exe.Length)] : value.Split(' ')[0];
    }

    /// <summary>True when the path to the executable contains a space and is not quoted.</summary>
    public static bool IsUnquotedWithSpaces(string imagePath)
    {
        var value = imagePath.Trim();
        if (value.Length == 0 || value[0] == '"' || value.StartsWith(@"\", StringComparison.Ordinal)) return false;
        var exe = ExeEnd().Match(value);
        return exe.Success && value[..exe.Index].Contains(' ');
    }

    /// <summary>Directories where an attacker would plant "Program.exe" etc. for an unquoted path.</summary>
    public static IEnumerable<string> UnquotedCandidateDirectories(string imagePath)
    {
        var value = Environment.ExpandEnvironmentVariables(imagePath.Trim());
        var exe = ExeEnd().Match(value);
        if (!exe.Success) yield break;
        var path = value[..exe.Index];
        for (var space = path.IndexOf(' '); space > 0; space = path.IndexOf(' ', space + 1))
        {
            var prefix = path[..space];
            var directory = Path.GetDirectoryName(prefix);
            if (!string.IsNullOrEmpty(directory)) yield return directory;
        }
    }

    private static string Raise(string current, string candidate) =>
        Rank(candidate) < Rank(current) ? candidate : current;

    private static int Rank(string level) => level switch { "Critical" => 0, "High" => 1, "Medium" => 2, "Low" => 3, _ => 4 };

    [GeneratedRegex(@"\.(exe|sys|dll)(?=$|\s|"")", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ExeEnd();

    [GeneratedRegex(@"\\(Temp|Tmp|Downloads|Users\\Public)\\", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex StagingPath();
}
