using System.Text.RegularExpressions;
using Downpour.Contracts;

namespace Downpour.Core;

/// <summary>
/// Grades a "service installed" event (System 7045, Security 4697) by what was installed instead of treating every
/// install as HIGH. Windows and Defender install Microsoft-signed drivers routinely (for example Defender's MpKslDrv on
/// every platform update), while attacker tools install services that run a shell or an unsigned file.
/// Only the service name and the executable path are used; command-line arguments are dropped.
/// </summary>
public static partial class ServiceInstallAnalyzer
{
    public const int MaximumDetail = 300;

    public static readonly IReadOnlySet<int> EventIds = new HashSet<int> { 7045, 4697 };

    public static bool Applies(string logName, int eventId) =>
        (logName.Equals("System", StringComparison.OrdinalIgnoreCase) && eventId == 7045)
        || (logName.Equals("Security", StringComparison.OrdinalIgnoreCase) && eventId == 4697);

    /// <summary>
    /// Turns a service ImagePath into a path Windows would open: strips \??\ and quotes, maps \SystemRoot\ and
    /// relative System32 paths to %SystemRoot%, and drops arguments. Returns null for empty or network paths.
    /// </summary>
    public static string? NormalizeImagePath(string? imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath) || imagePath.Length > 2048) return null;
        var text = imagePath.Trim();
        if (text.StartsWith(@"\??\", StringComparison.Ordinal)) text = text[4..];
        if (text.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) text = "%SystemRoot%" + text[11..];
        else if (text.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase) || text.StartsWith(@"SysWOW64\", StringComparison.OrdinalIgnoreCase))
            text = @"%SystemRoot%\" + text;
        var target = PersistenceAnalyzer.CommandTarget(text);
        if (target is null || target.StartsWith(@"\\", StringComparison.Ordinal)) return null;
        return target.Length <= 1024 ? target : null;
    }

    /// <summary>
    /// Severity and a one-line detail. A service that runs a shell or script host is CRITICAL (PsExec/Impacket style);
    /// Microsoft-signed is LOW; another publisher's signed file in a protected folder is MEDIUM; unsigned or in a user
    /// folder stays HIGH; when the file could not be checked the rule's severity is kept.
    /// </summary>
    public static (string Severity, string Detail) Assess(string ruleSeverity, string? serviceName, string? imagePath, string? resolvedPath, PersistenceSignature? signature)
    {
        var name = Clean(serviceName, 80) ?? "unnamed service";
        var shown = Clean(resolvedPath ?? NormalizeImagePath(imagePath) ?? imagePath, 160) ?? "path not recorded";
        var command = imagePath ?? "";
        string severity;
        string verdict;
        if (command.Length > 0 && (PersistenceAnalyzer.IsScriptHostCommand(command) || ShellService().IsMatch(command)))
        {
            severity = "CRITICAL";
            verdict = "runs a shell or script host (remote-execution tools install services like this)";
        }
        else if (signature is null)
        {
            // Kept at the rule's severity: a vanished service file is usually an update, but can also be clean-up.
            severity = ruleSeverity;
            verdict = resolvedPath is null && NormalizeImagePath(imagePath) is not null
                ? "file no longer exists (updated or removed), signature cannot be checked"
                : "signature not checked";
        }
        else if (signature.Signed == true && signature.Microsoft)
        {
            severity = "LOW";
            verdict = "signed by Microsoft (routine Windows or Defender component)";
        }
        else if (signature.Signed == true && !AudioThreatAnalyzer.IsUserWritable(resolvedPath))
        {
            severity = "MEDIUM";
            verdict = $"signed by {PersistenceAnalyzer.SignerDisplay(signature.Signer)}";
        }
        else if (signature.Signed == true)
        {
            severity = "HIGH";
            verdict = $"signed by {PersistenceAnalyzer.SignerDisplay(signature.Signer)}, but in a folder any program can write to";
        }
        else
        {
            severity = "HIGH";
            verdict = "file is not validly signed";
        }
        // Verdict before path: alert titles are cut at 160 characters and the full path is kept as the alert's evidence.
        var detail = $"{name} · {verdict} · {shown}";
        return (severity, detail.Length <= MaximumDetail ? detail : detail[..MaximumDetail]);
    }

    /// <summary>Services whose image is a shell: %COMSPEC% or cmd with switches (PsExec, Impacket smbexec/psexec, Metasploit).</summary>
    [GeneratedRegex(@"%comspec%|(^|[\\\s""])cmd(\.exe)?""?\s+/|\bpwsh(\.exe)?\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ShellService();

    private static string? Clean(string? value, int max)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var clean = new string(value.Where(ch => !char.IsControl(ch)).Take(max).ToArray()).Trim();
        return clean.Length == 0 ? null : clean;
    }
}
