namespace Downpour.Core;

/// <summary>Canonical containment checks for package files; works when roots have a trailing separator.</summary>
public static class UpdatePathPolicy
{
    public static bool IsStrictChildPath(string directoryPath, string candidatePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(candidatePath);
        var root = Path.GetFullPath(directoryPath);
        var candidate = Path.GetFullPath(candidatePath);
        var relative = Path.GetRelativePath(root, candidate);
        return relative != "." && !Path.IsPathRooted(relative) &&
            relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) &&
            !relative.StartsWith(".." + Path.AltDirectorySeparatorChar, StringComparison.Ordinal);
    }
}
