using Downpour.Core;

namespace Downpour.Tests;

public sealed class UpdatePathPolicyTests
{
    [Fact]
    public void IsStrictChildPath_AcceptsChildWhenRootHasTrailingSeparator()
    {
        var root = Path.Combine(Path.GetTempPath(), "downpour-update-root");
        var candidate = Path.Combine(root, "bin", "Downpour.Desktop.exe");

        Assert.True(UpdatePathPolicy.IsStrictChildPath(root + Path.DirectorySeparatorChar, candidate));
    }

    [Fact]
    public void IsStrictChildPath_RejectsRootAndSiblingWithSharedPrefix()
    {
        var root = Path.Combine(Path.GetTempPath(), "downpour-update");

        Assert.False(UpdatePathPolicy.IsStrictChildPath(root + Path.DirectorySeparatorChar, root));
        Assert.False(UpdatePathPolicy.IsStrictChildPath(root + Path.DirectorySeparatorChar, root + "-outside" + Path.DirectorySeparatorChar + "file.exe"));
    }
}
