using Downpour.Contracts;
using Downpour.Core;

namespace Downpour.Tests;

public class FeatureSwitchManagerTests
{
    [Fact]
    public async Task LoadAsync_WhenFileDoesNotExist_ReturnsDefaults()
    {
        // Arrange
        var tempPath = Path.Combine(Path.GetTempPath(), $"downpour-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempPath);
        var manager = new FeatureSwitchManager(Path.Combine(tempPath, "feature-switches.json"));

        try
        {
            // Act
            var switches = await manager.LoadAsync();

            // Assert
            Assert.NotNull(switches);
            Assert.True(switches.ContainsKey(ActionKinds.QuarantineFile));
            Assert.False(switches[ActionKinds.QuarantineFile].Enabled);
        }
        finally
        {
            if (Directory.Exists(tempPath))
            {
                try { Directory.Delete(tempPath, recursive: true); }
                catch { /* Ignore */ }
            }
        }
    }

    [Fact]
    public async Task SetEnabledAsync_EnablesFeature_WritesToStorage()
    {
        // Arrange
        var tempPath = Path.Combine(Path.GetTempPath(), $"downpour-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempPath);
        var manager = new FeatureSwitchManager(Path.Combine(tempPath, "feature-switches.json"));
        var featureId = ActionKinds.QuarantineFile;

        try
        {
            // Act
            var result = await manager.SetEnabledAsync(featureId, enabled: true);

            // Assert
            Assert.True(result);

            var switches = await manager.LoadAsync();
            Assert.True(switches[featureId].Enabled);
            Assert.NotNull(switches[featureId].EnabledAtUtc);
        }
        finally
        {
            if (Directory.Exists(tempPath))
            {
                try { Directory.Delete(tempPath, recursive: true); }
                catch { /* Ignore */ }
            }
        }
    }

    [Fact]
    public async Task SetEnabledAsync_DisablesFeature_UpdatesStorage()
    {
        // Arrange
        var tempPath = Path.Combine(Path.GetTempPath(), $"downpour-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempPath);
        var manager = new FeatureSwitchManager(Path.Combine(tempPath, "feature-switches.json"));
        var featureId = ActionKinds.QuarantineFile;

        try
        {
            await manager.SetEnabledAsync(featureId, enabled: true);

            // Act
            var result = await manager.SetEnabledAsync(featureId, enabled: false);

            // Assert
            Assert.True(result);

            var switches = await manager.LoadAsync();
            Assert.False(switches[featureId].Enabled);
            Assert.Null(switches[featureId].EnabledAtUtc);
        }
        finally
        {
            if (Directory.Exists(tempPath))
            {
                try { Directory.Delete(tempPath, recursive: true); }
                catch { /* Ignore */ }
            }
        }
    }

    [Fact]
    public async Task SetEnabledAsync_WithUnknownFeature_ReturnsFalse()
    {
        // Arrange
        var tempPath = Path.Combine(Path.GetTempPath(), $"downpour-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempPath);
        var manager = new FeatureSwitchManager(Path.Combine(tempPath, "feature-switches.json"));

        try
        {
            // Act
            var result = await manager.SetEnabledAsync("UnknownFeature", enabled: true);

            // Assert
            Assert.False(result);
        }
        finally
        {
            if (Directory.Exists(tempPath))
            {
                try { Directory.Delete(tempPath, recursive: true); }
                catch { /* Ignore */ }
            }
        }
    }

    [Fact]
    public async Task SetEnabledAsync_WithSameState_ReturnsTrue()
    {
        // Arrange
        var tempPath = Path.Combine(Path.GetTempPath(), $"downpour-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempPath);
        var manager = new FeatureSwitchManager(Path.Combine(tempPath, "feature-switches.json"));
        var featureId = ActionKinds.QuarantineFile;

        try
        {
            await manager.SetEnabledAsync(featureId, enabled: true);

            // Act
            var result = await manager.SetEnabledAsync(featureId, enabled: true);

            // Assert
            Assert.True(result);
        }
        finally
        {
            if (Directory.Exists(tempPath))
            {
                try { Directory.Delete(tempPath, recursive: true); }
                catch { /* Ignore */ }
            }
        }
    }

    [Fact]
    public async Task LoadAsync_WithPersistedState_RestoresState()
    {
        // Arrange
        var tempPath = Path.Combine(Path.GetTempPath(), $"downpour-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempPath);
        var manager = new FeatureSwitchManager(Path.Combine(tempPath, "feature-switches.json"));
        var featureId = ActionKinds.QuarantineFile;

        try
        {
            await manager.SetEnabledAsync(featureId, enabled: true);

            // Create a new manager instance to simulate restart
            var newManager = new FeatureSwitchManager(Path.Combine(tempPath, "feature-switches.json"));

            // Act
            var switches = await newManager.LoadAsync();

            // Assert
            Assert.True(switches[featureId].Enabled);
            Assert.NotNull(switches[featureId].EnabledAtUtc);
        }
        finally
        {
            if (Directory.Exists(tempPath))
            {
                try { Directory.Delete(tempPath, recursive: true); }
                catch { /* Ignore */ }
            }
        }
    }

    [Fact]
    public async Task LoadAsync_WithSchemaMismatch_ReturnsDefaults()
    {
        // Arrange
        var tempPath = Path.Combine(Path.GetTempPath(), $"downpour-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempPath);
        var filePath = Path.Combine(tempPath, "feature-switches.json");
        await File.WriteAllTextAsync(filePath, @"{""SchemaVersion"":999}");
        var manager = new FeatureSwitchManager(filePath);

        try
        {
            // Act
            var switches = await manager.LoadAsync();

            // Assert
            Assert.NotNull(switches);
            Assert.True(switches.ContainsKey(ActionKinds.QuarantineFile));
            Assert.False(switches[ActionKinds.QuarantineFile].Enabled);
        }
        finally
        {
            if (Directory.Exists(tempPath))
            {
                try { Directory.Delete(tempPath, recursive: true); }
                catch { /* Ignore */ }
            }
        }
    }

    [Fact]
    public async Task LoadAsync_WithPolicyVersionChange_DisablesSwitch()
    {
        // Arrange
        var tempPath = Path.Combine(Path.GetTempPath(), $"downpour-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempPath);
        var filePath = Path.Combine(tempPath, "feature-switches.json");
        var manager = new FeatureSwitchManager(filePath);
        var featureId = ActionKinds.QuarantineFile;

        try
        {
            await manager.SetEnabledAsync(featureId, enabled: true);

            // Write a file with a different policy version
            var json = await File.ReadAllTextAsync(filePath);
            var modifiedJson = json.Replace(DefaultActionCatalog.CurrentPolicyVersion, "0.0.0");
            await File.WriteAllTextAsync(filePath, modifiedJson);

            // Act
            var switches = await manager.LoadAsync();

            // Assert
            Assert.False(switches[featureId].Enabled);
            Assert.Null(switches[featureId].EnabledAtUtc);
        }
        finally
        {
            if (Directory.Exists(tempPath))
            {
                try { Directory.Delete(tempPath, recursive: true); }
                catch { /* Ignore */ }
            }
        }
    }
}
