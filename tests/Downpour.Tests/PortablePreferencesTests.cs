using System.Text;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class PortablePreferencesTests
{
    private static readonly string[] Names = ["RainEffectsEnabled", "ReduceMotion", "SoundAlarmEnabled"];

    [Fact]
    public void PreferencesSurviveEncryptionAndComeBackSorted()
    {
        var values = new Dictionary<string, bool>(StringComparer.Ordinal)
        {
            ["SoundAlarmEnabled"] = true,
            ["RainEffectsEnabled"] = false,
            ["ReduceMotion"] = true,
        };

        var blob = PortableSettingsBundle.Encrypt("correct horse battery", PortablePreferences.Serialize(values));
        var imported = PortablePreferences.Deserialize(PortableSettingsBundle.Decrypt("correct horse battery", blob), Names);

        Assert.Equal(Names, imported.Keys);
        Assert.False(imported["RainEffectsEnabled"]);
        Assert.True(imported["ReduceMotion"]);
        Assert.True(imported["SoundAlarmEnabled"]);
        Assert.Throws<InvalidDataException>(() => PortableSettingsBundle.Decrypt("wrong horse battery!", blob));
    }

    [Fact]
    public void BundleRefusesStateAnOlderBuildDoesNotKnow()
    {
        var payload = Encoding.UTF8.GetBytes("""{"schema":"downpour-preferences.v1","values":{"CaseEvidence":false}}""");
        var exception = Assert.Throws<InvalidDataException>(() => PortablePreferences.Deserialize(payload, Names));
        Assert.Contains("CaseEvidence", exception.Message);
    }

    [Fact]
    public void SerializeAcceptsOnlyShortLetterNames()
    {
        Assert.Throws<ArgumentException>(() => PortablePreferences.Serialize(new Dictionary<string, bool> { ["Case evidence"] = true }));
        Assert.Throws<ArgumentException>(() => PortablePreferences.Serialize(new Dictionary<string, bool> { [new string('a', PortablePreferences.MaximumNameLength + 1)] = true }));
        Assert.Throws<ArgumentException>(() => PortablePreferences.Serialize(new Dictionary<string, bool>()));
        Assert.Throws<ArgumentException>(() => PortablePreferences.Serialize(
            Enumerable.Range(0, PortablePreferences.MaximumEntries + 1).ToDictionary(index => new string('a', index + 1), _ => true)));
    }

    [Fact]
    public void DeserializeRefusesMalformedChunksWholeAndNeverPartly()
    {
        Assert.Throws<InvalidDataException>(() => PortablePreferences.Deserialize(Array.Empty<byte>(), Names));
        Assert.Throws<InvalidDataException>(() => PortablePreferences.Deserialize(Encoding.UTF8.GetBytes("not json"), Names));
        Assert.Throws<InvalidDataException>(() => PortablePreferences.Deserialize(Encoding.UTF8.GetBytes("""{"schema":"downpour-preferences.v2","values":{"ReduceMotion":true}}"""), Names));
        Assert.Throws<InvalidDataException>(() => PortablePreferences.Deserialize(Encoding.UTF8.GetBytes("""{"schema":"downpour-preferences.v1","values":{}}"""), Names));
        Assert.Throws<InvalidDataException>(() => PortablePreferences.Deserialize(Encoding.UTF8.GetBytes("""{"schema":"downpour-preferences.v1","values":{"ReduceMotion":"yes"}}"""), Names));
        Assert.Throws<InvalidDataException>(() => PortablePreferences.Deserialize(Encoding.UTF8.GetBytes("""{"schema":"downpour-preferences.v1","values":{"ReduceMotion":true,"ReduceMotion":false}}"""), Names));
        Assert.Throws<InvalidDataException>(() => PortablePreferences.Deserialize(Encoding.UTF8.GetBytes("""{"schema":"downpour-preferences.v1","values":{"Case evidence":true}}"""), Names));
        Assert.Throws<InvalidDataException>(() => PortablePreferences.Deserialize(new byte[PortablePreferences.MaximumPayloadBytes + 1], Names));
    }

    [Fact]
    public void ChangeSummaryNamesOnlyWhatDiffers()
    {
        var current = new Dictionary<string, bool> { ["RainEffectsEnabled"] = true, ["ReduceMotion"] = false };
        var imported = new Dictionary<string, bool> { ["RainEffectsEnabled"] = false, ["ReduceMotion"] = false, ["SoundAlarmEnabled"] = true };

        var changes = PortablePreferences.DescribeChanges(current, imported);

        Assert.Equal(2, changes.Count);
        Assert.Contains("rain effects enabled: on → off", changes);
        Assert.Contains("sound alarm enabled: off → on", changes);
        Assert.DoesNotContain(changes, change => change.Contains("reduce motion", StringComparison.Ordinal));
    }

    [Fact]
    public void PayloadCarriesNoPathAddressOrFreeText()
    {
        var payload = Encoding.UTF8.GetString(PortablePreferences.Serialize(new Dictionary<string, bool> { ["ReduceMotion"] = true }));
        Assert.Matches("^[A-Za-z0-9{}\":,._-]+$", payload);
        Assert.DoesNotContain("\\", payload);
        Assert.DoesNotContain("@", payload);
    }

    [Fact]
    public void PreviewSaysWhatLeavesTheMachineAndRefusesFeedKeys()
    {
        var preferencesOnly = PortableSettingsBundle.Preview(new(true, false, false, false));
        Assert.True(preferencesOnly.CanExport);
        Assert.Single(preferencesOnly.Contents);
        Assert.Equal("Application settings", preferencesOnly.Contents[0]);
        Assert.Empty(preferencesOnly.Refusals);

        var withKeys = PortableSettingsBundle.Preview(new(true, false, false, true));
        Assert.Contains(withKeys.Refusals, refusal => refusal.Contains("credentials", StringComparison.Ordinal));
        Assert.DoesNotContain(withKeys.Contents, content => content.Contains("credential", StringComparison.OrdinalIgnoreCase));
    }
}
