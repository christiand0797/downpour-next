using Downpour.Contracts;
using Downpour.Core;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Downpour.Tests;

public sealed class AlertInvestigationExportTests
{
    [Fact]
    public void ExportIncludesOnlyValidatedBoundedAlertMetadata()
    {
        var captured = DateTimeOffset.UtcNow;
        Assert.True(SecurityEventCatalog.TryGetRule("System", 7045, out var rule));
        var alert = new SecurityAlert(
            new string('a', 64), rule.Summary, rule.Severity, rule.Technique, "System", "Service Control Manager", 7045, 902,
            captured.AddMinutes(-1), captured.AddMinutes(-1), captured, 1, "Open");
        var snapshot = new SecurityAlertSnapshot(1, captured, 1, [alert], ["One bounded source is unavailable."]);

        var json = AlertInvestigationExport.CreateJson(snapshot);
        var document = JsonConvert.DeserializeObject<AlertInvestigationDocument>(json);

        Assert.NotNull(document);
        Assert.Equal(1, document.SchemaVersion);
        Assert.Equal(1, document.TotalRetainedAlerts);
        Assert.Equal(1, document.IncludedAlerts);
        Assert.Equal(alert.AlertId, Assert.Single(document.Alerts).AlertId);
        Assert.Contains("event messages", document.Scope, StringComparison.OrdinalIgnoreCase);
        var exportedFields = JObject.Parse(json).Properties().Select(property => property.Name).ToArray();
        Assert.DoesNotContain("commandLine", exportedFields, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("username", exportedFields, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("eventXml", exportedFields, StringComparer.OrdinalIgnoreCase);
        Assert.InRange(System.Text.Encoding.UTF8.GetByteCount(json), 1, AlertInvestigationExport.MaximumExportBytes);
    }

    [Fact]
    public void ExportRejectsSnapshotOutsideTheAlertContract()
    {
        var captured = DateTimeOffset.UtcNow;
        var malformed = new SecurityAlertSnapshot(1, captured, 1,
            [new SecurityAlert("not-an-id", "arbitrary untrusted text", "HIGH", "T1543.003", "System", "provider", 7045, 1,
                captured, captured, captured, 1, "Open")], []);

        Assert.Throws<InvalidDataException>(() => AlertInvestigationExport.CreateJson(malformed));
    }
}
