using System.Security.Cryptography;
using System.Text;
using Downpour.Core;

namespace Downpour.Tests;

public sealed class RansomwareDefenseInspectorTests
{
    [Fact]
    public void GetDefaultProtectedDirectoriesReturnsExpectedList()
    {
        var dirs = RansomwareDefenseInspector.GetDefaultProtectedDirectories();

        Assert.NotNull(dirs);
        Assert.NotEmpty(dirs);
        Assert.All(dirs, d => Assert.False(string.IsNullOrWhiteSpace(d)));
    }

    [Theory]
    [InlineData("readme_for_decrypt.txt", true)]
    [InlineData("restore-my-files.txt", true)]
    [InlineData("_readme.txt", true)]
    [InlineData("how_to_recover.html", true)]
    [InlineData("decrypt_notes.txt", true)]
    [InlineData("HOW_TO_DECRYPT_FILES.txt", true)]
    [InlineData("!-README-!.txt", true)]
    [InlineData("decrypt_my_files.hta", true)]
    [InlineData("files_encrypted.rtf", true)]
    [InlineData("readme.md", false)]
    [InlineData("notes.txt", false)]
    [InlineData("recovery_report.docx", false)]
    [InlineData("normal_budget.xlsx", false)]
    public void IsRansomNoteIdentifiesRansomNotesAccurately(string fileName, bool expected)
    {
        var isNote = RansomwareDefenseInspector.IsRansomNote(fileName);
        Assert.Equal(expected, isNote);
    }

    [Theory]
    [InlineData(".lockbit", true)]
    [InlineData(".blackcat", true)]
    [InlineData(".rhysida", true)]
    [InlineData(".darkside", true)]
    [InlineData(".crypted", true)]
    [InlineData(".enc", true)]
    [InlineData(".locked", true)]
    [InlineData(".wnry", true)]
    [InlineData(".txt", false)]
    [InlineData(".docx", false)]
    [InlineData(".pdf", false)]
    [InlineData(".dll", false)]
    public void IsSuspiciousRansomwareExtensionRecognizesMaliciousExtensions(string extension, bool expected)
    {
        var isSuspicious = RansomwareDefenseInspector.IsSuspiciousRansomwareExtension(extension);
        Assert.Equal(expected, isSuspicious);
    }

    [Fact]
    public async Task InspectAsyncDetectsRansomNotesAndMaliciousExtensions()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "DownpourTest_Ransomware_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            // Benign file
            await File.WriteAllTextAsync(Path.Combine(tempDir, "document.txt"), "Standard clean business text.");

            // Ransom note
            await File.WriteAllTextAsync(Path.Combine(tempDir, "readme_for_decrypt.txt"), "ALL YOUR FILES ARE ENCRYPTED. PAY 1 BTC.");

            // Encrypted payload with known extension
            await File.WriteAllBytesAsync(Path.Combine(tempDir, "finances.xlsx.lockbit"), new byte[256]);

            var posture = await RansomwareDefenseInspector.InspectAsync([tempDir]);

            Assert.Equal("UNDER_ATTACK", posture.OverallStatus);
            Assert.Contains(posture.ThreatIndicators, i => i.Category == "Ransom Note");
            Assert.Contains(posture.ThreatIndicators, i => i.Category == "Suspicious Extension");
            Assert.True(posture.TotalFilesMonitored >= 3);
            Assert.Contains("File restoration and automated rollback actions are guarded", posture.SecurityNotice);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, true);
            }
        }
    }

    [Fact]
    public async Task InspectAsyncDetectsActiveAndEncryptedCanaries()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "DownpourTest_Canary_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            // 1. Benign active canary
            var activeCanaryPath = Path.Combine(tempDir, "!_Budget_2026_FINAL.xlsx.canary");
            var benignBytes = Encoding.UTF8.GetBytes("PK\x03\x04" + new string('A', 500));
            await File.WriteAllBytesAsync(activeCanaryPath, benignBytes);

            // 2. High-entropy encrypted canary
            var encCanaryPath = Path.Combine(tempDir, "!_Contract_Draft_v3.docx.canary");
            var randomBytes = new byte[1024];
            RandomNumberGenerator.Fill(randomBytes);
            await File.WriteAllBytesAsync(encCanaryPath, randomBytes);

            var posture = await RansomwareDefenseInspector.InspectAsync([tempDir]);

            var active = Assert.Single(posture.Canaries, c => c.FileName == "!_Budget_2026_FINAL.xlsx.canary");
            Assert.Equal("Active", active.Status);
            Assert.True(active.IntegrityVerified);

            var encrypted = Assert.Single(posture.Canaries, c => c.FileName == "!_Contract_Draft_v3.docx.canary");
            Assert.Equal("Encrypted", encrypted.Status);
            Assert.False(encrypted.IntegrityVerified);
            Assert.True(encrypted.CurrentEntropy > 7.5);

            Assert.Contains(posture.ThreatIndicators, i => i.Category == "Canary Disruption" && i.Severity == "CRITICAL");
            Assert.Equal("UNDER_ATTACK", posture.OverallStatus);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, true);
            }
        }
    }

    [Fact]
    public async Task GenerateReportFormatsComprehensiveSections()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "DownpourTest_Report_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            await File.WriteAllTextAsync(Path.Combine(tempDir, "memo.txt"), "Benign notes.");

            var posture = await RansomwareDefenseInspector.InspectAsync([tempDir]);
            var reportText = RansomwareDefenseInspector.GenerateReport(posture);

            Assert.Contains("=== DOWNPOUR RANSOMWARE DEFENSE & POSTURE REPORT ===", reportText);
            Assert.Contains("=== VOLUME SHADOW COPY (VSS) POSTURE ===", reportText);
            Assert.Contains("=== PROTECTED DIRECTORIES", reportText);
            Assert.Contains("=== CANARY FILE DECOYS", reportText);
            Assert.Contains("=== DETECTED THREAT INDICATORS", reportText);
            Assert.Contains("=== EXECUTION & RECOVERY POLICY NOTICE ===", reportText);
            Assert.Contains(posture.SecurityNotice, reportText);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, true);
            }
        }
    }
}
