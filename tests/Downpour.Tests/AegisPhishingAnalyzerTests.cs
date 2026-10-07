using Downpour.Core;

namespace Downpour.Tests;

public sealed class AegisPhishingAnalyzerTests
{
    [Fact]
    public void CleanTextReturnsZeroScoreAndCleanVerdict()
    {
        var text = "Hi team, let's reschedule our design review meeting to Thursday at 2 PM. Thanks!";
        var result = AegisPhishingAnalyzer.Analyze(text);

        Assert.Equal(0, result.Score);
        Assert.Equal("CLEAN", result.Verdict);
        Assert.Empty(result.MatchedCategories);
        Assert.Contains("No suspicious urgency", result.Reasons[0], StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void EmptyOrWhitespaceReturnsZeroScore(string? text)
    {
        var result = AegisPhishingAnalyzer.Analyze(text!);

        Assert.Equal(0, result.Score);
        Assert.Equal("CLEAN", result.Verdict);
        Assert.Equal(0, result.UrgencyHits);
    }

    [Fact]
    public void UrgencyTriggersContributeUpToThirtyPoints()
    {
        var text = "URGENT: Act now! Your deadline is today. Verify your account immediately within 24 hours!";
        var result = AegisPhishingAnalyzer.Analyze(text);

        Assert.True(result.UrgencyHits >= 2);
        Assert.Contains("Urgency", result.MatchedCategories);
        Assert.True(result.Score >= 30);
    }

    [Fact]
    public void AuthorityImpersonationContributePoints()
    {
        var text = "Official communication from Microsoft account security and your bank help desk.";
        var result = AegisPhishingAnalyzer.Analyze(text);

        Assert.True(result.AuthorityHits >= 2);
        Assert.Contains("Authority", result.MatchedCategories);
        Assert.True(result.Score >= 20);
    }

    [Fact]
    public void FearAndRewardTriggersContributePoints()
    {
        var text = "Suspicious activity detected on your account! Your password has been compromised. Confirm your identity now.";
        var result = AegisPhishingAnalyzer.Analyze(text);

        Assert.True(result.FearHits >= 2);
        Assert.Contains("Psychological Trigger", result.MatchedCategories);
    }

    [Fact]
    public void BlobUriTriggersEvasionPoints()
    {
        var text = "Please view the shared invoice at blob:https://portal.office.com/document-auth";
        var result = AegisPhishingAnalyzer.Analyze(text);

        Assert.True(result.BlobHits > 0);
        Assert.Contains("Link Evasion", result.MatchedCategories);
        Assert.True(result.Score >= 30);
    }

    [Fact]
    public void RedirectShortenersTriggerPoints()
    {
        var text = "Your package tracking link is ready: https://bit.ly/3x8yz-tracking";
        var result = AegisPhishingAnalyzer.Analyze(text);

        Assert.True(result.RedirectHits > 0);
        Assert.Contains("Redirect Chain", result.MatchedCategories);
    }

    [Fact]
    public void QrCodeTriggersPoints()
    {
        var text = "For security authentication, please scan the below QR code with your phone camera.";
        var result = AegisPhishingAnalyzer.Analyze(text);

        Assert.True(result.QrHits);
        Assert.Contains("QR Evasion", result.MatchedCategories);
    }

    [Fact]
    public void ToneMismatchPhrasesContributePoints()
    {
        var text = "Dear valued customer, kindly update your information attached herewith. Do the needful and revert back.";
        var result = AegisPhishingAnalyzer.Analyze(text);

        Assert.True(result.GrammarHits >= 2);
        Assert.Contains("Tone Mismatch", result.MatchedCategories);
    }

    [Fact]
    public void CompoundPhishingYieldsPhishingVerdict()
    {
        var text =
            "URGENT: Your Microsoft 365 account has been compromised. " +
            "You must verify your account immediately within 24 hours or your access will be terminated. " +
            "Click this link: blob:https://login.microsoftonline.com/auth or scan the below QR code to confirm your identity.";

        var result = AegisPhishingAnalyzer.Analyze(text);

        Assert.True(result.Score >= 70);
        Assert.Equal("PHISHING", result.Verdict);
        Assert.Contains("Urgency", result.MatchedCategories);
        Assert.Contains("Authority", result.MatchedCategories);
        Assert.Contains("Psychological Trigger", result.MatchedCategories);
        Assert.Contains("Link Evasion", result.MatchedCategories);
        Assert.Contains("QR Evasion", result.MatchedCategories);
    }

    [Fact]
    public void IntermediateScoreYieldsSuspiciousVerdict()
    {
        // Urgency (+15) + Authority (+20) + Redirect (+15) = 50
        var text = "Immediately contact your bank at https://tinyurl.com/bank-verify";
        var result = AegisPhishingAnalyzer.Analyze(text);

        Assert.InRange(result.Score, 50, 69);
        Assert.Equal("SUSPICIOUS", result.Verdict);
    }
}
