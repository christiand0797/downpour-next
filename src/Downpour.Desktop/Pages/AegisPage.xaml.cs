using System.Collections.ObjectModel;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed partial class AegisPage : Page
{
    private static readonly Color RedColor = Color.FromArgb(255, 248, 81, 73);
    private static readonly Color OrangeColor = Color.FromArgb(255, 240, 136, 62);
    private static readonly Color GreenColor = Color.FromArgb(255, 63, 185, 80);

    public AegisPage()
    {
        InitializeComponent();
    }

    private void Analyze_Click(object sender, RoutedEventArgs e)
    {
        var text = PhishInputText.Text?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(text))
        {
            ResultCard.Visibility = Visibility.Collapsed;
            return;
        }

        var result = AegisPhishingAnalyzer.Analyze(text);
        ResultScoreText.Text = result.Score.ToString();
        VerdictText.Text = result.Verdict;

        Color scoreColor;
        string summary;
        if (result.Verdict == "PHISHING")
        {
            scoreColor = RedColor;
            summary = "Critical Risk: High probability of phishing, credential harvesting, or social engineering.";
        }
        else if (result.Verdict == "SUSPICIOUS")
        {
            scoreColor = OrangeColor;
            summary = "Elevated Risk: Contains urgency pressure, tone anomalies, or suspicious redirection cues.";
        }
        else
        {
            scoreColor = GreenColor;
            summary = "Low Risk: No significant urgency, impersonation, or deceptive indicators detected.";
        }

        var brush = new SolidColorBrush(scoreColor);
        var bgBrush = new SolidColorBrush(Color.FromArgb(51, scoreColor.R, scoreColor.G, scoreColor.B));

        ResultScoreText.Foreground = brush;
        VerdictText.Foreground = brush;
        VerdictBadge.Background = bgBrush;
        VerdictSummary.Text = summary;

        ReasonsList.ItemsSource = result.Reasons;
        ResultCard.Visibility = Visibility.Visible;
    }

    private void LoadSample_Click(object sender, RoutedEventArgs e)
    {
        PhishInputText.Text =
            "URGENT: Your Microsoft 365 account has been compromised. " +
            "You must verify your account immediately within 24 hours or your access will be terminated. " +
            "Click this link: blob:https://login.microsoftonline.com/auth or scan the below QR code to confirm your identity.";
        Analyze_Click(sender, e);
    }

    private void Clear_Click(object sender, RoutedEventArgs e)
    {
        PhishInputText.Text = string.Empty;
        ResultCard.Visibility = Visibility.Collapsed;
    }
}
