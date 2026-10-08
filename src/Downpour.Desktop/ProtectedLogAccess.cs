using System.Security.Principal;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace Downpour_Desktop;

/// <summary>
/// Explains how to let Downpour read the Security and Sysmon logs without running it as administrator: membership in the
/// built-in Event Log Readers group (S-1-5-32-573) grants read-only access to event logs and nothing else. Downpour never
/// changes group membership itself; the person runs the shown command in an administrator terminal or uses Computer Management.
/// </summary>
internal static class ProtectedLogAccess
{
    private const string EventLogReadersSid = "S-1-5-32-573";

    /// <summary>True when the current sign-in token already carries Event Log Readers or administrator rights.</summary>
    public static bool HasAccessInThisSession()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.Groups?.Any(g => g.Value == EventLogReadersSid) == true ||
               new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>The account name as Windows expects it, for example PC-NAME\person.</summary>
    public static string AccountName => $"{Environment.UserDomainName}\\{Environment.UserName}";

    /// <summary>Uses the group SID so it works on Windows in every language (the group name is translated).</summary>
    public static string Command => $"Add-LocalGroupMember -SID {EventLogReadersSid} -Member '{AccountName.Replace("'", "''")}'";

    public static async Task ShowAsync(XamlRoot root)
    {
        var body = new StackPanel { Spacing = 10, MaxWidth = 640 };
        body.Children.Add(Text(
            "Windows protects the Security log (sign-ins, failed passwords, new accounts, new services and started programs) and the Sysmon log. " +
            "Only administrators and members of the built-in Event Log Readers group can read them."));
        body.Children.Add(Text(
            "Adding your account to Event Log Readers lets Downpour watch these logs while still running with normal rights. " +
            "The group only allows reading event logs; it does not grant any other permission."));
        body.Children.Add(Text("1.  Right-click Start and choose Terminal (Admin).\n2.  Paste this command and press Enter:", bold: true));
        body.Children.Add(new TextBox
        {
            Text = Command, IsReadOnly = true, TextWrapping = TextWrapping.Wrap,
            FontFamily = new FontFamily("Cascadia Mono, Consolas"), FontSize = 12,
        });
        body.Children.Add(Text("3.  Sign out of Windows and sign back in, then reopen Downpour. Group changes apply at the next sign-in.", bold: true));
        body.Children.Add(Text(
            $"Prefer clicking? In Computer Management open Local Users and Groups → Groups → Event Log Readers → Add, and enter {AccountName}. " +
            "(Windows Home does not include that view; use the command.) To undo, run the same command with Remove-LocalGroupMember."));
        if (HasAccessInThisSession())
            body.Children.Add(Text("This sign-in already has access. If the warning remains, restart Downpour.", bold: true));

        var dialog = new ContentDialog
        {
            Title = "Let Downpour read protected Windows logs",
            Content = new ScrollViewer { Content = body },
            PrimaryButtonText = "Copy command",
            SecondaryButtonText = "Open Computer Management",
            CloseButtonText = "Close",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = root,
        };
        dialog.Resources["ContentDialogMaxWidth"] = 760.0;
        var result = await dialog.ShowAsync();
        if (result == ContentDialogResult.Primary) EntityDetails.Copy(Command);
        else if (result == ContentDialogResult.Secondary)
        {
            try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("compmgmt.msc") { UseShellExecute = true })?.Dispose(); }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException) { }
        }
    }

    private static TextBlock Text(string text, bool bold = false) => new()
    {
        Text = text, TextWrapping = TextWrapping.Wrap,
        FontWeight = bold ? Microsoft.UI.Text.FontWeights.SemiBold : Microsoft.UI.Text.FontWeights.Normal,
    };
}
