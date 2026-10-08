using System.Diagnostics;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;

namespace Downpour_Desktop.Pages;

/// <summary>
/// Audio Shield: microphone and loopback listeners, audio devices with live levels, audio effect DLLs loaded into the
/// audio engine, and glitch causes. Rows are rebuilt only when what is shown changes; level meters update in place
/// every second. Fixes use the audited action broker (end program, quarantine) or open a fixed Windows settings page.
/// </summary>
public sealed partial class AudioPage : Page
{
    /// <summary>The only settings pages this page opens; nothing else is ever launched.</summary>
    private static readonly IReadOnlyDictionary<string, string> SettingsPages = new Dictionary<string, string>
    {
        ["sound"] = "ms-settings:sound",
        ["devices"] = "ms-settings:sound-devices",
        ["bluetooth"] = "ms-settings:bluetooth",
        ["mic-privacy"] = "ms-settings:privacy-microphone",
        ["troubleshoot"] = "ms-settings:troubleshoot",
        ["apps"] = "ms-settings:appsfeatures",
    };

    private readonly AudioClient _client = new();
    private readonly Dictionary<string, ProgressBar> _meters = new(StringComparer.Ordinal);
    private AudioSnapshot? _latest;
    private string _structure = "";
    private string _filter = "";

    public AudioPage()
    {
        InitializeComponent();
        LiveRefresh.Attach(this, () => RefreshAsync());
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _ = RefreshAsync(ensureService: true);
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        _structure = "";
        await RefreshAsync(ensureService: true);
    }

    private async void Export_Click(object sender, RoutedEventArgs e) => await CaseFileExporter.ExportFromAsync(ExportButton);

    private void OpenTriage_Click(object sender, RoutedEventArgs e) => App.NavigateToRoute("threats");

    private void IssueFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        _filter = (IssueFilter.SelectedItem as ComboBoxItem)?.Tag as string ?? "";
        _structure = "";
        if (_latest is not null) Render(_latest);
    }

    private void ShowAllDevices_Toggled(object sender, RoutedEventArgs e)
    {
        _structure = "";
        if (_latest is not null) Render(_latest);
    }

    private async void OpenSoundDevices_Click(object sender, RoutedEventArgs e) => await OpenSettingsAsync("devices");
    private async void OpenBluetooth_Click(object sender, RoutedEventArgs e) => await OpenSettingsAsync("bluetooth");
    private async void OpenMicPrivacy_Click(object sender, RoutedEventArgs e) => await OpenSettingsAsync("mic-privacy");
    private async void OpenTroubleshoot_Click(object sender, RoutedEventArgs e) => await OpenSettingsAsync("troubleshoot");

    private static async Task OpenSettingsAsync(string page)
    {
        if (SettingsPages.TryGetValue(page, out var uri)) await Windows.System.Launcher.LaunchUriAsync(new Uri(uri));
    }

    private async Task RefreshAsync(bool ensureService = false)
    {
        var snapshot = await _client.TryGetSnapshotAsync();
        if (snapshot is null && ensureService)
        {
            await App.EnsureSensorServiceAsync();
            snapshot = await _client.TryGetSnapshotAsync();
        }
        if (snapshot is null)
        {
            SummaryHeadline.Text = "The sensor service is not reachable";
            SummaryDetail.Text = "Audio Shield runs in the local sensor service and resumes when it reconnects.";
            SummaryIcon.Foreground = Brush("HudAmberBrush");
            return;
        }
        _latest = snapshot;
        Render(snapshot);
    }

    private void Render(AudioSnapshot s)
    {
        var showAll = ShowAllDevices.IsOn;
        var listening = s.Sessions.Where(x => x.Flow == AudioFlows.Recording).OrderBy(x => x.State == "active" ? 0 : 1).ThenBy(x => x.ProcessName).ToArray();
        var playing = s.Sessions.Where(x => x.Flow == AudioFlows.Playback).OrderBy(x => x.ProcessName).ToArray();
        var devices = s.Devices.Where(d => showAll || d.State == "active")
            .OrderBy(d => d.Flow).ThenByDescending(d => d.IsDefault).ThenBy(d => d.Name).ToArray();
        var issues = s.Issues.Where(i => _filter.Length == 0 || i.Category == _filter).ToArray();

        RenderSummary(s, listening);
        RenderTiles(s, listening);

        var structure = string.Join('|',
            string.Join(',', issues.Select(i => i.Severity + i.Indicator)),
            string.Join(',', listening.Select(x => $"{x.ProcessId}{x.Device}{x.State}{x.Signed}")),
            string.Join(',', playing.Select(x => $"{x.ProcessId}{x.Device}")),
            string.Join(',', devices.Select(d => $"{d.Id}{d.State}{d.IsDefault}{d.Muted}{d.VolumePercent}{d.IsNew}{d.Format}")),
            string.Join(',', s.Effects.Select(e => e.Clsid + e.Signed)),
            $"{s.Posture}", string.Join(',', s.Warnings));
        if (structure != _structure)
        {
            _structure = structure;
            _meters.Clear();
            RenderIssues(issues, s);
            RenderSessions(ListeningPanel, ListeningEmpty, listening, recording: true);
            RenderSessions(PlayingPanel, PlayingEmpty, playing, recording: false);
            RenderDevices(devices);
            RenderEffects(s.Effects);
            RenderPosture(s.Posture);
            WarningsText.Text = string.Join(Environment.NewLine, s.Warnings);
            WarningsText.Visibility = s.Warnings.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        }
        UpdateMeters(s);
    }

    private void RenderSummary(AudioSnapshot s, IReadOnlyList<AudioSession> listening)
    {
        var worst = s.Issues.Where(i => i.Severity != AudioThreatAnalyzer.Info).MinBy(i => AudioThreatAnalyzer.Rank(i.Severity));
        var active = listening.Where(x => x.State == "active").ToArray();
        if (worst is not null && AudioThreatAnalyzer.Rank(worst.Severity) <= 1)
        {
            SummaryHeadline.Text = worst.Title;
            SummaryDetail.Text = worst.Detail;
            SummaryIcon.Glyph = "";
            SummaryIcon.Foreground = Brush("HudRedBrush");
        }
        else if (active.Length > 0)
        {
            SummaryHeadline.Text = active.Length == 1 ? $"{active[0].ProcessName} is listening to your microphone" : $"{active.Length} programs are listening to your microphone";
            SummaryDetail.Text = string.Join(", ", active.Select(x => $"{x.ProcessName} on {x.Device}")) + ". Check that each one is something you are using right now.";
            SummaryIcon.Glyph = "";
            SummaryIcon.Foreground = Brush("HudAmberBrush");
        }
        else if (worst is not null)
        {
            SummaryHeadline.Text = worst.Title;
            SummaryDetail.Text = worst.Detail;
            SummaryIcon.Glyph = "";
            SummaryIcon.Foreground = Brush("HudAmberBrush");
        }
        else
        {
            SummaryHeadline.Text = "Nothing is listening, and audio looks healthy";
            SummaryDetail.Text = $"{s.Devices.Count(d => d.State == "active")} active audio devices, {s.Effects.Count} audio effects checked. Updated {s.CapturedAtUtc.ToLocalTime():T}.";
            SummaryIcon.Glyph = "";
            SummaryIcon.Foreground = Brush("HudGreenBrush");
        }
    }

    private void RenderTiles(AudioSnapshot s, IReadOnlyList<AudioSession> listening)
    {
        var active = listening.Count(x => x.State == "active");
        ListeningValue.Text = active.ToString();
        ListeningValue.Foreground = Brush(active > 0 ? "HudAmberBrush" : "HudGreenBrush");
        ListeningCaption.Text = listening.Count > active ? $"{listening.Count - active} more holding a mic open" : active > 0 ? "receiving audio now" : "no recording streams";

        var mics = s.Devices.Where(d => d.Flow == AudioFlows.Recording && d.State == "active").ToArray();
        MicValue.Text = mics.Length.ToString();
        var defaultMic = mics.FirstOrDefault(d => d.IsDefault);
        MicCaption.Text = defaultMic is null ? "no default microphone"
            : $"default: {defaultMic.Name}{(defaultMic.Muted == true ? " (muted)" : "")}{(mics.Any(d => d.IsNew) ? " · new device" : "")}";

        var unsigned = s.Effects.Count(e => e.Signed == false);
        EffectsValue.Text = s.Effects.Count.ToString();
        EffectsValue.Foreground = Brush(unsigned > 0 ? "HudRedBrush" : "HudCyanBrush");
        EffectsCaption.Text = unsigned > 0 ? $"{unsigned} not validly signed" : $"{s.Effects.Count(e => e.Microsoft)} Microsoft, {s.Effects.Count(e => !e.Microsoft)} vendor";

        var posture = s.Posture;
        var healthy = posture.AudioService == "Running" && posture.EndpointBuilder == "Running";
        EngineValue.Text = healthy ? $"{posture.AudioEngineCpuPercent:0.0}% CPU" : "Stopped";
        EngineValue.Foreground = Brush(!healthy || posture.AudioEngineCpuPercent >= AudioThreatAnalyzer.EngineCpuGlitchPercent ? "HudRedBrush" : "HudCyanBrush");
        EngineMeter.Value = Math.Min(100, posture.AudioEngineCpuPercent * 4);
        EngineCaption.Text = posture.AudioEngineSigned switch
        {
            true => "audiodg.exe signed by Microsoft",
            false => "audiodg.exe failed the signature check",
            _ => posture.AudioEnginePath is null ? "audio engine idle" : "signature not checked yet",
        };

        var threats = s.Issues.Count(i => i.Category != AudioIssueCategories.Glitch && i.Severity != AudioThreatAnalyzer.Info);
        var glitches = s.Issues.Count(i => i.Category == AudioIssueCategories.Glitch);
        IssuesValue.Text = $"{threats} / {glitches}";
        IssuesValue.Foreground = Brush(threats > 0 ? "HudRedBrush" : glitches > 0 ? "HudAmberBrush" : "HudGreenBrush");
        IssuesCaption.Text = "threats / sound problems";
    }

    private void RenderIssues(IReadOnlyList<AudioIssue> issues, AudioSnapshot s)
    {
        IssuesPanel.Children.Clear();
        IssuesEmpty.Visibility = issues.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        foreach (var issue in issues)
        {
            var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 6, 0, 0) };
            foreach (var button in ActionsFor(issue, s)) actions.Children.Add(button);
            var body = new StackPanel { Spacing = 3 };
            body.Children.Add(new TextBlock { Text = issue.Title, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            body.Children.Add(new TextBlock { Text = issue.Detail, FontSize = 12, Foreground = Brush("HudTextDimBrush"), TextWrapping = TextWrapping.Wrap });
            body.Children.Add(new TextBlock { Text = $"{issue.Category} · {issue.Technique}", FontSize = 11, Foreground = Brush("HudTextFaintBrush") });
            if (actions.Children.Count > 0) body.Children.Add(actions);
            IssuesPanel.Children.Add(Card(Chip(issue.Severity == AudioThreatAnalyzer.Info ? "INFO" : issue.Severity, SeverityBrush(issue.Severity)), body, SeverityBrush(issue.Severity)));
        }
    }

    /// <summary>The fixes offered for one issue: brokered actions for the program or file involved, then the right settings page.</summary>
    private IEnumerable<Button> ActionsFor(AudioIssue issue, AudioSnapshot s)
    {
        switch (issue.Category)
        {
            case AudioIssueCategories.Listening:
                var session = s.Sessions.FirstOrDefault(x => x.Flow == AudioFlows.Recording && issue.Indicator == $"listen|{x.ProcessName.ToLowerInvariant()}|{(x.Path ?? "").ToLowerInvariant()}");
                if (session is not null && issue.Severity != AudioThreatAnalyzer.Info)
                {
                    yield return ActionButton("End program", () => EndProgramAsync(session));
                    if (session.Path is { } path) yield return ActionButton("Quarantine program", () => QuarantineAsync(path, session.ProcessName));
                }
                yield return SettingsButton("Microphone privacy", "mic-privacy");
                if (issue.Severity != AudioThreatAnalyzer.Info) yield return SettingsButton("Uninstall apps", "apps");
                break;
            case AudioIssueCategories.Driver:
                var effect = s.Effects.FirstOrDefault(e => issue.Indicator.StartsWith($"apo|{e.Clsid.ToLowerInvariant()}|", StringComparison.Ordinal));
                if (effect?.DllPath is { } dll) yield return ActionButton("Quarantine DLL", () => QuarantineAsync(dll, effect.Name));
                if (issue.Indicator.StartsWith("engine-path|", StringComparison.Ordinal) && s.Posture.AudioEnginePath is { } engine)
                    yield return ActionButton("Quarantine file", () => QuarantineAsync(engine, "audiodg.exe"));
                yield return SettingsButton("Sound devices", "devices");
                break;
            case AudioIssueCategories.Device:
                yield return SettingsButton("Disable in sound devices", "devices");
                if (issue.Detail.Contains("bluetooth", StringComparison.OrdinalIgnoreCase)) yield return SettingsButton("Bluetooth devices", "bluetooth");
                if (issue.Title.StartsWith("Virtual", StringComparison.Ordinal)) yield return SettingsButton("Uninstall apps", "apps");
                break;
            case AudioIssueCategories.Glitch:
                yield return SettingsButton("Audio troubleshooter", "troubleshoot");
                yield return SettingsButton("Sound settings", "sound");
                if (issue.Indicator.EndsWith("|hfp", StringComparison.Ordinal)) yield return SettingsButton("Bluetooth devices", "bluetooth");
                break;
            case AudioIssueCategories.Privacy:
                yield return SettingsButton("Microphone privacy", "mic-privacy");
                break;
        }
        if (issue.Severity != AudioThreatAnalyzer.Info) yield return ActionButton("Review in triage", () => { App.NavigateToRoute("threats"); return Task.CompletedTask; });
    }

    private void RenderSessions(StackPanel panel, TextBlock empty, IReadOnlyList<AudioSession> sessions, bool recording)
    {
        panel.Children.Clear();
        empty.Visibility = sessions.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        foreach (var x in sessions)
        {
            var meter = Meter($"s|{x.Flow}|{x.ProcessId}|{x.Device}", x.Peak, recording ? "HudMagentaBrush" : null);
            var body = new StackPanel { Spacing = 3 };
            body.Children.Add(new TextBlock { Text = $"{x.ProcessName}  ·  PID {x.ProcessId}", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            body.Children.Add(new TextBlock
            {
                Text = $"{x.Device} ({x.DeviceKind}) · {x.State} · {Signature(x.Signed, x.Signer)}{(x.HasWindow ? "" : " · no window")}",
                FontSize = 12, Foreground = Brush("HudTextDimBrush"), TextWrapping = TextWrapping.Wrap,
            });
            if (x.Path is not null) body.Children.Add(new TextBlock { Text = x.Path, FontSize = 11, Foreground = Brush("HudTextFaintBrush"), TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
            body.Children.Add(meter);
            if (recording && x.ProcessId > 4)
            {
                var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
                var row = x;
                actions.Children.Add(ActionButton("End program", () => EndProgramAsync(row)));
                if (x.Path is { } path && !AudioThreatAnalyzer.IsExpectedListener(x.ProcessName))
                    actions.Children.Add(ActionButton("Quarantine program", () => QuarantineAsync(path, row.ProcessName)));
                body.Children.Add(actions);
            }
            var tone = recording ? (x.State == "active" ? "HudMagentaBrush" : "HudStrokeMutedBrush") : "HudCyanBrush";
            panel.Children.Add(Card(Chip(recording ? (x.State == "active" ? "REC" : "OPEN") : "PLAY", Brush(tone)), body, Brush(tone)));
        }
    }

    private void RenderDevices(IReadOnlyList<AudioDevice> devices)
    {
        DevicesPanel.Children.Clear();
        foreach (var d in devices)
        {
            var body = new StackPanel { Spacing = 3 };
            var title = $"{d.Name}{(d.IsDefault ? "  ·  DEFAULT" : "")}{(d.IsNew ? "  ·  NEW" : "")}";
            body.Children.Add(new TextBlock { Text = title, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            var volume = d.VolumePercent is { } v ? $"volume {v}%" : "volume n/a";
            var mute = d.Muted == true ? " · MUTED" : "";
            body.Children.Add(new TextBlock
            {
                Text = $"{(d.Flow == AudioFlows.Recording ? "Recording" : "Playback")} · {d.Kind} · {d.State} · {volume}{mute}{(d.Format is null ? "" : " · " + d.Format)}",
                FontSize = 12, Foreground = Brush("HudTextDimBrush"), TextWrapping = TextWrapping.Wrap,
            });
            if (d.Adapter.Length > 0) body.Children.Add(new TextBlock { Text = d.Adapter, FontSize = 11, Foreground = Brush("HudTextFaintBrush") });
            if (d.State == "active") body.Children.Add(Meter($"d|{d.Id}", d.Peak, d.Flow == AudioFlows.Recording ? "HudMagentaBrush" : null));
            var tone = d.State != "active" ? Brush("HudStrokeMutedBrush")
                : d.Kind is AudioDeviceKinds.Loopback or AudioDeviceKinds.Virtual or AudioDeviceKinds.Network || d.IsNew ? Brush("HudAmberBrush")
                : Brush(d.Flow == AudioFlows.Recording ? "HudMagentaBrush" : "HudCyanBrush");
            DevicesPanel.Children.Add(Card(Chip(d.Flow == AudioFlows.Recording ? "MIC" : "OUT", tone), body, tone));
        }
    }

    private void RenderEffects(IReadOnlyList<AudioEffect> effects)
    {
        EffectsPanel.Children.Clear();
        EffectsEmpty.Visibility = effects.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        var microsoftPanel = new StackPanel { Spacing = 6 };
        foreach (var e in effects)
        {
            var body = new StackPanel { Spacing = 3 };
            body.Children.Add(new TextBlock { Text = e.Name, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            body.Children.Add(new TextBlock { Text = $"{e.DllPath ?? "DLL not found"} · {Signature(e.Signed, e.Signer)}", FontSize = 12, Foreground = Brush("HudTextDimBrush"), TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
            body.Children.Add(new TextBlock { Text = e.Clsid, FontSize = 11, Foreground = Brush("HudTextFaintBrush"), IsTextSelectionEnabled = true });
            if (!e.Microsoft && e.DllPath is { } dll)
            {
                var name = e.Name;
                var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
                actions.Children.Add(ActionButton("Quarantine DLL", () => QuarantineAsync(dll, name)));
                body.Children.Add(actions);
            }
            var tone = Brush(e.Signed == false ? "HudRedBrush" : e.Microsoft ? "HudCyanBrush" : "HudVioletBrush");
            var card = Card(Chip(e.Signed == false ? "UNSIGNED" : e.Microsoft ? "MS" : "VENDOR", tone), body, tone);
            // Microsoft's own signed effects are expected on every PC; keep them folded so vendor and unsigned ones stand out.
            if (e.Microsoft && e.Signed == true) microsoftPanel.Children.Add(card);
            else EffectsPanel.Children.Add(card);
        }
        if (microsoftPanel.Children.Count > 0)
            EffectsPanel.Children.Add(new Expander
            {
                Header = $"{microsoftPanel.Children.Count} Windows audio effects signed by Microsoft",
                Content = microsoftPanel,
                HorizontalAlignment = HorizontalAlignment.Stretch,
                HorizontalContentAlignment = HorizontalAlignment.Stretch,
            });
    }

    private void RenderPosture(AudioPosture p)
    {
        PosturePanel.Children.Clear();
        (string Label, string Value, bool Good)[] lines =
        [
            ("Windows Audio service", p.AudioService, p.AudioService == "Running"),
            ("Audio Endpoint Builder service", p.EndpointBuilder, p.EndpointBuilder == "Running"),
            ("Audio engine (audiodg.exe)", p.AudioEnginePath is null ? "not running (no audio in use)" : $"{p.AudioEnginePath} · {p.AudioEngineInstances} running · {p.AudioEngineCpuPercent:0.0}% CPU",
                p.AudioEnginePath is null || p.AudioEnginePath.EndsWith(@"\System32\audiodg.exe", StringComparison.OrdinalIgnoreCase)),
            ("Audio engine signature", p.AudioEngineSigned switch { true => "Microsoft", false => "FAILED", _ => "not checked" }, p.AudioEngineSigned != false),
            ("Microphone access for apps", p.MicrophoneAccessAllowed switch { true => "On", false => "Off", _ => "Not set" }, true),
            ("Desktop apps may use the microphone", p.DesktopAppsMicrophoneAllowed switch { true => "Yes", false => "No", _ => "Not set" }, true),
            ("Audio errors / warnings (24 h)", $"{p.AudioErrors24h} / {p.AudioWarnings24h}", p.AudioErrors24h == 0),
        ];
        foreach (var (label, value, good) in lines)
        {
            var grid = new Grid { ColumnSpacing = 12 };
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(260) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.Children.Add(new TextBlock { Text = label, FontSize = 12, Foreground = Brush("HudTextDimBrush") });
            var text = new TextBlock { Text = value, FontSize = 12, TextWrapping = TextWrapping.Wrap, Foreground = Brush(good ? "HudTextBrush" : "HudRedBrush"), IsTextSelectionEnabled = true };
            Grid.SetColumn(text, 1);
            grid.Children.Add(text);
            PosturePanel.Children.Add(grid);
        }
    }

    private void UpdateMeters(AudioSnapshot s)
    {
        foreach (var d in s.Devices)
            if (_meters.TryGetValue($"d|{d.Id}", out var bar)) bar.Value = Level(d.Peak);
        foreach (var x in s.Sessions)
            if (_meters.TryGetValue($"s|{x.Flow}|{x.ProcessId}|{x.Device}", out var bar)) bar.Value = Level(x.Peak);
    }

    /// <summary>Perceptual level: peaks are linear amplitude, so a square root makes quiet speech visible.</summary>
    private static double Level(double peak) => Math.Sqrt(Math.Clamp(peak, 0, 1)) * 100;

    private ProgressBar Meter(string key, double peak, string? brush)
    {
        var bar = new ProgressBar { Maximum = 100, Value = Level(peak), Style = (Style)Application.Current.Resources["HudMeterStyle"], Margin = new Thickness(0, 4, 0, 0) };
        if (brush is not null) bar.Foreground = Brush(brush);
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(bar, "Live audio level");
        _meters[key] = bar;
        return bar;
    }

    private async Task EndProgramAsync(AudioSession session)
    {
        DateTimeOffset started;
        try
        {
            using var process = Process.GetProcessById(session.ProcessId);
            started = process.StartTime.ToUniversalTime();
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            await ShowAsync("Program already closed", $"{session.ProcessName} (PID {session.ProcessId}) is no longer running.");
            return;
        }

        var client = new ProcessTerminationClient();
        var preview = await client.PreviewTerminateAsync(session.ProcessId, started);
        if (preview is null)
        {
            await App.EnsureSensorServiceAsync();
            preview = await client.PreviewTerminateAsync(session.ProcessId, started);
        }
        if (preview is null) { await ShowAsync("Action broker unreachable", "Ending a program needs the local Downpour service."); return; }
        if (!preview.Accepted || preview.Preview is not { ConsentToken: not null } p)
        {
            await ShowAsync("Ending this program is not allowed", preview.Message + Environment.NewLine + Environment.NewLine + "Turn on “Allow process termination” in Settings to permit it.");
            return;
        }
        var text = $"End {p.ProcessName} (PID {p.ProcessId})?\n\nImage: {p.ImagePath}\nIt is receiving audio from {session.Device}.\n\nExpected effects:\n• {string.Join("\n• ", p.ExpectedEffects)}\n\nRisks:\n• {string.Join("\n• ", p.Risks)}\n\nUnsaved work in the program will be lost. The action is written to the audit log.";
        if (!await ConfirmAsync("Confirm end program", text, "End program")) return;
        var result = await client.TerminateAsync(session.ProcessId, started, p.ConsentToken);
        await ShowAsync(result?.Accepted == true ? "Program ended" : "Program was not ended", result?.Message ?? "The action broker did not confirm the action.");
        _structure = "";
    }

    private async Task QuarantineAsync(string path, string label)
    {
        var client = new QuarantineClient();
        var preview = await client.PreviewQuarantineAsync(path);
        if (preview is null)
        {
            await App.EnsureSensorServiceAsync();
            preview = await client.PreviewQuarantineAsync(path);
        }
        if (preview is null) { await ShowAsync("Action broker unreachable", "Quarantine needs the local Downpour service."); return; }
        if (!preview.Accepted || preview.Preview is not { ConsentToken: not null } p)
        {
            await ShowAsync("Quarantine is not allowed for this file", preview.Message + Environment.NewLine + Environment.NewLine + "Turn on “Allow quarantine actions” in Settings to permit it; Windows system files are always protected.");
            return;
        }
        var text = $"Quarantine {label}?\n\n{p.TargetPath}\n{p.Size:N0} bytes · SHA-256 {p.Sha256}\n\nThe file is encrypted into Downpour's quarantine and removed from its folder. A program or audio effect that needs it will stop working until it is restored from Remediation. If the file is in use, end the program first or restart and try again.";
        if (!await ConfirmAsync("Confirm quarantine", text, "Quarantine")) return;
        var result = await client.QuarantineAsync(p.TargetPath, p.ConsentToken);
        await ShowAsync(result?.Accepted == true ? "Quarantined" : "Not quarantined", result?.Message ?? "The action broker did not confirm the action.");
        _structure = "";
    }

    private Button ActionButton(string text, Func<Task> action)
    {
        var button = new Button { Content = text, FontSize = 12, Padding = new Thickness(10, 4, 10, 4) };
        button.Click += async (_, _) =>
        {
            button.IsEnabled = false;
            try { await action(); }
            catch (Exception ex) when (ex is IOException or InvalidOperationException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
            {
                await ShowAsync("The action could not run", ex.Message);
            }
            finally { button.IsEnabled = true; }
        };
        return button;
    }

    private Button SettingsButton(string text, string page) => ActionButton(text, () => OpenSettingsAsync(page));

    private async Task ShowAsync(string title, string message)
    {
        if (XamlRoot is null) return;
        await new ContentDialog { Title = title, Content = new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap }, CloseButtonText = "OK", XamlRoot = XamlRoot }.ShowAsync();
    }

    private async Task<bool> ConfirmAsync(string title, string message, string primary)
    {
        if (XamlRoot is null) return false;
        var dialog = new ContentDialog
        {
            Title = title,
            Content = new ScrollViewer { Content = new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true }, MaxHeight = 420 },
            PrimaryButtonText = primary,
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = XamlRoot,
        };
        return await dialog.ShowAsync() == ContentDialogResult.Primary;
    }

    private static string Signature(bool? signed, string? signer) => signed switch
    {
        true => $"signed by {PersistenceAnalyzer.SignerDisplay(signer)}",
        false => "NOT validly signed",
        _ => "signature not checked",
    };

    private static Border Card(UIElement chip, UIElement body, Brush edge)
    {
        var grid = new Grid { ColumnSpacing = 14 };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.Children.Add(chip);
        Grid.SetColumn((FrameworkElement)body, 1);
        grid.Children.Add(body);
        return new Border
        {
            Padding = new Thickness(14, 10, 14, 10),
            CornerRadius = new CornerRadius(8),
            BorderThickness = new Thickness(3, 1, 1, 1),
            BorderBrush = edge,
            Background = Brush("HudPanelBrush"),
            Child = grid,
        };
    }

    private static Border Chip(string text, Brush brush) => new()
    {
        Padding = new Thickness(8, 3, 8, 3),
        CornerRadius = new CornerRadius(4),
        BorderThickness = new Thickness(1),
        BorderBrush = brush,
        VerticalAlignment = VerticalAlignment.Top,
        MinWidth = 64,
        Child = new TextBlock { Text = text, FontSize = 11, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, Foreground = brush, HorizontalAlignment = HorizontalAlignment.Center },
    };

    private static Brush SeverityBrush(string severity) => Brush(severity switch
    {
        "CRITICAL" => "HudRedBrush",
        "HIGH" => "HudOrangeBrush",
        "MEDIUM" => "HudAmberBrush",
        "LOW" => "HudBlueBrush",
        _ => "HudTextFaintBrush",
    });

    private static Brush Brush(string key) => (Brush)Application.Current.Resources[key];
}
