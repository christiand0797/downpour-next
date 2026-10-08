using System.Text;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;
using Windows.UI;

namespace Downpour_Desktop.Pages;

public sealed class ThreatMatchRow
{
    public required string Severity { get; init; }
    public required string Title { get; init; }
    public required string Subject { get; init; }
    public required string Detail { get; init; }
    public required string When { get; init; }
    public required Brush SeverityBrush { get; init; }
    public required Brush SeverityTint { get; init; }
}

public sealed class ConnectionRow
{
    public required string Program { get; init; }
    public required string Pid { get; init; }
    public required string Endpoint { get; init; }
    public required string Country { get; init; }
    public required string Network { get; init; }
    public required Brush MarkerBrush { get; init; }
}

public sealed class FeedRow
{
    public required string Name { get; init; }
    public required string Provider { get; init; }
    public required string State { get; init; }
    public required string Entries { get; init; }
    public required string Purpose { get; init; }
    public required string Updated { get; init; }
    public required Brush StateBrush { get; init; }
    public required Brush StateTint { get; init; }
}

public sealed partial class ThreatDatabasesPage : Page
{
    private readonly ThreatDatabaseClient _client = new();
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly CircularGauge _coverage = new("ONLINE", Color.FromArgb(255, 0, 229, 255));
    private CancellationTokenSource _lifetime = new();
    private ThreatDatabaseSnapshot? _snapshot;
    private bool _refreshing;

    public ThreatDatabasesPage()
    {
        InitializeComponent();
        CoverageGaugeHost.Content = _coverage;
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        _timer.Tick += async (_, _) => await RefreshAsync();
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (_lifetime.IsCancellationRequested) { _lifetime.Dispose(); _lifetime = new(); }
        _timer.Start();
        await RefreshAsync();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        _timer.Stop();
        _lifetime.Cancel();
    }

    private async Task RefreshAsync()
    {
        if (_refreshing || _lifetime.IsCancellationRequested) return;
        _refreshing = true;
        var token = _lifetime.Token;
        try
        {
            await App.EnsureSensorServiceAsync();
            var response = await _client.GetSnapshotAsync(token);
            if (token.IsCancellationRequested) return;
            if (response?.Snapshot is not { } snapshot)
            {
                Show(InfoBarSeverity.Warning, "Threat databases unavailable", _client.FailureMessage + " Values below may be out of date.");
                return;
            }
            _snapshot = snapshot;
            Render(snapshot);
        }
        catch (OperationCanceledException) { }
        finally { _refreshing = false; }
    }

    private void Render(ThreatDatabaseSnapshot s)
    {
        var scoring = s.Feeds.Where(f => f.Kind != ThreatFeedKinds.Geo).ToArray();
        var online = scoring.Count(f => f.State is ThreatFeedStates.Current or ThreatFeedStates.Stale or ThreatFeedStates.Updating && f.Entries > 0);
        _coverage.SetMetric(scoring.Length == 0 ? null : 100d * online / scoring.Length, $"{online}/{scoring.Length}");
        IndicatorsText.Text = s.TotalIndicators.ToString("N0");
        var origin = s.Feeds.FirstOrDefault(f => f.Kind == ThreatFeedKinds.Geo);
        OriginsText.Text = origin is { Entries: > 0 } ? $"+ {origin.Entries:N0} origin ranges" : "Origin database not loaded yet";

        var serious = s.Matches.Count(m => m.Severity is "CRITICAL" or "HIGH");
        MatchesText.Text = s.Matches.Count.ToString("N0");
        MatchesText.Foreground = s.Matches.Count == 0 ? Brush("HudGreenBrush") : serious > 0 ? Brush("HudRedBrush") : Brush("HudAmberBrush");
        MatchesDetail.Text = s.Matches.Count == 0 ? "Clean against every loaded list" : $"{serious} high or critical";
        MatchesCard.Style = (Style)Application.Current.Resources[serious > 0 ? "HudAlertCardStyle" : "HudCardStyle"];

        ConnectionsText.Text = s.Coverage.ConnectionsChecked.ToString("N0");
        DomainsText.Text = $"{s.Coverage.DomainsChecked:N0} DNS names checked";
        FilesText.Text = (s.Coverage.DriversHashed + s.Coverage.ProgramsHashed).ToString("N0");
        FilesDetail.Text = $"{s.Coverage.DriversHashed:N0} drivers · {s.Coverage.ProgramsHashed:N0} programs";
        SweepText.Text = s.Coverage.LastSweepUtc is { } sweep ? sweep.ToLocalTime().ToString("HH:mm:ss") : "pending";
        SweepDetail.Text = s.Coverage.LastSweepDuration is { } took ? $"took {took.TotalSeconds:0.0} s · repeats every 5 min" : "first sweep is running";

        MatchesEmpty.Visibility = s.Matches.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        LiveList.Set(MatchList, s.Matches.Select(m => new ThreatMatchRow
        {
            Severity = m.Severity,
            Title = $"{ThreatVerdicts.Label(m.Verdict)} · {m.Confidence}% confidence · {m.Label} · {m.Where}",
            Subject = m.Subject,
            Detail = string.Join(Environment.NewLine, (m.Reasons ?? []).Select(r => "• " + r)
                .Append($"Indicator {m.Indicator} · MITRE {m.Technique}")),
            When = m.SeenAtUtc.ToLocalTime().ToString("MMM d HH:mm"),
            SeverityBrush = SeverityBrush(m.Severity),
            SeverityTint = SeverityTint(m.Severity),
        }).ToArray());

        ConnectionsEmpty.Visibility = s.Connections.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        LiveList.Set(ConnectionList, s.Connections.Select(c => new ConnectionRow
        {
            Program = c.Program,
            Pid = $"PID {c.ProcessId}{(c.Listed ? " · LISTED IN A THREAT DATABASE" : "")}",
            Endpoint = c.RemoteAddress.Contains(':') ? $"[{c.RemoteAddress}]:{c.RemotePort}" : $"{c.RemoteAddress}:{c.RemotePort}",
            Country = c.CountryCode is { } code ? $"{IpOriginDatabase.CountryName(code)} ({code})" : "Origin unknown",
            Network = c.Asn is { } asn ? $"AS{asn} · {c.Network}" : c.Network ?? "",
            MarkerBrush = c.Listed ? Brush("HudRedBrush") : Brush("HudCyanBrush"),
        }).ToArray());

        LiveList.Set(FeedRepeater, s.Feeds.Select(f => new FeedRow
        {
            Name = f.Name,
            Provider = $"{f.Provider} · {f.License}".ToUpperInvariant(),
            State = f.State.Replace('-', ' ').ToUpperInvariant(),
            Entries = f.Entries > 0 ? $"{f.Entries:N0} {(f.Kind == ThreatFeedKinds.Geo ? "ranges" : "entries")}" : "—",
            Purpose = f.Purpose,
            Updated = f.Error is { } error ? $"Problem: {error}" :
                f.RetrievedAtUtc is { } at ? $"Updated {Age(s.CapturedAtUtc - at)} ago · {f.Bytes / 1024d:N0} KB" : "Not downloaded yet",
            StateBrush = StateBrush(f.State),
            StateTint = StateTint(f.State),
        }).ToArray());

        LiveList.Set(LolbinList, s.Lolbins.Count == 0
            ? new[] { "None of the catalogued built-in tools are running." }
            : s.Lolbins.Select(l => $"{l.Name} ×{l.Instances} — can be used for: {l.Categories} ({l.Techniques})").ToArray());
        WarningsText.Text = string.Join(Environment.NewLine, s.Warnings);
        ReportButton.IsEnabled = true;
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        RefreshButton.IsEnabled = false;
        try
        {
            var response = await _client.RefreshAsync(_lifetime.Token);
            switch (response?.ResultCode)
            {
                case "refresh-started": Show(InfoBarSeverity.Informational, "Updating", "Out-of-date databases are downloading in the background. This page refreshes on its own."); break;
                case "cooldown": Show(InfoBarSeverity.Informational, "Already updated recently", "Try again in a couple of minutes."); break;
                case "disabled": Show(InfoBarSeverity.Warning, "Updates are switched off", "Turn on threat database updates in Settings to download new data."); break;
                default: Show(InfoBarSeverity.Error, "Update not started", response is null ? _client.FailureMessage : "The local sensor service did not accept the request."); break;
            }
            if (response?.Snapshot is { } snapshot) { _snapshot = snapshot; Render(snapshot); }
        }
        catch (OperationCanceledException) { }
        finally { RefreshButton.IsEnabled = true; }
    }

    private void LookupBox_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == Windows.System.VirtualKey.Enter) Lookup_Click(sender, e);
    }

    private async void Lookup_Click(object sender, RoutedEventArgs e)
    {
        var value = LookupBox.Text.Trim();
        if (value.Length == 0) return;
        LookupResult.Text = "Checking…";
        LookupResult.Foreground = Brush("HudTextDimBrush");
        try
        {
            var response = await _client.LookupAsync(value, _lifetime.Token);
            if (response is null) { LookupResult.Text = _client.FailureMessage; return; }
            if (!response.Accepted)
            {
                LookupResult.Text = "That doesn't look like an IP address, website, link or file hash.";
                return;
            }
            var text = new StringBuilder();
            var hits = response.LookupHits ?? [];
            text.Append(hits.Count == 0 ? $"{response.LookupValue} is not in any loaded database." : $"{response.LookupValue} is listed by {hits.Count} database{(hits.Count == 1 ? "" : "s")}:");
            foreach (var hit in hits) text.Append($"{Environment.NewLine}  • {hit.FeedName}: {hit.Label}");
            if (response.LookupOrigin is { } origin)
                text.Append($"{Environment.NewLine}Origin: {(origin.CountryCode is { } c ? $"{IpOriginDatabase.CountryName(c)} ({c})" : "unknown country")}" +
                            $"{(origin.Asn is { } asn ? $" · AS{asn} {origin.Network}" : " · not a routed public network")}");
            LookupResult.Text = text.ToString();
            LookupResult.Foreground = hits.Count > 0 ? Brush("HudRedBrush") : Brush("HudGreenBrush");
        }
        catch (OperationCanceledException) { }
    }

    private async void ExportCase_Click(object sender, RoutedEventArgs e) => await CaseFileExporter.ExportFromAsync(ExportCaseButton);

    private void Report_Click(object sender, RoutedEventArgs e)
    {
        if (_snapshot is not { } s) return;
        var report = new StringBuilder();
        report.AppendLine("Downpour Next — threat database evidence report");
        report.AppendLine($"Created: {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}  (snapshot {s.CapturedAtUtc:u})");
        report.AppendLine($"Computer: {Environment.MachineName}");
        report.AppendLine($"Indicators loaded: {s.TotalIndicators:N0}; last sweep: {s.Coverage.LastSweepUtc?.ToString("u") ?? "pending"}");
        report.AppendLine();
        report.AppendLine($"MATCHES ({s.Matches.Count})");
        foreach (var m in s.Matches)
        {
            report.AppendLine($"{m.SeenAtUtc:u}  {m.Severity,-8} {ThreatVerdicts.Label(m.Verdict)} ({m.Confidence}%) {m.Where}: {m.Subject} | {m.FeedName}: {m.Label} | indicator {m.Indicator} | {m.Technique}");
            foreach (var reason in m.Reasons ?? []) report.AppendLine($"    - {reason}");
        }
        report.AppendLine();
        report.AppendLine($"CONNECTIONS AT LAST SWEEP ({s.Connections.Count})");
        foreach (var c in s.Connections)
            report.AppendLine($"{c.Program} (PID {c.ProcessId}) -> {c.RemoteAddress}:{c.RemotePort}  {c.CountryCode ?? "??"}  {(c.Asn is { } a ? $"AS{a} {c.Network}" : "")}{(c.Listed ? "  [LISTED]" : "")}");
        report.AppendLine();
        report.AppendLine("Sources: " + string.Join("; ", s.Feeds.Where(f => f.RetrievedAtUtc is not null).Select(f => $"{f.Name} ({f.Provider}, {f.RetrievedAtUtc:u})")));
        report.AppendLine("Origins show where an address block is registered and which network runs it. They do not identify or locate a person.");
        var data = new DataPackage();
        data.SetText(report.ToString());
        Clipboard.SetContent(data);
        Show(InfoBarSeverity.Success, "Evidence report copied", "Paste it into a document or email to keep a dated record. It contains program names and addresses from this PC.");
    }

    private void Show(InfoBarSeverity severity, string title, string message)
    {
        StatusBar.Severity = severity;
        StatusBar.Title = title;
        StatusBar.Message = message;
        StatusBar.IsOpen = true;
    }

    private static string Age(TimeSpan age) =>
        age.TotalMinutes < 1 ? "moments" : age.TotalHours < 1 ? $"{age.TotalMinutes:0} min" : age.TotalDays < 1 ? $"{age.TotalHours:0} h" : $"{age.TotalDays:0} d";

    private static Brush Brush(string key) => (Brush)Application.Current.Resources[key];

    private static Brush SeverityBrush(string severity) => Brush(severity switch
    {
        "CRITICAL" => "HudRedBrush", "HIGH" => "HudOrangeBrush", "MEDIUM" => "HudAmberBrush", _ => "HudCyanBrush",
    });

    private static Brush SeverityTint(string severity) => Brush(severity switch
    {
        "CRITICAL" => "HudRedTintBrush", "HIGH" => "HudOrangeTintBrush", "MEDIUM" => "HudAmberTintBrush", _ => "HudCyanTintBrush",
    });

    private static Brush StateBrush(string state) => Brush(state switch
    {
        ThreatFeedStates.Current => "HudGreenBrush", ThreatFeedStates.Updating => "HudCyanBrush", ThreatFeedStates.Stale => "HudAmberBrush",
        ThreatFeedStates.Failed => "HudRedBrush", _ => "HudTextFaintBrush",
    });

    private static Brush StateTint(string state) => Brush(state switch
    {
        ThreatFeedStates.Current => "HudGreenTintBrush", ThreatFeedStates.Updating => "HudCyanTintBrush", ThreatFeedStates.Stale => "HudAmberTintBrush",
        ThreatFeedStates.Failed => "HudRedTintBrush", _ => "HudCyanTintBrush",
    });
}
