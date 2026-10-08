using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using Downpour.Contracts;
using Downpour.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.Win32.SafeHandles;
using Windows.ApplicationModel.DataTransfer;

namespace Downpour_Desktop;

public sealed record DetailField(string Label, string Value);

/// <summary>
/// Something a row is about: its fields, plus what it refers to (a file, a running process, an IP address or a domain),
/// which decides the extra information and the actions offered.
/// </summary>
public sealed record DetailEntity(
    string Title,
    string? Subtitle,
    IReadOnlyList<DetailField> Fields,
    string? FilePath = null,
    int? ProcessId = null,
    string? Address = null,
    string? Domain = null,
    string? Kind = null);

/// <summary>
/// Makes rows clickable everywhere (owner request): click for a details window (all fields, then on-demand extra
/// information: file hash and headers, local threat-database matches, IP origin), right-click for a menu of fitting
/// actions. Lookups use the local threat databases only; nothing is sent online. Changes (end process, quarantine,
/// block address) go through the existing previewed, confirmed and audited brokers.
/// </summary>
public static class EntityDetails
{
    /// <summary>Wires a list: item click opens details, right-click opens the action menu.</summary>
    public static void Attach(ListViewBase list, Func<object, DetailEntity?> describe)
    {
        list.IsItemClickEnabled = true;
        list.ItemClick += async (_, e) =>
        {
            if (e.ClickedItem is { } item && describe(item) is { } entity && list.XamlRoot is { } root) await ShowAsync(root, entity);
        };
        list.RightTapped += (_, e) =>
        {
            if ((e.OriginalSource as FrameworkElement)?.DataContext is not { } item || describe(item) is not { } entity) return;
            Menu(entity, list.XamlRoot).ShowAt(list, new FlyoutShowOptions { Position = e.GetPosition(list) });
            e.Handled = true;
        };
    }

    /// <summary>Wires any element (cards built in code): click for details, right-click for actions.</summary>
    public static void Attach(FrameworkElement element, DetailEntity entity)
    {
        element.Tapped += async (_, e) =>
        {
            if (e.OriginalSource is FrameworkElement { } source && IsInsideButton(source, element)) return;
            if (element.XamlRoot is { } root) await ShowAsync(root, entity);
        };
        element.RightTapped += (_, e) =>
        {
            Menu(entity, element.XamlRoot).ShowAt(element, new FlyoutShowOptions { Position = e.GetPosition(element) });
            e.Handled = true;
        };
        ToolTipService.SetToolTip(element, "Click for details · right-click for actions");
    }

    private static bool IsInsideButton(DependencyObject source, FrameworkElement stop)
    {
        for (var node = source; node is not null && !ReferenceEquals(node, stop); node = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetParent(node))
            if (node is ButtonBase) return true;
        return false;
    }

    public static MenuFlyout Menu(DetailEntity entity, XamlRoot? root)
    {
        var menu = new MenuFlyout();
        void Add(string text, string glyph, Func<Task> run) =>
            menu.Items.Add(Item(text, glyph, run));
        if (root is not null) Add("Details…", "", () => ShowAsync(root, entity));
        foreach (var (text, glyph, run) in Actions(entity, root)) Add(text, glyph, run);
        menu.Items.Add(new MenuFlyoutSeparator());
        Add("Copy all details", "", () => { Copy(Describe(entity)); return Task.CompletedTask; });
        foreach (var field in entity.Fields.Where(f => f.Value.Length is > 0 and <= 400).Take(6))
            Add($"Copy {field.Label}", "", () => { Copy(field.Value); return Task.CompletedTask; });
        return menu;
    }

    private static MenuFlyoutItem Item(string text, string glyph, Func<Task> run)
    {
        var item = new MenuFlyoutItem { Text = text, Icon = new FontIcon { Glyph = glyph } };
        item.Click += async (_, _) => await run();
        return item;
    }

    /// <summary>The actions that fit what the entity refers to.</summary>
    private static IEnumerable<(string Text, string Glyph, Func<Task> Run)> Actions(DetailEntity entity, XamlRoot? root)
    {
        var path = ResolvePath(entity);
        if (path is not null)
        {
            yield return ("Open file location", "", () => { OpenLocation(path); return Task.CompletedTask; });
            yield return ("File properties", "", () => { ShowProperties(path); return Task.CompletedTask; });
            yield return ("Scan with YARA", "", () => ScanAsync(root, path));
        }
        if (entity.ProcessId is { } pid && pid > 4 && root is not null)
            yield return ("End process…", "", () => ActionFlows.EndProcessAsync(root, pid, entity.Title));
        if (path is not null && root is not null)
            yield return ("Quarantine file…", "", () => ActionFlows.QuarantineAsync(root, path, entity.Title));
        if (entity.Address is { } ip && IPAddress.TryParse(ip, out var parsed) && !ThreatFeedParser.IsReserved(parsed) && root is not null)
            yield return ("Block this address…", "", () => ActionFlows.BlockIpAsync(root, ip, entity.Title));
    }

    /// <summary>The details window: fields first, then extra information gathered on demand, then actions.</summary>
    public static async Task ShowAsync(XamlRoot root, DetailEntity entity)
    {
        var fields = new Grid { ColumnSpacing = 14, RowSpacing = 6 };
        fields.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(150) });
        fields.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        var row = 0;
        void AddField(string label, string value)
        {
            fields.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var name = new TextBlock { Text = label, FontSize = 12, Foreground = HudPalette.Resource("HudTextDimBrush"), TextWrapping = TextWrapping.Wrap };
            var text = new TextBlock { Text = value.Length == 0 ? "—" : value, FontSize = 12, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true };
            Grid.SetRow(name, row);
            Grid.SetRow(text, row);
            Grid.SetColumn(text, 1);
            fields.Children.Add(name);
            fields.Children.Add(text);
            row++;
        }
        foreach (var field in entity.Fields) AddField(field.Label, field.Value);

        var more = new StackPanel { Spacing = 6 };
        more.Children.Add(new TextBlock { Text = "MORE INFORMATION", FontSize = 11, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, CharacterSpacing = 120, Foreground = HudPalette.Resource("HudTextDimBrush") });
        var progress = new ProgressRing { IsActive = true, Width = 20, Height = 20, HorizontalAlignment = HorizontalAlignment.Left };
        more.Children.Add(progress);

        // Buttons wrap onto rows of four so none are cut off.
        var actions = new StackPanel { Spacing = 8 };
        StackPanel? actionRow = null;
        void AddAction(Button button)
        {
            if (actionRow is null || actionRow.Children.Count == 4)
            {
                actionRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
                actions.Children.Add(actionRow);
            }
            actionRow.Children.Add(button);
        }
        Func<Task>? pending = null;
        ContentDialog? dialogRef = null;
        foreach (var (text, _, run) in Actions(entity, root).Take(5))
        {
            var button = new Button { Content = text, FontSize = 12 };
            button.Click += (_, _) => { pending = run; dialogRef?.Hide(); };
            AddAction(button);
        }
        var copy = new Button { Content = "Copy all", FontSize = 12 };
        copy.Click += (_, _) => Copy(Describe(entity));
        AddAction(copy);

        var body = new StackPanel { Spacing = 14, MinWidth = 560 };
        if (entity.Subtitle is { Length: > 0 } subtitle)
            body.Children.Add(new TextBlock { Text = subtitle, FontSize = 12, Foreground = HudPalette.Resource("HudTextDimBrush"), TextWrapping = TextWrapping.Wrap });
        body.Children.Add(fields);
        body.Children.Add(more);
        body.Children.Add(actions);

        var dialog = new ContentDialog
        {
            Title = entity.Title,
            Content = new ScrollViewer { Content = body, MaxHeight = 560 },
            CloseButtonText = "Close",
            XamlRoot = root,
        };
        dialog.Resources["ContentDialogMaxWidth"] = 900.0;
        dialogRef = dialog;
        var shown = dialog.ShowAsync();
        try
        {
            foreach (var line in await Task.Run(() => EnrichAsync(entity)))
                more.Children.Add(new TextBlock { Text = line, FontSize = 12, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            more.Children.Add(new TextBlock { Text = $"Extra information is unavailable ({ex.GetType().Name}).", FontSize = 12 });
        }
        finally
        {
            progress.IsActive = false;
            progress.Visibility = Visibility.Collapsed;
        }
        await shown;
        if (pending is not null) await pending();
    }

    /// <summary>Extra facts, gathered locally: process start and file, file hash and headers, local database matches, IP origin.</summary>
    private static async Task<IReadOnlyList<string>> EnrichAsync(DetailEntity entity)
    {
        var lines = new List<string>();
        var databases = new ThreatDatabaseClient();
        if (entity.ProcessId is { } pid && pid > 4)
        {
            try
            {
                using var process = Process.GetProcessById(pid);
                lines.Add($"Running since {process.StartTime:g} · {process.Threads.Count} threads · {process.WorkingSet64 / 1048576.0:0.#} MB in memory");
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                lines.Add("The process is no longer running or its details are protected.");
            }
        }
        var path = ResolvePath(entity);
        if (path is not null)
        {
            var info = new FileInfo(path);
            lines.Add($"File: {path}");
            lines.Add($"Size {info.Length / 1024.0:N0} KB · modified {info.LastWriteTime:g} · created {info.CreationTime:g}");
            if (info.Length <= StaticFileInspector.MaximumFileSize)
            {
                try
                {
                    await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    var inspection = StaticFileInspector.Inspect(stream, Path.GetFileName(path));
                    lines.Add($"SHA-256 {inspection.Sha256}");
                    if (inspection.IsPortableExecutable)
                        lines.Add($"Program file ({inspection.Architecture}), {inspection.SectionCount} sections{(inspection.WritableExecutableSectionCount > 0 ? $", {inspection.WritableExecutableSectionCount} writable+executable (unusual, packers and some malware)" : "")}, "
                            + (inspection.HasAuthenticodeCertificateTable ? "has an embedded signature block" : "no embedded signature block (may be catalog-signed or unsigned)")
                            + (inspection.PeTimestampUtc is { } built ? $", built {built:yyyy-MM-dd}" : ""));
                    lines.Add(await DatabaseLine(databases, inspection.Sha256, "This file's hash"));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
                {
                    lines.Add($"The file could not be read for hashing ({ex.GetType().Name}).");
                }
            }
        }
        if (entity.Address is { } ip)
        {
            var reply = await databases.LookupAsync(ip);
            if (reply?.LookupOrigin is { } origin)
                lines.Add($"Origin: {IpOriginDatabase.CountryName(origin.CountryCode)}{(origin.Asn is { } asn ? $" · AS{asn} {origin.Network}" : "")} (approximate; this is the network's registration, not a person's location)");
            lines.Add(DatabaseResult(reply, $"{ip}"));
        }
        if (entity.Domain is { } domain)
            lines.Add(DatabaseResult(await databases.LookupAsync(domain), domain));
        if (lines.Count == 0) lines.Add("No extra information applies to this item.");
        return lines;
    }

    private static async Task<string> DatabaseLine(ThreatDatabaseClient client, string value, string subject) =>
        DatabaseResult(await client.LookupAsync(value), subject);

    private static string DatabaseResult(ThreatDatabaseResponse? reply, string subject) => reply switch
    {
        null => "Threat databases: the sensor service did not answer.",
        { LookupHits: { Count: > 0 } hits } => $"⚠ {subject} is listed in {hits.Count} threat database{(hits.Count == 1 ? "" : "s")}: {string.Join("; ", hits.Select(h => $"{h.FeedName} ({h.Label})"))}.",
        { Accepted: true } => $"{subject} is not listed in any of the local threat databases.",
        _ => $"{subject} could not be checked against the threat databases.",
    };

    /// <summary>A fully qualified local file that exists: the entity's file, or the running process's image.</summary>
    public static string? ResolvePath(DetailEntity entity)
    {
        var candidate = entity.FilePath;
        if (candidate is null && entity.ProcessId is { } pid && pid > 4) candidate = ProcessImage(pid);
        if (string.IsNullOrWhiteSpace(candidate)) return null;
        candidate = Environment.ExpandEnvironmentVariables(PersistenceAnalyzer.CommandTarget(candidate.Replace(@"\??\", "")) ?? candidate);
        if (candidate.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            candidate = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), candidate[12..]);
        try
        {
            if (!Path.IsPathFullyQualified(candidate) || candidate.StartsWith(@"\\", StringComparison.Ordinal) || candidate.Contains('"')) return null;
            var full = Path.GetFullPath(candidate);
            return File.Exists(full) ? full : null;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
    }

    public static string? ProcessImage(int pid)
    {
        using var handle = OpenProcess(0x1000, false, (uint)pid);
        if (handle.IsInvalid) return null;
        var buffer = new char[1024];
        var size = (uint)buffer.Length;
        return QueryFullProcessImageNameW(handle, 0, buffer, ref size) && size > 0 ? new string(buffer, 0, (int)size) : null;
    }

    /// <summary>Explorer with the file selected; the path was validated as an existing local file without quotes.</summary>
    private static void OpenLocation(string path)
    {
        try { Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = false })?.Dispose(); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException) { }
    }

    private static void ShowProperties(string path) => SHObjectProperties(IntPtr.Zero, 0x2 /* SHOP_FILEPATH */, path, null);

    private static async Task ScanAsync(XamlRoot? root, string path)
    {
        var reply = await new YaraScanClient().StartAsync(path, recursive: false, skipMicrosoftSigned: false);
        if (root is null) return;
        var open = await ActionFlows.ConfirmAsync(root, reply?.Accepted == true ? "Scan started" : "Scan not started",
            (reply?.Message ?? "The scanner did not answer.") + (reply?.Accepted == true ? "\n\nMatches appear on the Scanner page and in Triage." : ""), "Open Scanner");
        if (open) App.NavigateToRoute("scanner");
    }

    public static string Describe(DetailEntity entity) =>
        string.Join(Environment.NewLine, new[] { entity.Title, entity.Subtitle ?? "" }.Where(t => t.Length > 0)
            .Concat(entity.Fields.Select(f => $"{f.Label}: {f.Value}")));

    public static void Copy(string text)
    {
        var package = new DataPackage();
        package.SetText(text);
        Clipboard.SetContent(package);
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SHObjectProperties(IntPtr hwnd, uint type, string name, string? page);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, uint processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, [Out] char[] name, ref uint size);
}
