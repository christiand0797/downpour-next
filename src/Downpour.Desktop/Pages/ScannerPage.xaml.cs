using Downpour.Core;
using Microsoft.UI.Xaml.Controls;
using System.Runtime.InteropServices;
using Windows.Storage.Pickers;

namespace Downpour_Desktop.Pages;

public sealed partial class ScannerPage : Page
{
    private bool _busy;

    public ScannerPage() => InitializeComponent();

    private async void ChooseFile_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (_busy) return;
        Windows.Storage.StorageFile? file;
        try
        {
            var picker = new FileOpenPicker();
            picker.FileTypeFilter.Add(".exe");
            picker.FileTypeFilter.Add(".dll");
            picker.FileTypeFilter.Add(".sys");
            WinRT.Interop.InitializeWithWindow.Initialize(picker, App.MainWindowHandle);
            file = await picker.PickSingleFileAsync();
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException or UnauthorizedAccessException)
        {
            InspectionStatus.Text = $"The file picker could not be opened: {exception.Message}";
            return;
        }
        if (file is null) return;

        _busy = true;
        ChooseFileButton.IsEnabled = false;
        InspectionProgress.IsActive = true;
        ResultCard.Visibility = Microsoft.UI.Xaml.Visibility.Collapsed;
        InspectionStatus.Text = "Reading and hashing the selected file…";
        try
        {
            var filePath = file.Path;
            var inspection = await Task.Run(() =>
            {
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024,
                    FileOptions.SequentialScan);
                return StaticFileInspector.Inspect(stream, file.Name);
            });
            FileNameText.Text = inspection.FileName;
            FileSizeText.Text = $"{inspection.FileSize:N0} bytes ({inspection.FileSize / 1024d / 1024d:F2} MiB)";
            HashText.Text = inspection.Sha256;
            FormatText.Text = inspection.IsPortableExecutable ? "Windows Portable Executable (PE)" : "Not recognized as a PE image";
            PeDetailsText.Text = inspection.IsPortableExecutable
                ? $"{inspection.Architecture} · {inspection.SectionCount} sections · {inspection.WritableExecutableSectionCount} writable + executable sections · " +
                  (inspection.PeTimestampUtc is { } timestamp ? $"header timestamp {timestamp:yyyy-MM-dd HH:mm:ss} UTC" : "no PE timestamp")
                : "No supported PE headers were present. SHA-256 was still calculated.";
            CertificateText.Text = inspection.IsPortableExecutable
                ? inspection.HasAuthenticodeCertificateTable ? "Present (not verified)" : "Not present (not a trust verdict)"
                : "Not applicable";
            ResultCard.Visibility = Microsoft.UI.Xaml.Visibility.Visible;
            InspectionStatus.Text = "Static inspection complete. No safe/malicious verdict was produced.";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException)
        {
            InspectionStatus.Text = $"Inspection failed: {exception.Message}";
        }
        finally
        {
            InspectionProgress.IsActive = false;
            ChooseFileButton.IsEnabled = true;
            _busy = false;
        }
    }
}
