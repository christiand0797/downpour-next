using System.Globalization;
using Downpour.Contracts;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;

namespace Downpour_Desktop.Pages;

public sealed partial class CapabilityPage : Page
{
    public CapabilityPage() => InitializeComponent();

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (e.Parameter is not CapabilityDefinition capability) return;

        GroupLabel.Text = capability.Group.ToUpperInvariant();
        TitleLabel.Text = capability.Title;
        DescriptionLabel.Text = capability.Description;
        StatusLabel.Text = capability.Status switch
        {
            "implemented" => "Implemented",
            "in-progress" => "In progress",
            "prototype" => "Prototype",
            _ => "Planned"
        };
        StatusIcon.Glyph = char.ConvertFromUtf32(int.Parse(capability.Icon, NumberStyles.HexNumber, CultureInfo.InvariantCulture));
        StatusDetail.Text = capability.Status == "implemented"
            ? "This capability is available in the new application."
            : "This navigation route preserves feature parity tracking. The capability is not operational in this build; its original sensors and response actions have not been ported.";
        SourceLabel.Text = $"Original implementation: {capability.SourceMethod}";
    }
}
