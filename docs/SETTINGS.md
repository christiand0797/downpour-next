# Settings and local preferences

Downpour Next has one Settings navigation destination. Supported visual preferences are stored in the packaged app's `ApplicationData.Current.LocalSettings` container under versioned keys for the current Windows user. In portable/unpackaged mode, the app falls back to a bounded INI file under `%LOCALAPPDATA%\DownpourNext`. The app does not store credentials or threat-feed contents in these settings.

Implemented preferences:

- Rain and sky effects: show/hide the animated storm canvas.
- Reduce motion: pause continuous rain, stars, aurora, and lightning animation.
- Automatic storm rotation: allow scene changes among drizzle, storm, thunderstorm, and hurricane; a dashboard mode selection holds the selected mode manually.

If Windows local settings are unavailable, the screen reports that choices will only last for the current run.

Service-backed sensor and response settings are separate from these visual preferences. The page loads and updates the bounded, versioned sensor-settings contract through the local service. If the service is unavailable, these controls are disabled and the failure is shown. PowerShell script-content analysis and automatic threat-intelligence lookups have their own switches; these do not disable unrelated metadata inventory.

Four response-policy switches control quarantine/restore, process termination, IP firewall changes, and USB device/storage changes. These are actual broker policy gates, not immediate actions. Each action still requires its own preview and confirmation; immutable process/device protections remain in force. Switching off firewall actions does not cancel expiry cleanup of existing temporary rules. State is persisted by the service for the current Windows user. Automatic administrator elevation remains unfinished: Windows access-denied results are visible, and enabling a switch does not grant additional Windows permissions.

The toggle handlers are attached in the page constructor after `InitializeComponent` so initial XAML control construction cannot invoke handlers before the named controls are ready. Build/test and process startup passed after this adjustment; a native interactive navigation check remains outstanding.
