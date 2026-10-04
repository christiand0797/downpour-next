# Settings and local preferences

Downpour Next has one Settings navigation destination. Supported visual preferences are stored in the packaged app's `ApplicationData.Current.LocalSettings` container under versioned keys for the current Windows user. In portable/unpackaged mode, the app falls back to a bounded INI file under `%LOCALAPPDATA%\DownpourNext`. The app does not store credentials or threat-feed contents in these settings.

Implemented preferences:

- Rain and sky effects: show/hide the animated storm canvas.
- Reduce motion: pause continuous rain, stars, aurora, and lightning animation.
- Automatic storm rotation: allow scene changes among drizzle, storm, thunderstorm, and hurricane; a dashboard mode selection holds the selected mode manually.

If Windows local settings are unavailable, the screen reports that choices will only last for the current run. Protection, scanning, telemetry, and response controls remain absent until their underlying feature and policy paths exist. This avoids presenting nonfunctional toggles or implying that unported v29 capabilities are active.
