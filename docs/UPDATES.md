# In-app portable updates

## User flow

On the dashboard, select **Update Downpour** beside the local service badge. Downpour queries the fixed `christiand0797/downpour-next` GitHub Releases endpoint for the latest stable release. If the installed version is behind, it downloads the matching Windows x64 portable ZIP, verifies the SHA-256 digest published in the GitHub release metadata, validates and extracts the archive to a bounded staging directory, then closes Downpour and its owned sensor service. A helper process waits for the old desktop process to exit, applies the package, and restarts the app. If no newer release exists, the button reports that the installed version is current.

The action is user initiated; there is no background download or silent automatic update. Network access is required. Update files are replaced in the extracted application directory. Downpour's settings, event/alert database, and other user state remain under `%LOCALAPPDATA%\DownpourNext`, outside the portable package. Extra files are preserved. The helper waits for the desktop and its bundled service to stop; if the service was started separately, close it and retry. If the app folder is not writable, the update fails with a visible error and should be re-extracted to a writable folder.

## Validation and limits

- The release API host, repository, stable tag shape, release page, exact asset name, HTTPS download URL, asset size, digest, redirects, and response size are checked.
- The ZIP is limited to 512 MiB compressed, 1 GiB expanded, and 2,000 entries. Path traversal, duplicate paths, reserved updater paths, and symbolic links are rejected. The desktop and service executables must exist.
- Staged files are re-hashed before application. Existing package files are copied to a temporary backup and restored on an application failure where Windows permits it. Unknown user files are preserved.
- HTTP/TLS and the release API's digest protect transport integrity, but the GitHub digest is not a publisher signature. Release binaries are currently unsigned; a compromised repository owner, release account, or GitHub publishing path could publish a malicious package and matching digest. This updater is therefore suitable only for the current development distribution. Do not describe it as a signed or independently authenticated security update channel.
- The repository must permit anonymous access to latest release metadata and assets for other users to update without GitHub credentials. A private repository returns an unavailable result. No credentials or GitHub token are embedded or read from the machine.
- Updating is supported only for the extracted self-contained Windows x64 portable folder. It is not an installer, does not register a Windows service, and does not migrate package-owned user files.

## Update rollback incident (v0.1.10–v0.1.11)

The user reported that an update on a second computer displayed the generic rollback dialog. Source review found two apply defects: the app base path can end in a directory separator, so appending another separator made the package containment check reject every destination; and the old helper ran as `Downpour.Desktop.exe` while trying to replace that same executable. A corrected updater uses a standalone single-file helper copied to `%LOCALAPPDATA%\DownpourNext\update-helper`, canonical relative-path containment, detailed error text, and local error logging. The standalone helper is included in v0.1.12 onward.

The v0.1.10 and v0.1.11 updater cannot safely update itself. Install v0.1.12 once by extracting its ZIP over the existing portable folder while Downpour is closed, or into a fresh folder; then launch the new `Downpour.Desktop.exe` and retry in-app updates. User data under `%LOCALAPPDATA%\DownpourNext` remains separate. A failed staged update from the old versions can leave `.downpour-update`; v0.1.12 clears it only after checking the reserved tree contains no reparse points. If you continue to see the rollback dialog, read `%LOCALAPPDATA%\DownpourNext\updates\last-update-error.txt` and share its contents when requesting help.

## Verification

`ReleaseUpdateClientTests` covers fixed repository and asset validation, stable-release/version rules, duplicate metadata rejection, digest verification, untrusted redirect rejection, archive traversal rejection, and required executable extraction. Still required before calling the updater production-ready: publisher code signing or a separately authenticated signed manifest, full native UI click-through, failure-injection for locked files/restart rollback, and test from a clean public download on another Windows account.
