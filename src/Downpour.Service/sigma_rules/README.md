# Drop-in Sigma rules for Downpour Next

Anything placed here (`.json` or `.yml`/`.yaml`) is loaded by `SigmaEngine.LoadFromYamlFiles()` at service startup. Rules run against:
  * Live process command lines (logsource: category: process_creation)
  * PowerShell 4104 script block text (logsource: category: ps_script)

Standard Sigma rules from https://github.com/SigmaHQ/sigma work for the common field set:
Image, CommandLine, ParentImage, User, ScriptBlockText — with contains/startswith/endswith/re/windash modifiers and logical conditions.

## Provenance and License

- **Source / Provenance**: Ported from Downpour v29 (`downpour_consolidated/sigma_rules/`).
- **License**: Derived from SigmaHQ standard detection rules licensed under the **Detection Rule License 1.1 (DRL 1.1)**.
- **Reference**: https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md
- **Notice**: Detection Rule License (DRL) 1.1 permits commercial and non-commercial use, modification, and distribution in applications providing detection capabilities.
