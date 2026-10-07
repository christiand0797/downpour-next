/*
    YARA Rules for Malware Detection
    Downpour v29 Titanium - Threat Intelligence
*/

rule malware_process_injection
{
    meta:
        author = "Downpour Security"
        version = "29.0.0"
        date = "2026-04-27"
        category = "malware"
        severity = "critical"
    strings:
        $api1 = "VirtualAllocEx"
        $api2 = "WriteProcessMemory"
        $api3 = "CreateRemoteThread"
        $api4 = "NtMapViewOfSection"
        $api5 = "ZwMapViewOfSection"
    condition:
        3 of them
}

rule malware_hidden_process
{
    meta:
        author = "Downpour Security"
        version = "29.0.0"
        date = "2026-04-27"
        category = "malware"
        severity = "high"
    strings:
        $api1 = "NtQuerySystemInformation"
        $api2 = "ZwQuerySystemInformation"
        $api3 = "NtSetInformationThread"
        $api4 = "DebugActiveProcess"
    condition:
        2 of them
}

rule malware_keylogger
{
    meta:
        author = "Downpour Security"
        version = "29.0.0"
        date = "2026-04-27"
        category = "malware"
        severity = "high"
    strings:
        $api1 = "GetAsyncKeyState"
        $api2 = "GetKeyboardState"
        $api3 = "MapVirtualKey"
        $api4 = "SetWindowsHookEx"
    condition:
        2 of them
}

rule malware_powershell_obfuscation
{
    meta:
        author = "Downpour Security"
        version = "29.0.0"
        date = "2026-04-27"
        category = "malware"
        severity = "high"
    strings:
        $ps1 = "Invoke-Expression" nocase
        $ps2 = "IEX" nocase
        $ps3 = "New-Object System.Net.WebClient" nocase
        $ps4 = "DownloadString" nocase
    condition:
        2 of them
}