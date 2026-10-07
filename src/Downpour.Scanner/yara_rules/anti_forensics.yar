rule Anti_Forensics_Tools
{
    meta:
        author = "Downpour v29 Titanium"
        version = "1.0"
        date = "2024-12-01"
        category = "anti-forensics"
        severity = "critical"
        mitre = "T1070,T1070.001,T1070.004,T1070.006"
        description = "Detects anti-forensics and evidence destruction tools"

    strings:
        $sdelete = "sdelete" ascii nocase
        $sdelete64 = "sdelete64" ascii nocase
        $eraser = "eraser.exe" ascii nocase
        $cipher_w = "cipher /w:" ascii nocase
        $bleachbit = "bleachbit" ascii nocase
        $ccleaner = "ccleaner" ascii nocase
        $privazer = "privazer" ascii nocase
        $timestomp1 = "timestomp" ascii nocase
        $timestomp2 = "SetMACE" ascii nocase
        $ninjacopy = "NinjaCopy" ascii nocase
        $phant0m = "Invoke-Phant0m" ascii nocase
        $evt_clear1 = "wevtutil cl" ascii nocase
        $evt_clear2 = "wevtutil clear-log" ascii nocase
        $evt_clear3 = "Clear-EventLog" ascii nocase
        $usn_del = "fsutil usn deletejournal" ascii nocase
        $prefetch_del = "del /q /f %systemroot%\\Prefetch" ascii nocase
        $mft_del = "MFTECmd" ascii nocase
        $auditpol1 = "auditpol /clear" ascii nocase
        $auditpol2 = "auditpol /set" ascii nocase
        $auditpol3 = "auditpol /remove" ascii nocase

    condition:
        any of them
}

rule Log_Tampering_Script
{
    meta:
        author = "Downpour v29 Titanium"
        version = "1.0"
        date = "2024-12-01"
        category = "anti-forensics"
        severity = "critical"
        mitre = "T1070.001"
        description = "Detects scripts that clear multiple event logs"

    strings:
        $wevtutil = "wevtutil" ascii nocase
        $clear = "cl " ascii nocase
        $security = "Security" ascii nocase
        $system = "System" ascii nocase
        $application = "Application" ascii nocase

    condition:
        $wevtutil and $clear and (($security and $system) or ($security and $application) or ($system and $application))
}
