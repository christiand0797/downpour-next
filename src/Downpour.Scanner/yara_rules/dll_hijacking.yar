rule DLL_Search_Order_Hijack
{
    meta:
        author = "Downpour v29 Titanium"
        version = "1.0"
        date = "2024-12-01"
        category = "persistence"
        severity = "critical"
        mitre = "T1574.001,T1574.002"
        description = "Detects DLL hijacking and side-loading techniques"

    strings:
        $_hijack1 = "SetDllDirectory" ascii
        $_hijack2 = "AddDllDirectory" ascii
        $_hijack3 = "LoadLibraryEx" ascii
        $sideload1 = "version.dll" ascii nocase
        $sideload2 = "winmm.dll" ascii nocase
        $sideload3 = "wsock32.dll" ascii nocase
        $sideload4 = "dbghelp.dll" ascii nocase
        $sideload5 = "cryptbase.dll" ascii nocase
        $sideload6 = "amsi.dll" ascii nocase
        $proxy1 = "DllMain" ascii
        $proxy2 = "#pragma comment(linker" ascii
        $proxy3 = "ExportFunc" ascii

    condition:
        ($proxy1 or $proxy2 or $proxy3) and 2 of ($sideload*)
}

rule AMSI_Bypass_Script
{
    meta:
        author = "Downpour v29 Titanium"
        version = "1.0"
        date = "2024-12-01"
        category = "defense-evasion"
        severity = "critical"
        mitre = "T1562.001"
        description = "Detects AMSI bypass techniques in scripts"

    strings:
        $amsi1 = "AmsiScanBuffer" ascii nocase
        $amsi2 = "AmsiInitFailed" ascii nocase
        $amsi3 = "AmsiUtils" ascii nocase
        $amsi4 = "amsiContext" ascii nocase
        $patch1 = "VirtualProtect" ascii
        $patch2 = "WriteProcessMemory" ascii
        $patch3 = "[Runtime.InteropServices.Marshal]" ascii nocase
        $bypass1 = "Invoke-AmsiBypass" ascii nocase
        $bypass2 = "Disable-Amsi" ascii nocase
        $bypass3 = "Bypass-Amsi" ascii nocase
        $reflection1 = "[Ref].Assembly.GetType" ascii nocase
        $reflection2 = "System.Management.Automation.AmsiUtils" ascii nocase

    condition:
        2 of them
}

rule Firewall_Tampering_Script
{
    meta:
        author = "Downpour v29 Titanium"
        version = "1.0"
        date = "2024-12-01"
        category = "defense-evasion"
        severity = "critical"
        mitre = "T1562.004"
        description = "Detects firewall tampering and disabling in scripts"

    strings:
        $fw_off1 = "netsh advfirewall set allprofiles state off" ascii nocase
        $fw_off2 = "netsh advfirewall set currentprofile state off" ascii nocase
        $fw_off3 = "netsh firewall set opmode disable" ascii nocase
        $fw_svc1 = "sc stop MpsSvc" ascii nocase
        $fw_svc2 = "sc config MpsSvc start= disabled" ascii nocase
        $fw_svc3 = "net stop MpsSvc" ascii nocase
        $fw_reg1 = "EnableFirewall" ascii nocase
        $fw_add1 = "netsh advfirewall firewall add rule" ascii nocase
        $fw_del1 = "netsh advfirewall firewall delete rule" ascii nocase
        $fw_ps1 = "Set-NetFirewallProfile" ascii nocase
        $fw_ps2 = "Disable-NetFirewallRule" ascii nocase

    condition:
        2 of them
}
