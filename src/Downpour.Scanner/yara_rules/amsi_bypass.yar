/*
    YARA Rules for AMSI Bypass Detection
    Downpour v29 Titanium - Defense Evasion Detection

    Detects in-memory and on-disk patterns associated with
    AMSI (Antimalware Scan Interface) bypass techniques.
*/

rule amsi_bypass_memory_patch
{
    meta:
        author = "Downpour Security"
        version = "29.80"
        date = "2026-09-16"
        category = "defense_evasion"
        severity = "critical"
        mitre = "T1562.001"
        description = "Detects common AMSI memory patching patterns"
    strings:
        $patch1 = "AmsiScanBuffer" ascii wide
        $patch2 = "AmsiInitFailed" ascii wide
        $patch3 = "amsi.dll" ascii wide nocase
        $patch4 = "AmsiUtils" ascii wide
        $patch5 = "amsiContext" ascii wide
        $patch6 = { C3 }  // ret instruction (common patch target)
        $api1 = "VirtualProtect" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "GetProcAddress" ascii
    condition:
        2 of ($patch*) and 1 of ($api*)
}

rule amsi_bypass_powershell_reflection
{
    meta:
        author = "Downpour Security"
        version = "29.80"
        date = "2026-09-16"
        category = "defense_evasion"
        severity = "critical"
        mitre = "T1562.001"
        description = "Detects PowerShell reflection-based AMSI bypass"
    strings:
        $ref1 = "System.Management.Automation.AmsiUtils" ascii wide nocase
        $ref2 = "amsiInitFailed" ascii wide nocase
        $ref3 = "NonPublic,Static" ascii wide nocase
        $ref4 = "SetValue" ascii wide
        $ref5 = "GetField" ascii wide
        $ref6 = "[Ref].Assembly" ascii wide nocase
    condition:
        3 of them
}

rule amsi_bypass_clr_hooking
{
    meta:
        author = "Downpour Security"
        version = "29.80"
        date = "2026-09-16"
        category = "defense_evasion"
        severity = "critical"
        mitre = "T1562.001"
        description = "Detects CLR-based AMSI hooking via .NET reflection"
    strings:
        $clr1 = "clr.dll" ascii wide nocase
        $clr2 = "mscorlib" ascii wide nocase
        $clr3 = "System.Runtime.InteropServices.Marshal" ascii wide
        $hook1 = "Copy" ascii
        $hook2 = "GetDelegateForFunctionPointer" ascii wide
        $amsi = "amsi" ascii wide nocase
    condition:
        1 of ($clr*) and 1 of ($hook*) and $amsi
}

rule amsi_dll_hijack
{
    meta:
        author = "Downpour Security"
        version = "29.80"
        date = "2026-09-16"
        category = "defense_evasion"
        severity = "critical"
        mitre = "T1574.001"
        description = "Detects rogue amsi.dll placed for DLL hijacking"
    strings:
        $name = "amsi.dll" ascii wide nocase
        $export1 = "AmsiScanBuffer" ascii
        $export2 = "AmsiInitialize" ascii
        $nop1 = { 90 90 90 90 }  // NOP sled
        $ret = { 31 C0 C3 }     // xor eax,eax; ret (always return clean)
    condition:
        $name and 1 of ($export*) and (1 of ($nop*, $ret))
}
