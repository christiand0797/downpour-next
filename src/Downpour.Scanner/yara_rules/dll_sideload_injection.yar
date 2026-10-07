/*
    YARA Rules for DLL Sideloading and Process Injection
    Downpour v29 Titanium - Execution and Evasion Detection

    Detects DLL sideloading, phantom DLL loading, process
    injection patterns, and fiber-based shellcode execution.
*/

rule dll_sideloading_indicators
{
    meta:
        author = "Downpour Security"
        version = "29.80"
        date = "2026-09-16"
        category = "defense_evasion"
        severity = "high"
        mitre = "T1574.002"
        description = "Detects common DLL sideloading payload patterns"
    strings:
        $loader1 = "LoadLibrary" ascii wide
        $loader2 = "GetModuleHandle" ascii wide
        $loader3 = "GetProcAddress" ascii wide
        $export1 = "DllCanUnloadNow" ascii
        $export2 = "DllGetClassObject" ascii
        $export3 = "DllRegisterServer" ascii
        $decrypt1 = "CryptDecrypt" ascii wide
        $decrypt2 = { 30 ?? 47 }  // XOR loop pattern
        $shellcode = { FC E8 }    // Common shellcode prologue
    condition:
        2 of ($loader*) and 1 of ($export*) and (1 of ($decrypt*) or $shellcode)
}

rule process_injection_classic
{
    meta:
        author = "Downpour Security"
        version = "29.80"
        date = "2026-09-16"
        category = "defense_evasion"
        severity = "critical"
        mitre = "T1055.001"
        description = "Detects classic process injection API chain"
    strings:
        $api1 = "OpenProcess" ascii wide
        $api2 = "VirtualAllocEx" ascii wide
        $api3 = "WriteProcessMemory" ascii wide
        $api4 = "CreateRemoteThread" ascii wide
        $api5 = "NtCreateThreadEx" ascii wide
        $api6 = "RtlCreateUserThread" ascii wide
    condition:
        $api1 and $api2 and $api3 and 1 of ($api4, $api5, $api6)
}

rule process_hollowing
{
    meta:
        author = "Downpour Security"
        version = "29.80"
        date = "2026-09-16"
        category = "defense_evasion"
        severity = "critical"
        mitre = "T1055.012"
        description = "Detects process hollowing (RunPE) technique"
    strings:
        $api1 = "CreateProcess" ascii wide
        $api2 = "NtUnmapViewOfSection" ascii wide
        $api3 = "ZwUnmapViewOfSection" ascii wide
        $api4 = "VirtualAllocEx" ascii wide
        $api5 = "WriteProcessMemory" ascii wide
        $api6 = "SetThreadContext" ascii wide
        $api7 = "ResumeThread" ascii wide
        $_create_suspended = { 04 00 00 00 }  // CREATE_SUSPENDED flag
    condition:
        $api1 and ($api2 or $api3) and $api4 and $api5 and ($api6 or $api7)
}

rule fiber_based_shellcode
{
    meta:
        author = "Downpour Security"
        version = "29.80"
        date = "2026-09-16"
        category = "defense_evasion"
        severity = "critical"
        description = "Detects fiber-based shellcode execution (2026 evasion technique)"
    strings:
        $api1 = "ConvertThreadToFiber" ascii wide
        $api2 = "CreateFiber" ascii wide
        $api3 = "SwitchToFiber" ascii wide
        $api4 = "VirtualAlloc" ascii wide
        $api5 = "VirtualProtect" ascii wide
        $_rwx = { 40 00 00 00 }  // PAGE_EXECUTE_READWRITE
    condition:
        $api1 and $api2 and $api3 and ($api4 or $api5)
}

rule apc_injection
{
    meta:
        author = "Downpour Security"
        version = "29.80"
        date = "2026-09-16"
        category = "defense_evasion"
        severity = "critical"
        mitre = "T1055.004"
        description = "Detects APC injection technique"
    strings:
        $api1 = "QueueUserAPC" ascii wide
        $api2 = "NtQueueApcThread" ascii wide
        $api3 = "OpenThread" ascii wide
        $api4 = "VirtualAllocEx" ascii wide
        $api5 = "WriteProcessMemory" ascii wide
    condition:
        ($api1 or $api2) and $api3 and ($api4 or $api5)
}

rule early_bird_injection
{
    meta:
        author = "Downpour Security"
        version = "29.80"
        date = "2026-09-16"
        category = "defense_evasion"
        severity = "critical"
        description = "Detects Early Bird APC injection (queue before process init)"
    strings:
        $api1 = "CreateProcess" ascii wide
        $api2 = "VirtualAllocEx" ascii wide
        $api3 = "WriteProcessMemory" ascii wide
        $api4 = "QueueUserAPC" ascii wide
        $api5 = "ResumeThread" ascii wide
        $_create_suspended = { 04 00 00 00 }  // CREATE_SUSPENDED
    condition:
        $api1 and $api2 and $api3 and $api4 and $api5
}
