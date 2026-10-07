/*
    YARA Rules for Rootkit/Evasion Detection
    Downpour v29 Titanium - Threat Intelligence
*/

rule rootkit_nt_hooks
{
    meta:
        author = "Downpour Security"
        version = "29.0.0"
        date = "2026-04-27"
        category = "rootkit"
        severity = "critical"
    strings:
        $api1 = "NtOpenProcess"
        $api2 = "NtOpenThread"
        $api3 = "NtSuspendThread"
        $api4 = "NtTerminateProcess"
    condition:
        any of them
}

rule rootkit_inline_hook
{
    meta:
        author = "Downpour Security"
        version = "29.0.0"
        date = "2026-04-27"
        category = "rootkit"
        severity = "critical"
    strings:
        $pat1 = { E9 ?? ?? ?? ?? }  // JMP offset
        $pat2 = { FF 25 ?? ?? ?? ?? } // JMP [imm]
    condition:
        any of them
}

rule rootkit_ssdt_hook
{
    meta:
        author = "Downpour Security"
        version = "29.0.0"
        date = "2026-04-27"
        category = "rootkit"
        severity = "high"
    strings:
        $func1 = "KeAddSystemServiceTable"
        $func2 = "KiServiceTable"
        $func3 = "KeShadowServiceTable"
    condition:
        any of them
}