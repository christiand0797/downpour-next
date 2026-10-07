/*
    Credential Dumping Tool Detection
    Downpour v29 Titanium

    Detects well-known credential dumping tools:
      - Mimikatz and variants
      - ProcDump LSASS targeting
      - Comsvcs.dll MiniDump
      - NTDSUtil/DSInternals for AD
      - SAM/SYSTEM registry extraction
      - LaZagne password recovery
*/

rule cred_mimikatz_strings {
    meta:
        author = "Downpour Security"
        version = "1.0"
        date = "2026-09-16"
        category = "credential_dumping"
        severity = "critical"
        mitre = "T1003.001"
        description = "Mimikatz binary or script indicators"

    strings:
        $mimi1 = "mimikatz" ascii wide nocase
        $mimi2 = "gentilkiwi" ascii wide
        $mimi3 = "sekurlsa" ascii wide nocase
        $mimi4 = "kiwi_" ascii wide
        $mimi5 = "Benjamin DELPY" ascii wide
        $mod1 = "sekurlsa::logonpasswords" ascii wide nocase
        $mod2 = "sekurlsa::wdigest" ascii wide nocase
        $mod3 = "lsadump::sam" ascii wide nocase
        $mod4 = "lsadump::dcsync" ascii wide nocase
        $mod5 = "token::elevate" ascii wide nocase
        $mod6 = "privilege::debug" ascii wide nocase
        $mod7 = "kerberos::golden" ascii wide nocase
        $mod8 = "crypto::certificates" ascii wide nocase

    condition:
        2 of ($mimi1, $mimi2, $mimi3, $mimi4, $mimi5) or
        2 of ($mod1, $mod2, $mod3, $mod4, $mod5, $mod6, $mod7, $mod8)
}

rule cred_lsass_dump_techniques {
    meta:
        author = "Downpour Security"
        version = "1.0"
        date = "2026-09-16"
        category = "credential_dumping"
        severity = "critical"
        mitre = "T1003.001"
        description = "LSASS memory dump techniques"

    strings:
        $procdump_lsass = "procdump" ascii wide nocase
        $lsass_target = "lsass" ascii wide nocase
        $minidump = "MiniDump" ascii wide nocase
        $comsvcs = "comsvcs.dll" ascii wide nocase
        $_comsvcs_full = "rundll32.exe C:\\Windows\\System32\\comsvcs.dll" ascii wide nocase
        $nanodump = "nanodump" ascii wide nocase
        $handlekatz = "handlekatz" ascii wide nocase
        $lsassy = "lsassy" ascii wide nocase
        $pypykatz = "pypykatz" ascii wide nocase
        $dump_flag = "-ma" ascii wide

    condition:
        ($procdump_lsass and $lsass_target) or
        ($comsvcs and ($minidump or $lsass_target)) or
        ($minidump and $lsass_target) or
        any of ($nanodump, $handlekatz, $lsassy, $pypykatz) or
        ($procdump_lsass and $dump_flag and $lsass_target)
}

rule cred_sam_system_extraction {
    meta:
        author = "Downpour Security"
        version = "1.0"
        date = "2026-09-16"
        category = "credential_dumping"
        severity = "high"
        mitre = "T1003.002"
        description = "SAM/SYSTEM registry hive extraction"

    strings:
        $reg_save1 = "reg save HKLM\\SAM" ascii wide nocase
        $reg_save2 = "reg save HKLM\\SYSTEM" ascii wide nocase
        $reg_save3 = "reg save HKLM\\SECURITY" ascii wide nocase
        $shadow_copy = "\\Windows\\System32\\config\\SAM" ascii wide nocase
        $ntds = "ntds.dit" ascii wide nocase
        $esentutl = "esentutl" ascii wide nocase
        $secretsdump = "secretsdump" ascii wide nocase
        $vol_shadow = "HarddiskVolumeShadowCopy" ascii wide nocase

    condition:
        2 of ($reg_save1, $reg_save2, $reg_save3) or
        ($shadow_copy and $vol_shadow) or
        ($ntds and ($esentutl or $secretsdump)) or
        ($ntds and $vol_shadow)
}

rule cred_ntdsutil_extraction {
    meta:
        author = "Downpour Security"
        version = "1.0"
        date = "2026-09-16"
        category = "credential_dumping"
        severity = "critical"
        mitre = "T1003.003"
        description = "NTDS.dit extraction via ntdsutil or DSInternals"

    strings:
        $ntdsutil = "ntdsutil" ascii wide nocase
        $ifm = "install from media" ascii wide nocase
        $activate = "activate instance ntds" ascii wide nocase
        $dsinternals = "DSInternals" ascii wide nocase
        $get_addb = "Get-ADDBAccount" ascii wide nocase
        $get_boot = "Get-BootKey" ascii wide nocase
        $ntds_dit = "ntds.dit" ascii wide nocase
        $vssadmin = "vssadmin create shadow" ascii wide nocase

    condition:
        ($ntdsutil and ($ifm or $activate)) or
        ($dsinternals and ($get_addb or $get_boot)) or
        ($ntds_dit and $vssadmin)
}

rule cred_lazagne_recovery {
    meta:
        author = "Downpour Security"
        version = "1.0"
        date = "2026-09-16"
        category = "credential_dumping"
        severity = "critical"
        mitre = "T1555"
        description = "LaZagne password recovery tool"

    strings:
        $lazagne1 = "lazagne" ascii wide nocase
        $lazagne2 = "LaZagne" ascii wide
        $modules = "all" ascii wide nocase
        $browser = "browsers" ascii wide nocase
        $wifi = "wifi" ascii wide nocase
        $sysadmin = "sysadmin" ascii wide nocase
        $database = "databases" ascii wide nocase
        $memory = "memory" ascii wide nocase
        $git_cred = "git" ascii wide nocase

    condition:
        ($lazagne1 or $lazagne2) and
        1 of ($modules, $browser, $wifi, $sysadmin, $database, $memory, $git_cred)
}
