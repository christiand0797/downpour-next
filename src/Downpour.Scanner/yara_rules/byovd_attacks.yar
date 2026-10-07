/*
    Bring Your Own Vulnerable Driver (BYOVD) Detection
    Downpour v29 Titanium

    Detects exploitation of vulnerable signed drivers:
      - Known vulnerable driver hashes and names
      - Driver loading for kernel-level attacks
      - EDR/AV killer techniques via driver exploitation
      - Kernel callback removal patterns
*/

rule byovd_known_vulnerable_drivers {
    meta:
        author = "Downpour Security"
        version = "1.0"
        date = "2026-09-16"
        category = "byovd"
        severity = "critical"
        mitre = "T1068"
        description = "Known vulnerable drivers used in BYOVD attacks"

    strings:
        $driver1 = "RTCore64.sys" ascii wide nocase
        $driver2 = "RTCore32.sys" ascii wide nocase
        $driver3 = "DBUtil_2_3.sys" ascii wide nocase
        $driver4 = "gdrv.sys" ascii wide nocase
        $driver5 = "WinRing0x64.sys" ascii wide nocase
        $driver6 = "WinRing0.sys" ascii wide nocase
        $driver7 = "cpuz141.sys" ascii wide nocase
        $driver8 = "AsIO.sys" ascii wide nocase
        $driver9 = "BS_HWMIO64_W10.sys" ascii wide nocase
        $driver10 = "EneIo64.sys" ascii wide nocase
        $driver11 = "MsIo64.sys" ascii wide nocase
        $driver12 = "GLCKIO2.sys" ascii wide nocase
        $driver13 = "physmem.sys" ascii wide nocase
        $driver14 = "HpPortIox64.sys" ascii wide nocase
        $driver15 = "ene.sys" ascii wide nocase
        $driver16 = "atillk64.sys" ascii wide nocase
        $driver17 = "iQVW64e.sys" ascii wide nocase
        $driver18 = "HWiNFO64A.sys" ascii wide nocase
        $driver19 = "AsUpIO.sys" ascii wide nocase
        $driver20 = "ProcExp152.sys" ascii wide nocase

    condition:
        any of them
}

rule byovd_driver_loader_patterns {
    meta:
        author = "Downpour Security"
        version = "1.0"
        date = "2026-09-16"
        category = "byovd"
        severity = "critical"
        mitre = "T1068"
        description = "Driver loading patterns associated with BYOVD attacks"

    strings:
        $ntload = "NtLoadDriver" ascii wide
        $nt_unload = "NtUnloadDriver" ascii wide
        $create_svc = "CreateServiceW" ascii wide
        $start_svc = "StartServiceW" ascii wide
        $device_io = "DeviceIoControl" ascii wide
        $_open_sc = "OpenSCManagerW" ascii wide
        $sc_create = "sc create" ascii wide nocase
        $_sc_start = "sc start" ascii wide nocase
        $driver_path = "\\drivers\\" ascii wide nocase
        $type_kernel = "type= kernel" ascii wide nocase
        $binpath = "binPath=" ascii wide nocase

    condition:
        ($ntload or $nt_unload) and $device_io or
        ($create_svc and $start_svc and $device_io) or
        ($sc_create and ($type_kernel or $binpath) and $driver_path)
}

rule byovd_edr_killer {
    meta:
        author = "Downpour Security"
        version = "1.0"
        date = "2026-09-16"
        category = "byovd"
        severity = "critical"
        mitre = "T1562.001"
        description = "EDR/AV process killing via vulnerable driver"

    strings:
        $terminate_proc = "ZwTerminateProcess" ascii wide
        $open_proc = "ZwOpenProcess" ascii wide
        $nt_terminate = "NtTerminateProcess" ascii wide
        $msfirewall = "MsMpEng.exe" ascii wide nocase
        $defender = "MpCmdRun.exe" ascii wide nocase
        $sense = "MsSense.exe" ascii wide nocase
        $crowdstrike = "CSFalconService" ascii wide nocase
        $carbon = "CbDefense" ascii wide nocase
        $sentinel = "SentinelAgent" ascii wide nocase
        $cylance = "CylanceSvc" ascii wide nocase
        $sophos = "SophosHealth" ascii wide nocase
        $symantec = "ccSvcHst" ascii wide nocase
        $eset = "ekrn.exe" ascii wide nocase

    condition:
        ($terminate_proc or $open_proc or $nt_terminate) and
        2 of ($msfirewall, $defender, $sense, $crowdstrike, $carbon,
              $sentinel, $cylance, $sophos, $symantec, $eset)
}

rule byovd_kernel_callback_removal {
    meta:
        author = "Downpour Security"
        version = "1.0"
        date = "2026-09-16"
        category = "byovd"
        severity = "critical"
        mitre = "T1562.001"
        description = "Kernel callback removal to blind security products"

    strings:
        $pscreate = "PsSetCreateProcessNotifyRoutine" ascii wide
        $pscreate_ex = "PsSetCreateProcessNotifyRoutineEx" ascii wide
        $psthread = "PsSetCreateThreadNotifyRoutine" ascii wide
        $psimage = "PsSetLoadImageNotifyRoutine" ascii wide
        $cmreg = "CmRegisterCallback" ascii wide
        $cmunreg = "CmUnRegisterCallback" ascii wide
        $ob_dereg = "ObUnRegisterCallbacks" ascii wide
        $remove_flag = "Remove" ascii wide
        $unregister = "Unregister" ascii wide
        $restore = "RestoreCallbacks" ascii wide

    condition:
        (1 of ($pscreate, $pscreate_ex, $psthread, $psimage) and
         1 of ($remove_flag, $unregister, $restore)) or
        ($cmunreg or $ob_dereg) or
        2 of ($pscreate, $psthread, $psimage, $cmreg)
}

rule byovd_physical_memory_access {
    meta:
        author = "Downpour Security"
        version = "1.0"
        date = "2026-09-16"
        category = "byovd"
        severity = "critical"
        mitre = "T1068"
        description = "Physical memory read/write via vulnerable driver"

    strings:
        $physmem1 = "\\Device\\PhysicalMemory" ascii wide
        $physmem2 = "\\\\.\\PhysicalMemory" ascii wide
        $map_phys = "MmMapIoSpace" ascii wide
        $unmap_phys = "MmUnmapIoSpace" ascii wide
        $map_view = "ZwMapViewOfSection" ascii wide
        $mm_copy = "MmCopyVirtualMemory" ascii wide
        $ke_stack = "KeStackAttachProcess" ascii wide
        $mdl_map = "MmMapLockedPagesSpecifyCache" ascii wide

    condition:
        any of ($physmem1, $physmem2) or
        ($map_phys and $unmap_phys) or
        ($map_view and ($mm_copy or $ke_stack)) or
        ($mdl_map and $ke_stack)
}
