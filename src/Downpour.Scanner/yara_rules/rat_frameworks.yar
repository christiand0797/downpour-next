/*
    RAT Framework Detection
    Downpour v29 Titanium

    Detects common Remote Access Trojan frameworks:
      - Cobalt Strike Beacon artifacts
      - Sliver C2 implant indicators
      - Havoc C2 framework patterns
      - Brute Ratel C4 (BRc4) indicators
      - Mythic C2 agent signatures
*/

rule rat_cobalt_strike_beacon {
    meta:
        author = "Downpour Security"
        version = "1.0"
        date = "2026-09-16"
        category = "rat"
        severity = "critical"
        mitre = "T1071.001"
        description = "Cobalt Strike Beacon implant indicators"

    strings:
        $beacon_config = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? }
        $sleep_mask = "ReflectiveLoader" ascii wide
        $pipe1 = "\\\\.\\pipe\\msagent_" ascii wide
        $pipe2 = "\\\\.\\pipe\\MSSE-" ascii wide
        $pipe3 = "\\\\.\\pipe\\postex_" ascii wide
        $pipe4 = "\\\\.\\pipe\\postex_ssh_" ascii wide
        $named_pipe = "\\\\.\\pipe\\status_" ascii wide
        $default_ua = "Mozilla/5.0 (compatible; MSIE 9.0" ascii wide
        $cs_watermark = "%d is life" ascii
        $beacon_dll = "beacon.dll" ascii
        $beacon_x64 = "beacon.x64.dll" ascii
        $reflective = "ReflectiveLoader" ascii
        $spawn_to = "rundll32.exe" ascii wide

    condition:
        $beacon_config or
        2 of ($pipe1, $pipe2, $pipe3, $pipe4, $named_pipe) or
        ($reflective and ($beacon_dll or $beacon_x64)) or
        ($cs_watermark) or
        ($sleep_mask and $default_ua and $spawn_to)
}

rule rat_sliver_implant {
    meta:
        author = "Downpour Security"
        version = "1.0"
        date = "2026-09-16"
        category = "rat"
        severity = "critical"
        mitre = "T1071.001"
        description = "Sliver C2 implant indicators (Go-based)"

    strings:
        $sliver1 = "sliverpb" ascii
        $sliver2 = "github.com/bishopfox/sliver" ascii
        $sliver3 = "sliver/protobuf" ascii
        $implant1 = "SliverHTTP" ascii
        $implant2 = "SliverDNS" ascii
        $implant3 = "SliverTCP" ascii
        $implant4 = "SliverMTLS" ascii
        $implant5 = "SliverWG" ascii
        $go_build1 = "go.buildid" ascii
        $pivot = "PivotListener" ascii
        $session = "InteractiveSession" ascii
        $stager = "SliverStager" ascii

    condition:
        2 of ($sliver1, $sliver2, $sliver3) or
        1 of ($implant1, $implant2, $implant3, $implant4, $implant5) or
        ($go_build1 and 1 of ($pivot, $session, $stager))
}

rule rat_havoc_framework {
    meta:
        author = "Downpour Security"
        version = "1.0"
        date = "2026-09-16"
        category = "rat"
        severity = "critical"
        mitre = "T1071.001"
        description = "Havoc C2 framework demon agent"

    strings:
        $havoc1 = "HavocFramework" ascii wide
        $havoc2 = "Demon" ascii wide
        $havoc3 = "DemonConfig" ascii wide
        $havoc4 = "TeamServer" ascii wide
        $sleep_obf = "Ekko" ascii wide
        $sleep_obf2 = "Zilean" ascii wide
        $sleep_obf3 = "Foliage" ascii wide
        $injection = "DotNetInline" ascii wide
        $syscall = "IndirectSyscall" ascii wide
        $amsi_patch = "AmsiScanBuffer" ascii wide
        $etw_patch = "EtwEventWrite" ascii wide

    condition:
        2 of ($havoc1, $havoc2, $havoc3, $havoc4) or
        1 of ($sleep_obf, $sleep_obf2, $sleep_obf3) and ($amsi_patch or $etw_patch) or
        ($injection and $syscall and ($amsi_patch or $etw_patch))
}

rule rat_brute_ratel_c4 {
    meta:
        author = "Downpour Security"
        version = "1.0"
        date = "2026-09-16"
        category = "rat"
        severity = "critical"
        mitre = "T1071.001"
        description = "Brute Ratel C4 (BRc4) badger implant"

    strings:
        $brc4_1 = "BRc4" ascii wide
        $brc4_2 = "bruteratel" ascii wide nocase
        $badger = "badger" ascii wide
        $brc4_pipe = "\\\\.\\pipe\\BRc4" ascii wide
        $stompmod = "StompModule" ascii wide
        $bofloader = "BOFLoader" ascii wide
        $syscall1 = "NtAllocateVirtualMemory" ascii wide
        $syscall2 = "NtProtectVirtualMemory" ascii wide
        $syscall3 = "NtCreateThreadEx" ascii wide
        $syscall4 = "NtWriteVirtualMemory" ascii wide
        $unhook = "UnhookNtDll" ascii wide

    condition:
        1 of ($brc4_1, $brc4_2, $brc4_pipe) or
        ($badger and $bofloader) or
        ($stompmod and $unhook) or
        3 of ($syscall1, $syscall2, $syscall3, $syscall4) and ($unhook or $stompmod)
}

rule rat_mythic_agent {
    meta:
        author = "Downpour Security"
        version = "1.0"
        date = "2026-09-16"
        category = "rat"
        severity = "critical"
        mitre = "T1071.001"
        description = "Mythic C2 framework agent indicators"

    strings:
        $mythic1 = "MythicMeta" ascii wide
        $mythic2 = "its-a-feature/Mythic" ascii wide
        $apollo = "Apollo.exe" ascii wide nocase
        $athena = "Athena" ascii wide
        $medusa = "Medusa" ascii wide
        $poseidon = "Poseidon" ascii wide
        $merlin = "Merlin" ascii wide
        $agent_msg = "agent_message" ascii wide
        $checkin = "checkin" ascii wide
        $tasking = "get_tasking" ascii wide
        $post_resp = "post_response" ascii wide
        $staging = "staging_rsa" ascii wide
        $uuid_pattern = /[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/

    condition:
        1 of ($mythic1, $mythic2) or
        2 of ($apollo, $athena, $medusa, $poseidon, $merlin) or
        ($agent_msg and $checkin and $tasking) or
        ($post_resp and $staging and $uuid_pattern)
}
