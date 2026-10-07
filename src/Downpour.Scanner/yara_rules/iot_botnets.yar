rule IoT_Botnet_Generic {
    meta:
        description = "Detects generic IoT botnet indicators"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        mitre_attack = "T0866"
    
    strings:
        $iot1 = "iot" nocase $iot2 = "device" nocase $iot3 = "camera" nocase $iot4 = "dvr" nocase $iot5 = "nvr" nocase $iot6 = "router" nocase $iot7 = "modem" nocase $busybox = "busybox" nocase $telnet = "telnet" nocase $wget = "wget " nocase $tftp = "tftp " nocase $_shell = "/bin/sh" nocase $_bash = "/bin/bash" nocase $_ash = "/bin/ash" nocase condition:
        any of ($iot*) and any of ($busybox, $telnet, $wget, $tftp) and filesize < 5MB
}

rule Mirai_Variant_Patterns {
    meta:
        description = "Detects Mirai botnet variants"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        reference = "https://attack.mitre.org/software/S0155/"
        mitre_attack = "S0155"
    
    strings:
        $mirai1 = "mirai" nocase $mirai2 = "mirai." nocase $mirai3 = "bot" nocase $mirai4 = "scan" nocase $mirai5 = "killer" nocase $mirai6 = "attack" nocase $cnc = "cnc" nocase $port = ":23" nocase $port2 = ":2323" nocase $port3 = ":5555" nocase $report = "/report" nocase $command = "/command" nocase condition:
        any of ($mirai*) and any of ($cnc, $port*, $report, $command) and filesize < 5MB
}

rule Gafgyt_Variant_Patterns {
    meta:
        description = "Detects Gafgyt botnet variants"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        reference = "https://attack.mitre.org/software/S0236/"
        mitre_attack = "S0236"
    
    strings:
        $gafgyt1 = "gafgyt" nocase $gafgyt2 = "bashlite" nocase $gafgyt3 = "lightaid" nocase $gafgyt4 = "qbot" nocase $download = "download" nocase $wget = "wget " nocase $tftp = "tftp " nocase $curl = "curl " nocase $_cnc = "cnc" nocase $_port = ":21" nocase $_port2 = ":23" nocase $_port3 = ":6667" nocase $_scan = "scan" nocase $_kill = "kill" nocase $_brute = "brute" nocase condition:
        any of ($gafgyt*) and any of ($download, $wget, $tftp, $curl) and filesize < 5MB
}

rule Moobot_Patterns {
    meta:
        description = "Detects Moobot botnet indicators"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
    
    strings:
        $moobot1 = "moobot" nocase $moobot2 = "moo" nocase $moobot3 = "bot" nocase $busybox = "busybox" nocase $telnet = "telnet" nocase $wget = "wget " nocase $_cnc = "cnc" nocase $_port = ":23" nocase $_port2 = ":8888" nocase $_scan = "scan" nocase $_attack = "attack" nocase condition:
        any of ($moobot*) and any of ($busybox, $telnet, $wget) and filesize < 5MB
}

rule Amnesia_Botnet_Patterns {
    meta:
        description = "Detects Amnesia botnet indicators"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
    
    strings:
        $amnesia1 = "amnesia" nocase $amnesia2 = "amnes" nocase $amnesia3 = "bot" nocase $persistence = "/etc/init.d/" nocase $persistence2 = "/etc/rc.d/" nocase $persistence3 = "/etc/cron" nocase $cnc = "cnc" nocase $_port = ":23" nocase $_port2 = ":4444" nocase $scan = "scan" nocase $_brute = "brute" nocase condition:
        any of ($amnesia*) and any of ($persistence*, $cnc, $scan) and filesize < 5MB
}

rule Hakai_Botnet_Patterns {
    meta:
        description = "Detects Hakai botnet indicators"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
    
    strings:
        $hakai1 = "hakai" nocase $hakai2 = "hak" nocase $hakai3 = "bot" nocase $busybox = "busybox" nocase $telnet = "telnet" nocase $cnc = "cnc" nocase $_port = ":23" nocase $_port2 = ":8080" nocase $_scan = "scan" nocase $_attack = "attack" nocase condition:
        any of ($hakai*) and any of ($busybox, $telnet, $cnc) and filesize < 5MB
}

rule Persira_Botnet_Patterns {
    meta:
        description = "Detects Persira botnet indicators"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
    
    strings:
        $persira1 = "persira" nocase $persira2 = "pers" nocase $persira3 = "bot" nocase $busybox = "busybox" nocase $telnet = "telnet" nocase $cnc = "cnc" nocase $_port = ":23" nocase $_port2 = ":6667" nocase $_scan = "scan" nocase $_brute = "brute" nocase condition:
        any of ($persira*) and any of ($busybox, $telnet, $cnc) and filesize < 5MB
}

rule Satori_Botnet_Patterns {
    meta:
        description = "Detects Satori botnet indicators"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
    
    strings:
        $satori1 = "satori" nocase $satori2 = "sato" nocase $satori3 = "bot" nocase $busybox = "busybox" nocase $telnet = "telnet" nocase $cnc = "cnc" nocase $_port = ":23" nocase $_port2 = ":9999" nocase $_scan = "scan" nocase $_attack = "attack" nocase condition:
        any of ($satori*) and any of ($busybox, $telnet, $cnc) and filesize < 5MB
}

rule Masuta_Botnet_Patterns {
    meta:
        description = "Detects Masuta botnet indicators"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
    
    strings:
        $masuta1 = "masuta" nocase $masuta2 = "masu" nocase $masuta3 = "bot" nocase $busybox = "busybox" nocase $telnet = "telnet" nocase $cnc = "cnc" nocase $_port = ":23" nocase $_port2 = ":5555" nocase $_scan = "scan" nocase $_brute = "brute" nocase condition:
        any of ($masuta*) and any of ($busybox, $telnet, $cnc) and filesize < 5MB
}

rule PureCryp_Botnet_Patterns {
    meta:
        description = "Detects PureCryp botnet indicators"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
    
    strings:
        $purecryp1 = "purecryp" nocase $purecryp2 = "pure" nocase $purecryp3 = "cryp" nocase $purecryp4 = "bot" nocase $busybox = "busybox" nocase $telnet = "telnet" nocase $cnc = "cnc" nocase $_port = ":23" nocase $_port2 = ":3333" nocase $_scan = "scan" nocase $miner = "miner" nocase $_pool = "pool." nocase condition:
        any of ($purecryp*) and any of ($busybox, $telnet, $cnc, $miner) and filesize < 5MB
}

rule Wroba_Botnet_Patterns {
    meta:
        description = "Detects Wroba botnet indicators"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
    
    strings:
        $wroba1 = "wroba" nocase $wroba2 = "wrob" nocase $wroba3 = "bot" nocase $busybox = "busybox" nocase $telnet = "telnet" nocase $cnc = "cnc" nocase $_port = ":23" nocase $_port2 = ":1234" nocase $_scan = "scan" nocase $_brute = "brute" nocase $_spread = "spread" nocase condition:
        any of ($wroba*) and any of ($busybox, $telnet, $cnc) and filesize < 5MB
}

rule Yakuza_Botnet_Patterns {
    meta:
        description = "Detects Yakuza botnet indicators"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
    
    strings:
        $yakuza1 = "yakuza" nocase $yakuza2 = "yaku" nocase $yakuza3 = "bot" nocase $busybox = "busybox" nocase $telnet = "telnet" nocase $cnc = "cnc" nocase $_port = ":23" nocase $_port2 = ":7777" nocase $_scan = "scan" nocase $_attack = "attack" nocase $ddos = "ddos" nocase condition:
        any of ($yakuza*) and any of ($busybox, $telnet, $cnc, $ddos) and filesize < 5MB
}

rule Hybrid_Botnet_Patterns {
    meta:
        description = "Detects Hybrid botnet indicators"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
    
    strings:
        $hybrid1 = "hybrid" nocase $hybrid2 = "hyb" nocase $hybrid3 = "bot" nocase $busybox = "busybox" nocase $telnet = "telnet" nocase $cnc = "cnc" nocase $_port = ":23" nocase $_port2 = ":6667" nocase $_scan = "scan" nocase $_brute = "brute" nocase $_spread = "spread" nocase condition:
        any of ($hybrid*) and any of ($busybox, $telnet, $cnc) and filesize < 5MB
}

rule BrickerBot_Patterns {
    meta:
        description = "Detects BrickerBot indicators"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
    
    strings:
        $bricker1 = "brickerbot" nocase $bricker2 = "brick" nocase $bricker3 = "bot" nocase $flash = "flash_erase" nocase $flash2 = "flash_write" nocase $flash3 = "mtd_write" nocase $cnc = "cnc" nocase $port = ":23" nocase $destroy = "rm -rf /" nocase $destroy2 = "mkfs" nocase $destroy3 = "flash_eraseall" nocase condition:
        any of ($bricker*) and any of ($flash*, $destroy*, $cnc, $port) and filesize < 5MB
}

rule Linux_Worm_Patterns {
    meta:
        description = "Detects Linux worm propagation patterns"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        mitre_attack = "T1211"
    
    strings:
        $worm1 = "worm" nocase $worm2 = "spread" nocase $worm3 = "infect" nocase $scan = "scan" nocase $brute = "brute" nocase $telnet = "telnet" nocase $self_prop = "/bin/" nocase $self_prop2 = "/sbin/" nocase $self_prop3 = "/usr/bin/" nocase $cnc = "cnc" nocase $port = ":23" nocase $port2 = ":22" nocase condition:
        any of ($worm*) and any of ($scan, $brute, $telnet, $self_prop, $self_prop2, $self_prop3, $cnc, $port, $port2) and filesize < 5MB
}

rule Android_Botnet_Patterns {
    meta:
        description = "Detects Android botnet indicators"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
    
    strings:
        $android1 = "android.intent.action" nocase $android2 = "getDeviceId" nocase $android3 = "SmsManager" nocase $android4 = "sendTextMessage" nocase $android5 = "BotManager" nocase $cnc = "cnc" nocase $port = ":23" nocase $port2 = ":6667" nocase $sms = "SMS" nocase $contacts = "Contacts" nocase $location = "Location" nocase condition:
        all of ($android*) and any of ($cnc, $sms, $contacts, $port, $port2, $location) and filesize < 5MB
}
