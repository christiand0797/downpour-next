rule BadUSB_Payload_Script {
    meta:
        author = "Downpour v29 Titanium"
        version = "1.0"
        date = "2026-09-16"
        category = "badusb"
        severity = "critical"
        mitre = "T1200"
        description = "Detects BadUSB / Rubber Ducky payload scripts"
    strings:
        $ducky1 = "DELAY" ascii
        $ducky2 = "STRING " ascii
        $ducky3 = "GUI r" ascii
        $ducky4 = "ENTER" ascii
        $ducky5 = "ALT F4" ascii
        $ducky6 = "REM " ascii
        $flipper1 = "Flipper" ascii nocase
        $flipper2 = ".sub" ascii
        $flipper3 = "BadUSB" ascii nocase
        $arduino1 = "Keyboard.press" ascii
        $arduino2 = "Keyboard.println" ascii
        $arduino3 = "Keyboard.write" ascii
        $arduino4 = "Mouse.move" ascii
        $teensy1 = "usb_keyboard" ascii
        $teensy2 = "usb_mouse" ascii
    condition:
        (3 of ($ducky*)) or
        (2 of ($flipper*)) or
        (2 of ($arduino*)) or
        (any of ($teensy*) and any of ($arduino*))
}

rule VSS_Deletion_Script {
    meta:
        author = "Downpour v29 Titanium"
        version = "1.0"
        date = "2026-09-16"
        category = "ransomware"
        severity = "critical"
        mitre = "T1490"
        description = "Detects VSS deletion and recovery sabotage scripts"
    strings:
        $vss1 = "vssadmin delete shadows" ascii nocase
        $vss2 = "vssadmin.exe Delete Shadows" ascii nocase
        $vss3 = "wmic shadowcopy delete" ascii nocase
        $vss4 = "shadowcopy where" ascii nocase
        $bcd1 = "bcdedit /set" ascii nocase
        $bcd2 = "recoveryenabled No" ascii nocase
        $bcd3 = "bootstatuspolicy ignoreallfailures" ascii nocase
        $wbadmin1 = "wbadmin delete catalog" ascii nocase
        $wbadmin2 = "wbadmin delete systemstatebackup" ascii nocase
        $catalog = "delete catalog -quiet" ascii nocase
        $resize = "shadowstorage /resize" ascii nocase
    condition:
        any of ($vss*) or
        ($bcd1 and $bcd2) or
        $bcd3 or
        any of ($wbadmin*) or
        $catalog or
        $resize
}
