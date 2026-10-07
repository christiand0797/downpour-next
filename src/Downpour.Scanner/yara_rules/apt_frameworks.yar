rule APT_Command_and_Control {
    meta:
        description = "Detects APT-related C2 patterns"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        mitre_attack = "T1071"
    
    strings:
        $apt1 = "beacon" nocase
        $apt2 = "http://" nocase
        $apt3 = "https://" nocase
        $apt4 = "port=" nocase
        $apt5 = "sleep" nocase
        $apt6 = "jitter" nocase
        $apt7 = "maxget" nocase
        $apt8 = "timeout" nocase
        $apt9 = "reconnect" nocase
        $apt10 = "checkin" nocase
        $apt11 = "host=" nocase
        $apt12 = "id=" nocase
    
    condition:
        any of ($apt1, $apt2, $apt3) and any of ($apt4, $apt5, $apt6, $apt7, $apt8, $apt9, $apt10, $apt11, $apt12) and filesize < 5MB
}

rule APT_Data_Exfiltration {
    meta:
        description = "Detects APT-related data exfiltration patterns"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        mitre_attack = "T1041"
    
    strings:
        $exfil1 = "upload" nocase
        $exfil2 = "exfil" nocase
        $exfil3 = "steal" nocase
        $exfil4 = "grab" nocase
        $exfil5 = "collect" nocase
        $exfil6 = "archive" nocase
        $exfil7 = "zip" nocase
        $exfil8 = "rar" nocase
        $exfil9 = "7z" nocase
        $exfil10 = "tar.gz" nocase
        $exfil11 = "ftp://" nocase
        $exfil12 = "scp " nocase
        $exfil13 = "rsync " nocase
    
    condition:
        any of ($exfil1, $exfil2, $exfil3, $exfil4, $exfil5) and any of ($exfil6, $exfil7, $exfil8, $exfil9, $exfil10, $exfil11, $exfil12, $exfil13) and filesize < 10MB
}

rule APT_Persistence {
    meta:
        description = "Detects APT-related persistence mechanisms"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        mitre_attack = "TA0003"
    
    strings:
        $pers1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $pers2 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $pers3 = "schtasks /create" nocase
        $pers4 = "sc create" nocase
        $pers5 = "reg add" nocase
        $pers6 = "startup" nocase
        $pers7 = "AppData\\Roaming\\" nocase
        $pers8 = "AppData\\Local\\" nocase
        $pers9 = "ProgramData\\" nocase
        $pers10 = "Tasks\\" nocase
    
    condition:
        any of ($pers1, $pers2) and any of ($pers3, $pers4, $pers5, $pers6, $pers7, $pers8, $pers9, $pers10) and filesize < 5MB
}

rule APT_Defense_Evasion {
    meta:
        description = "Detects APT-related defense evasion patterns"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        mitre_attack = "TA0005"
    
    strings:
        $evade1 = "bypass" nocase
        $evade2 = "disable" nocase
        $evade3 = "stop" nocase
        $evade4 = "kill" nocase
        $evade5 = "Uninstall" nocase
        $evade6 = "Remove" nocase
        $evade7 = "Delete" nocase
        $evade8 = "taskkill" nocase
        $evade9 = "net stop" nocase
        $evade10 = "sc stop" nocase
        $evade11 = "Set-MpPreference" nocase
        $evade12 = "Add-MpPreference" nocase
    
    condition:
        any of ($evade1, $evade2, $evade3, $evade4, $evade5) and any of ($evade6, $evade7, $evade8, $evade9, $evade10, $evade11, $evade12) and filesize < 5MB
}

rule APT_Credential_Access {
    meta:
        description = "Detects APT-related credential access patterns"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        mitre_attack = "TA0006"
    
    strings:
        $cred1 = "mimikatz" nocase
        $cred2 = "lsass.exe" nocase
        $cred3 = "sekurlsa" nocase
        $cred4 = "wdigest" nocase
        $cred5 = "kerberos" nocase
        $cred6 = "ticket" nocase
        $cred7 = "hash" nocase
        $cred8 = "dump" nocase
        $cred9 = "LSASS" nocase
        $cred10 = "SAM" nocase
        $cred11 = "SYSTEM" nocase
        $cred12 = "Hashdump" nocase
    
    condition:
        any of ($cred1, $cred2, $cred3) and any of ($cred4, $cred5, $cred6, $cred7, $cred8, $cred9, $cred10, $cred11, $cred12) and filesize < 10MB
}
