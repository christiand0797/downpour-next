rule Suspicious_DNS_Query {
    meta:
        description = "Detects suspicious DNS query patterns"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        mitre_attack = "T1071.004"
    
    strings:
        $dns1 = ".tk" nocase
        $dns2 = ".ga" nocase  
        $dns3 = ".ml" nocase  
        $dns4 = ".cf" nocase  
        $dns5 = ".gq" nocase  
        $dns6 = ".top" nocase  
        $dns7 = ".work" nocase  
        $dns8 = ".click" nocase  
        $dns9 = ".link" nocase  
        $dns10 = "duckdns.org" nocase  
        $dns11 = "no-ip.org" nocase  
        $dns12 = "ddns.net" nocase  
        $dns13 = "hopto.org" nocase  
        $dns14 = "sytes.org" nocase  
        $dns15 = "timedddns.com" nocase  
    
    condition:
        any of ($dns*) and filesize < 1MB  
}

rule Suspicious_HTTP_Header {
    meta:
        description = "Detects suspicious HTTP headers in files"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        mitre_attack = "T1071"
    
    strings:
        $header1 = "User-Agent: Mozilla/4.0" nocase  
        $header2 = "User-Agent: curl/" nocase  
        $header3 = "User-Agent: wget" nocase  
        $header4 = "User-Agent: python-requests" nocase  
        $header5 = "User-Agent: python-urllib" nocase  
        $header6 = "Accept: */*" nocase  
        $header7 = "Connection: close" nocase  
        $header8 = "Content-Type: application/x-www-form-urlencoded" nocase  
    
        $cmd1 = "cmd.exe" nocase  
        $cmd2 = "powershell.exe" nocase  
        $cmd3 = "/bin/sh" nocase  
        $cmd4 = "/bin/bash" nocase  
    
    condition:
        any of ($header*) and any of ($cmd*) and filesize < 2MB  
}

rule Data_Exfiltration_Patterns {
    meta:
        description = "Detects data exfiltration patterns"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        mitre_attack = "T1041"
    
    strings:
        $exfil1 = "ftp://" nocase  
        $exfil2 = "scp " nocase  
        $exfil3 = "rsync " nocase  
        $exfil4 = "rclone" nocase  
        $exfil5 = "mega.nz" nocase  
        $exfil6 = "dropbox.com" nocase  
        $exfil7 = "drive.google.com" nocase  
        $exfil8 = "1drv.ms" nocase  
        $exfil9 = "pastebin.com" nocase  
        $exfil10 = "ghostbin.com" nocase  
        $exfil11 = "transfer.sh" nocase  
        $exfil12 = "file.io" nocase  
    
        $size1 = "rar " nocase  
        $size2 = "zip " nocase  
        $size3 = "7z " nocase  
        $size4 = "tar.gz" nocase  
    
    condition:
        any of ($exfil*) and any of ($size*) and filesize < 10MB  
}

rule Lateral_Movement_Patterns {
    meta:
        description = "Detects lateral movement patterns"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        mitre_attack = "TA0008"
    
    strings:
        $lateral1 = "psexec" nocase  
        $lateral2 = "wmicexec" nocase  
        $lateral3 = "schtasks" nocase  
        $lateral4 = "at.exe" nocase  
        $lateral5 = "sc.exe" nocase  
        $lateral6 = "reg.exe" nocase  
        $lateral7 = "netsh" nocase  
        $lateral8 = "dcomcnfg" nocase  
        $lateral9 = "mmc.exe" nocase  
    
        $target1 = "admin$" nocase  
        $target2 = "c$" nocase  
        $target3 = "ipc$" nocase  
    
    condition:
        any of ($lateral*) and any of ($target*) and filesize < 5MB  
}

rule Persistence_Patterns {
    meta:
        description = "Detects persistence mechanisms"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        mitre_attack = "TA0003"
    
    strings:
        $pers1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase  
        $pers2 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase  
        $pers3 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase  
        $pers4 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase  
        $pers5 = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services" nocase  
        $pers6 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Load" nocase  
        $pers7 = "schtasks /create" nocase  
        $pers8 = "sc create" nocase  
        $pers9 = "reg add" nocase  
    
        $file1 = ".vbs" nocase  
        $file2 = ".js" nocase  
        $file3 = ".wsf" nocase  
        $file4 = ".hta" nocase  
    
    condition:
        any of ($pers*) and any of ($file*) and filesize < 3MB  
}
