rule SuspiciousPowerShell_Obfuscation
{
    meta:
        description = "Detects obfuscated PowerShell commands common in malware"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
        mitre_attack = "T1059.001"
    
    strings:
        $powershell = "powershell" nocase
        $encoded = "-e " nocase
        $encoded2 = "-en " nocase
        $encoded3 = "-enc " nocase
        $bypass = "bypass" nocase
        $hidden = "Hidden" nocase
        $noninteractive = "-NonI" nocase
        $windowstyle = "-W Hidden" nocase
        $invoke = "Invoke-Expression" nocase
        $download = "DownloadString" nocase
        $webclient = "WebClient" nocase
    
    condition:
        $powershell at 0 and 
        ($encoded or $encoded2 or $encoded3) and 
        ($bypass or $hidden or $noninteractive or $windowstyle or $invoke or $download or $webclient)
}

rule MaliciousMacro_Document
{
    meta:
        description = "Detects suspicious macros in Office documents"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        reference = "https://attack.mitre.org/techniques/T1137/"
        mitre_attack = "T1137"
    
    strings:
        $autoopen = "Auto_Open" nocase
        $autoclose = "Auto_Close" nocase
        $document_open = "Document_Open" nocase
        $shell = "Shell" nocase
        $run = "Run(" nocase
        $exec = "Exec(" nocase
        $wmi = "GetObject(\"WinMGMTS\")" nocase
        $download = "URLDownloadToFile" nocase
        $powershell = "powershell" nocase
        $cmd = "cmd.exe" nocase
    
    condition:
        ($autoopen or $autoclose or $document_open) and 
        ($shell or $run or $exec or $wmi or $download or $powershell or $cmd)
}

rule SuspiciousBatchScript
{
    meta:
        description = "Detects malicious batch script patterns"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        mitre_attack = "T1059.003"
    
    strings:
        $echo_off = "@echo off" nocase
        $powershell = "powershell" nocase
        $cmd = "cmd /c" nocase
        $del = "del " nocase
        $rmdir = "rmdir " nocase
        $format = "format " nocase
        $shutdown = "shutdown -s" nocase
        $taskkill = "taskkill" nocase
        $net = "net user" nocase
        $reg = "reg add" nocase
        $bypass = "bypass" nocase
    
    condition:
        any of ($powershell, $cmd, $del, $rmdir, $format, $shutdown, $taskkill, $net, $reg, $bypass, $echo_off) and 
        filesize < 100KB
}

rule CryptoMiner_Script
{
    meta:
        description = "Detects cryptomining script patterns"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        mitre_attack = "T1496"
    
    strings:
        $xmrig = "xmrig" nocase
        $monero = "monero" nocase
        $bitcoin = "bitcoin" nocase
        $stratum = "stratum+tcp://" nocase
        $pool = "pool." nocase
        $miner = "miner" nocase
        $hashrate = "hashrate" nocase
        $wallet = "wallet" nocase
    
    condition:
        any of them and filesize < 1MB
}
