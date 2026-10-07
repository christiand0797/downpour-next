rule MiraiBotnet_Strings
{
    meta:
        description = "Detects Mirai botnet malware strings"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        reference = "https://attack.mitre.org/software/S0157/"
        mitre_attack = "S0157"
    
    strings:
        $mirai1 = "mirai" nocase
        $mirai2 = "botnet" nocase  
        $mirai3 = "/dev/watchdog"  
        $mirai4 = "telnet" nocase
        $mirai5 = "loader" nocase
        $mirai6 = "cnc" nocase
        
    condition:
        any of them and filesize < 2MB
}

rule GafgytBotnet_Strings
{
    meta:
        description = "Detects Gafgyt botnet malware strings"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        reference = "https://attack.mitre.org/software/S0236/"
        mitre_attack = "S0236"
    
    strings:
        $gafgyt1 = "gafgyt" nocase
        $gafgyt2 = "busybox" nocase
        $gafgyt3 = "telnet" nocase
        $gafgyt4 = "/dev/watchdog"
        $gafgyt5 = "scanner" nocase
        
    condition:
        any of them and filesize < 2MB
}

rule KimwolfBotnet_IOCs
{
    meta:
        description = "Detects Kimwolf/Aisuru botnet IOCs"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        reference = "https://www.kaspersky.com/blog/kimwolf-botnet/48104/"
    
    strings:
        $kimwolf1 = "kimwolf" nocase
        $kimwolf2 = "aisuru" nocase  
        $kimwolf3 = "byteconnect" nocase
        $kimwolf4 = "plainproxies" nocase
        $kimwolf5 = "adlinknetwork" nocase
        $kimwolf6 = "14emeliaterracewestroxburyma02132.su" nocase
        $kimwolf7 = "rtrdedge1.samsungcdn.cloud" nocase
        
    condition:
        any of them and filesize < 2MB
}

rule Botnet_C2_Communication
{
    meta:
        description = "Detects common botnet C2 communication patterns"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        mitre_attack = "T1071"
    
    strings:
        $c2_1 = "GET /command" nocase
        $c2_2 = "POST /report" nocase
        $c2_3 = "bot_id=" nocase
        $c2_4 = "cnc_port=" nocase
        $c2_5 = "http://" nocase
        $c2_6 = "https://" nocase
        $ip_pattern = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/
        
    condition:
        ($c2_1 or $c2_2 or $c2_3 or $c2_4 or $c2_5 or $c2_6 or $ip_pattern) and filesize < 1MB
}

rule AndroidBotnet_Indicators
{
    meta:
        description = "Detects Android-based botnet indicators"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
    
    strings:
        $android1 = "android.intent.action" nocase
        $android2 = "getDeviceId" nocase
        $android3 = "getSubscriberId" nocase
        $android4 = "SmsManager" nocase
        $android5 = "sendTextMessage" nocase
        $android6 = "BotManager" nocase
        
    condition:
        all of them and filesize < 5MB
}
