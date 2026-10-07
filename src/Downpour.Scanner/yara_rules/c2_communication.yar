rule C2_Domain_Patterns
{
    meta:
        description = "Detects common C2 domain patterns"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        mitre_attack = "T1071"
    
    strings:
        $domain1 = ".su" nocase
        $domain2 = ".ru" nocase
        $domain3 = ".cn" nocase
        $domain4 = "duckdns.org" nocase
        $domain5 = "no-ip.org" nocase
        $domain6 = "ddns.net" nocase
        $domain7 = "hopto.org" nocase
        $domain8 = "sytes.org" nocase
        $domain9 = "timedddns.com" nocase
        
        $http = "http://" nocase  
        $https = "https://" nocase
    
    condition:
        any of ($domain*) and ($http or $https) and filesize < 1MB
}

rule C2_IP_Indicators
{
    meta:
        description = "Detects C2 IP address patterns in files"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        mitre_attack = "T1071"
    
    strings:
        $ip_pattern = /([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])/
        $port1 = ":443" 
        $port2 = ":8080"
        $port3 = ":1337"
        $port4 = ":5555"
        $port5 = ":4444"
        $port6 = ":8088"
        
        $cnc = "cnc." nocase
        $c2 = "c2." nocase
        $command = "command" nocase
        $report = "/report" nocase
    
    condition:
        $ip_pattern and any of ($port*, $cnc, $c2, $command, $report) and filesize < 2MB
}

rule C2_Protocol_Patterns
{
    meta:
        description = "Detects C2 protocol communication patterns"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        mitre_attack = "T1071"
    
    strings:
        $http_get = "GET /command HTTP/1.1" nocase
        $http_post = "POST /report HTTP/1.1" nocase
        $user_agent = "User-Agent: Mozilla/5.0" nocase
        $bot_id = "bot_id=" nocase
        $ip_param = "&ip=" nocase
        $port_param = "&port=" nocase
        $sleep = "sleep(" nocase
        $ping = "ping" nocase
        
        $base64 = /[A-Za-z0-9\+\/]{50,}={0,2}/  
    
    condition:
        any of them and filesize < 1MB
}

rule Kimwolf_C2_Specific
{
    meta:
        description = "Detects Kimwolf-specific C2 patterns"
        author = "Downpour v29 Titanium"
        date = "2026-05-02"
        reference = "https://www.kaspersky.com/blog/kimwolf-botnet/"
    
    strings:
        $kimwolf1 = "14emeliaterracewestroxburyma02132.su" nocase
        $kimwolf2 = "rtrdedge1.samsungcdn.cloud" nocase
        $kimwolf3 = "realizationnewestfangs.com" nocase
        $kimwolf4 = "adlinknetwork.vn" nocase
        $kimwolf5 = "service.adlinknetwork.vn" nocase
        $kimwolf6 = "monetisetrk5.co.uk" nocase
        $kimwolf7 = "twizzter6net.info" nocase
        $kimwolf8 = "byteconnect.net" nocase
        $kimwolf9 = "sdk.byteconnect.net" nocase
        $kimwolf10 = "plainproxies.com" nocase
        $kimwolf11 = "api.plainproxies.com" nocase
        $kimwolf12 = "ipidea.net" nocase
        $kimwolf13 = "ipidea.io" nocase
        $kimwolf14 = "ipidea.org" nocase
        $kimwolf15 = "grass.io" nocase
        $kimwolf16 = "api.grass.io" nocase
        $kimwolf17 = "device.grass.io" nocase
        $kimwolf18 = "peachpit.ad" nocase
        $kimwolf19 = "texel.us" nocase
        $kimwolf20 = "pawsatyou.eth" nocase
    
    condition:
        any of them and filesize < 1MB
}
