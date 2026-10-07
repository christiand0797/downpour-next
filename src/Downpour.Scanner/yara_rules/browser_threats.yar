rule Malicious_Browser_Extension_Loader
{
    meta:
        author = "Downpour v29"
        version = "1.0"
        date = "2026-09-16"
        category = "browser"
        severity = "high"
        mitre = "T1176"
        description = "Detects malicious browser extension installers and loaders"

    strings:
        $ext1 = "chrome.runtime.sendMessage" ascii
        $ext2 = "browser.runtime.sendMessage" ascii
        $ext3 = "chrome.tabs.executeScript" ascii
        $ext4 = "chrome.webRequest.onBeforeRequest" ascii
        $steal1 = "document.cookie" ascii
        $steal2 = "localStorage.getItem" ascii
        $steal3 = "sessionStorage" ascii
        $exfil1 = /https?:\/\/[a-z0-9]{8,}\./ ascii
        $exfil2 = "XMLHttpRequest" ascii
        $exfil3 = "fetch(" ascii
        $crypto1 = "wallet" ascii nocase
        $crypto2 = "metamask" ascii nocase
        $crypto3 = "seed phrase" ascii nocase
        $crypto4 = "private key" ascii nocase

    condition:
        (any of ($ext*)) and (any of ($steal*)) and (any of ($exfil*)) or
        (any of ($ext*)) and (2 of ($crypto*))
}

rule Browser_Credential_Stealer
{
    meta:
        author = "Downpour v29"
        version = "1.0"
        date = "2026-09-16"
        category = "infostealer"
        severity = "critical"
        mitre = "T1555.003"
        description = "Detects tools targeting browser credential databases"

    strings:
        $db1 = "Login Data" ascii wide
        $db2 = "Cookies" ascii wide
        $db3 = "Web Data" ascii wide
        $db4 = "History" ascii wide
        $path1 = "\\Google\\Chrome\\User Data" ascii wide
        $path2 = "\\Microsoft\\Edge\\User Data" ascii wide
        $path3 = "\\BraveSoftware\\Brave-Browser" ascii wide
        $path4 = "\\Mozilla\\Firefox\\Profiles" ascii wide
        $decrypt1 = "CryptUnprotectData" ascii wide
        $decrypt2 = "BCryptDecrypt" ascii wide
        $decrypt3 = "DPAPI" ascii wide
        $sqlite1 = "SELECT * FROM logins" ascii nocase
        $sqlite2 = "SELECT * FROM cookies" ascii nocase
        $sqlite3 = "password_value" ascii

    condition:
        (2 of ($path*)) and (any of ($db*)) and
        ((any of ($decrypt*)) or (any of ($sqlite*)))
}

rule C2_Beacon_Framework
{
    meta:
        author = "Downpour v29"
        version = "1.0"
        date = "2026-09-16"
        category = "c2"
        severity = "critical"
        mitre = "T1071"
        description = "Detects C2 beacon framework indicators"

    strings:
        $cs1 = "beacon" ascii nocase
        $cs2 = "sleep" ascii
        $cs3 = "jitter" ascii
        $cs4 = "callback" ascii
        $cs5 = "stage" ascii
        $cs6 = "listener" ascii
        $pipe1 = "\\\\.\\pipe\\" ascii
        $pipe2 = "named pipe" ascii nocase
        $http1 = "User-Agent:" ascii
        $http2 = "POST" ascii
        $http3 = "Cookie:" ascii
        $enc1 = "AES" ascii
        $enc2 = "XOR" ascii
        $enc3 = "base64" ascii nocase
        $mal1 = "shellcode" ascii nocase
        $mal2 = "inject" ascii nocase
        $mal3 = "spawn" ascii nocase

    condition:
        (3 of ($cs*)) and (any of ($pipe*) or 2 of ($http*)) and
        (any of ($enc*)) and (any of ($mal*))
}

rule WiFi_Attack_Tool
{
    meta:
        author = "Downpour v29"
        version = "1.0"
        date = "2026-09-16"
        category = "wireless"
        severity = "high"
        mitre = "T1557.002"
        description = "Detects WiFi attack tools and rogue AP software"

    strings:
        $tool1 = "aircrack" ascii nocase
        $tool2 = "airmon" ascii nocase
        $tool3 = "aireplay" ascii nocase
        $tool4 = "wifipumpkin" ascii nocase
        $tool5 = "hostapd" ascii nocase
        $tool6 = "fluxion" ascii nocase
        $tool7 = "wifiphisher" ascii nocase
        $tool8 = "evil twin" ascii nocase
        $tool9 = "karma attack" ascii nocase
        $tool10 = "mana attack" ascii nocase
        $deauth1 = "deauthentication" ascii nocase
        $deauth2 = "deauth" ascii nocase
        $deauth3 = "disassociation" ascii nocase
        $rogue1 = "rogue ap" ascii nocase
        $rogue2 = "fake access point" ascii nocase
        $rogue3 = "captive portal" ascii nocase

    condition:
        3 of them
}
