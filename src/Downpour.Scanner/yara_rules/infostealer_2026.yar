/*
    YARA Rules for 2026 Info-Stealer Detection
    Downpour v29 Titanium - Credential Theft Detection

    Covers ACR Stealer, browser credential access patterns,
    and common stealer infrastructure indicators.
*/

rule infostealer_browser_credential_access
{
    meta:
        author = "Downpour Security"
        version = "29.80"
        date = "2026-09-16"
        category = "credential_access"
        severity = "critical"
        mitre = "T1555.003"
        description = "Detects patterns of browser credential database access"
    strings:
        $db1 = "Login Data" ascii wide
        $db2 = "Web Data" ascii wide
        $db3 = "Cookies" ascii wide
        $db4 = "Local State" ascii wide
        $db5 = "History" ascii wide
        $chrome = "Google\\Chrome\\User Data" ascii wide nocase
        $edge = "Microsoft\\Edge\\User Data" ascii wide nocase
        $brave = "BraveSoftware\\Brave-Browser\\User Data" ascii wide nocase
        $opera = "Opera Software" ascii wide nocase
        $sql1 = "SELECT" ascii wide nocase
        $sql2 = "password_value" ascii wide nocase
        $sql3 = "encrypted_key" ascii wide nocase
        $dpapi = "CryptUnprotectData" ascii wide
    condition:
        2 of ($db*) and 1 of ($chrome, $edge, $brave, $opera) and (1 of ($sql*) or $dpapi)
}

rule infostealer_crypto_wallet_theft
{
    meta:
        author = "Downpour Security"
        version = "29.80"
        date = "2026-09-16"
        category = "credential_access"
        severity = "critical"
        description = "Detects targeting of cryptocurrency wallet files and extensions"
    strings:
        $wallet1 = "wallet.dat" ascii wide nocase
        $wallet2 = "keystore" ascii wide nocase
        $ext1 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide  // MetaMask
        $ext2 = "ibnejdfjmmkpcnlpebklmnkoeoihofec" ascii wide  // TronLink
        $ext3 = "fhbohimaelbohpjbbldcngcnapndodjp" ascii wide  // Binance
        $ext4 = "jbdaocneiiinmjbjlgalhcelgbejmnid" ascii wide  // Nifty
        $ext5 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii wide  // Phantom
        $path = "Local Extension Settings" ascii wide nocase
    condition:
        2 of ($wallet*) or (1 of ($ext*) and $path)
}

rule infostealer_dpapi_abuse
{
    meta:
        author = "Downpour Security"
        version = "29.80"
        date = "2026-09-16"
        category = "credential_access"
        severity = "high"
        mitre = "T1555.004"
        description = "Detects DPAPI abuse for credential decryption"
    strings:
        $api1 = "CryptUnprotectData" ascii wide
        $_api2 = "CryptProtectData" ascii wide
        $master1 = "Microsoft\\Protect" ascii wide
        $master2 = "S-1-5-21-" ascii wide
        $chrome_key = "encrypted_key" ascii wide
        $dpapi_blob = { 01 00 00 00 D0 8C 9D DF 01 15 D1 11 }  // DPAPI blob header
    condition:
        $api1 and ($master1 or $master2 or $chrome_key or $dpapi_blob)
}

rule infostealer_clipboard_hijacker
{
    meta:
        author = "Downpour Security"
        version = "29.80"
        date = "2026-09-16"
        category = "collection"
        severity = "high"
        mitre = "T1115"
        description = "Detects clipboard monitoring and cryptocurrency address replacement"
    strings:
        $api1 = "OpenClipboard" ascii wide
        $api2 = "GetClipboardData" ascii wide
        $api3 = "SetClipboardData" ascii wide
        $api4 = "AddClipboardFormatListener" ascii wide
        $btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii wide
        $eth = /0x[0-9a-fA-F]{40}/ ascii wide
    condition:
        ($api1 and $api3) or ($api4 and ($api2 or $api3)) or
        (2 of ($api*) and ($btc or $eth))
}

rule infostealer_keylogger_api
{
    meta:
        author = "Downpour Security"
        version = "29.80"
        date = "2026-09-16"
        category = "collection"
        severity = "high"
        mitre = "T1056.001"
        description = "Detects keylogger API usage patterns"
    strings:
        $api1 = "SetWindowsHookEx" ascii wide
        $api2 = "GetAsyncKeyState" ascii wide
        $_api3 = "GetKeyState" ascii wide
        $api4 = "GetKeyboardState" ascii wide
        $api5 = "GetForegroundWindow" ascii wide
        $api6 = "GetWindowText" ascii wide
        $hook_type = { 0D 00 00 00 }  // WH_KEYBOARD_LL = 13
    condition:
        ($api1 and $hook_type) or
        ($api2 and $api5 and $api6) or
        ($api4 and $api5)
}
