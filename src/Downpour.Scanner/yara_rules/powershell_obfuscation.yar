/*
    PowerShell Obfuscation Detection
    Downpour v29 Titanium

    Detects advanced PowerShell obfuscation techniques:
      - String concatenation obfuscation
      - Character/byte array construction
      - Invoke-Obfuscation tool patterns
      - Encoding and compression chains
      - Variable substitution tricks
*/

rule ps_obfuscation_string_concat {
    meta:
        author = "Downpour Security"
        version = "1.0"
        date = "2026-09-16"
        category = "powershell"
        severity = "high"
        mitre = "T1027.010"
        description = "PowerShell string concatenation obfuscation"

    strings:
        $concat1 = /\('[A-Za-z]'\s*\+\s*'[A-Za-z]'\s*\+\s*'[A-Za-z]'\s*\+\s*'[A-Za-z]'\s*\+/ ascii wide nocase
        $concat2 = "-join" ascii wide nocase
        $concat3 = "[char]" ascii wide nocase
        $concat4 = "[int]" ascii wide nocase
        $concat5 = "-replace" ascii wide nocase
        $iex = "iex" ascii wide nocase
        $invoke = "Invoke-Expression" ascii wide nocase
        $format = "-f" ascii wide nocase
        $split_join = "-split" ascii wide nocase

    condition:
        ($concat1 and ($iex or $invoke)) or
        ($concat3 and $concat4 and ($iex or $invoke)) or
        (3 of ($concat2, $concat5, $format, $split_join) and ($iex or $invoke))
}

rule ps_obfuscation_tick_marks {
    meta:
        author = "Downpour Security"
        version = "1.0"
        date = "2026-09-16"
        category = "powershell"
        severity = "high"
        mitre = "T1027.010"
        description = "PowerShell backtick obfuscation (tick-mark insertion)"

    strings:
        $tick1 = "I`n`v`o`k`e" ascii wide nocase
        $tick2 = "N`e`w`-`O`b`j" ascii wide nocase
        $tick3 = "D`o`w`n`l`o`a`d" ascii wide nocase
        $tick4 = "W`e`b`C`l`i`e`n`t" ascii wide nocase
        $tick5 = "S`t`a`r`t`-`P`r" ascii wide nocase
        $tick_pattern = /[A-Za-z]`[A-Za-z]`[A-Za-z]`[A-Za-z]`[A-Za-z]/

    condition:
        any of ($tick1, $tick2, $tick3, $tick4, $tick5) or
        #tick_pattern > 3
}

rule ps_obfuscation_invoke_obfuscation {
    meta:
        author = "Downpour Security"
        version = "1.0"
        date = "2026-09-16"
        category = "powershell"
        severity = "critical"
        mitre = "T1027.010"
        description = "Invoke-Obfuscation tool output patterns"

    strings:
        $set_var = /\$\{[^}]{20,}\}/ ascii wide
        $env_comspec = "$env:ComSpec[4,15,25]" ascii wide nocase
        $env_trick = "$env:Public[13]" ascii wide nocase
        $salloc = "[Runtime.InteropServices.Marshal]::" ascii wide
        $reversible = ".Invoke(" ascii wide
        $char_array = /\[char\[\]\]\s*\(\s*[0-9]{2,3}\s*,/ ascii wide
        $scriptblock = "[ScriptBlock]::Create(" ascii wide nocase

    condition:
        $set_var or
        ($env_comspec or $env_trick) or
        ($salloc and $reversible) or
        ($char_array and $scriptblock)
}

rule ps_obfuscation_compression_chain {
    meta:
        author = "Downpour Security"
        version = "1.0"
        date = "2026-09-16"
        category = "powershell"
        severity = "high"
        mitre = "T1027"
        description = "PowerShell compression/encoding execution chain"

    strings:
        $frombase64 = "FromBase64String" ascii wide nocase
        $decompress = "DeflateStream" ascii wide nocase
        $gzip = "GZipStream" ascii wide nocase
        $memstream = "MemoryStream" ascii wide nocase
        $streamread = "StreamReader" ascii wide nocase
        $readtoend = "ReadToEnd" ascii wide nocase
        $iex = "IEX" ascii wide nocase
        $invoke = "Invoke-Expression" ascii wide nocase

    condition:
        $frombase64 and ($decompress or $gzip) and $memstream and ($iex or $invoke) or
        $frombase64 and $memstream and $streamread and $readtoend and ($iex or $invoke)
}

rule ps_obfuscation_securestring_abuse {
    meta:
        author = "Downpour Security"
        version = "1.0"
        date = "2026-09-16"
        category = "powershell"
        severity = "high"
        mitre = "T1140"
        description = "SecureString abuse for payload decryption"

    strings:
        $secure1 = "ConvertTo-SecureString" ascii wide nocase
        $secure2 = "SecureStringToBSTR" ascii wide nocase
        $secure3 = "PtrToStringAuto" ascii wide nocase
        $secure4 = "PtrToStringBSTR" ascii wide nocase
        $key = "-Key" ascii wide nocase
        $iex = "IEX" ascii wide nocase
        $invoke = "Invoke-Expression" ascii wide nocase

    condition:
        ($secure1 and $key and ($iex or $invoke)) or
        ($secure2 and $secure3 and ($iex or $invoke)) or
        ($secure2 and $secure4 and ($iex or $invoke))
}
