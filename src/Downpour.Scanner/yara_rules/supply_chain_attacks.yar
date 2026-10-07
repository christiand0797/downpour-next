/*
    YARA Rules for Supply Chain Attack Detection
    Downpour v29 Titanium

    Detects supply chain compromise patterns:
      - Malicious npm/pip/NuGet packages
      - Trojanized installers
      - Compromised CI/CD artifacts
      - Typosquatting package indicators
      - Software update hijacking
*/

rule supply_chain_malicious_npm
{
    meta:
        author = "Downpour Security"
        version = "29.81"
        date = "2026-09-16"
        category = "supply_chain"
        severity = "high"
        description = "Detects malicious patterns in npm package files"
    strings:
        $npm1 = "package.json" ascii
        $npm2 = "postinstall" ascii
        $cmd1 = "child_process" ascii
        $cmd2 = "exec(" ascii
        $cmd3 = "spawn(" ascii
        $exfil1 = "webhook.site" ascii nocase
        $exfil2 = "pipedream" ascii nocase
        $exfil3 = "requestbin" ascii nocase
        $exfil4 = "burpcollaborator" ascii nocase
        $eval1 = "eval(" ascii
        $eval2 = "Buffer.from(" ascii
        $eval3 = "atob(" ascii
        $dns_exfil = "dns.resolve" ascii
    condition:
        ($npm1 or $npm2) and
        (1 of ($cmd*)) and
        (1 of ($exfil*) or 1 of ($eval*) or $dns_exfil)
}

rule supply_chain_pip_malicious
{
    meta:
        author = "Downpour Security"
        version = "29.81"
        date = "2026-09-16"
        category = "supply_chain"
        severity = "high"
        description = "Detects malicious patterns in Python packages"
    strings:
        $setup1 = "setup.py" ascii
        $setup2 = "setup(" ascii
        $setup3 = "__init__.py" ascii
        $cmd1 = "subprocess" ascii
        $cmd2 = "os.system" ascii
        $cmd3 = "os.popen" ascii
        $exfil1 = "requests.post" ascii
        $exfil2 = "urllib.request" ascii
        $steal1 = "DISCORD_TOKEN" ascii
        $steal2 = "chrome" ascii nocase
        $steal3 = "Login Data" ascii
        $steal4 = "wallet" ascii nocase
        $b64 = "base64.b64decode" ascii
        $compile = "compile(" ascii
    condition:
        1 of ($setup*) and
        1 of ($cmd*) and
        (1 of ($exfil*) or 2 of ($steal*) or ($b64 and $compile))
}

rule supply_chain_trojanized_installer
{
    meta:
        author = "Downpour Security"
        version = "29.81"
        date = "2026-09-16"
        category = "supply_chain"
        severity = "critical"
        description = "Detects installers with embedded malicious payloads"
    strings:
        $installer1 = "Inno Setup" ascii wide
        $installer2 = "Nullsoft" ascii wide
        $installer3 = "InstallShield" ascii wide
        $installer4 = "WiX Toolset" ascii wide
        $mz = { 4D 5A }
        $shellcode1 = { FC E8 ?? 00 00 00 }    // call $+N shellcode pattern
        $shellcode2 = { 31 C9 64 8B 41 30 }    // xor ecx,ecx; mov eax,fs:[ecx+30] (PEB)
        $inject1 = "VirtualAlloc" ascii
        $inject2 = "CreateRemoteThread" ascii
        $inject3 = "WriteProcessMemory" ascii
        $c2_1 = "beacon" ascii nocase
        $c2_2 = "payload" ascii nocase
    condition:
        $mz at 0 and
        1 of ($installer*) and
        (1 of ($shellcode*) or (2 of ($inject*)) or 2 of ($c2_*))
}

rule supply_chain_github_action_compromise
{
    meta:
        author = "Downpour Security"
        version = "29.81"
        date = "2026-09-16"
        category = "supply_chain"
        severity = "high"
        description = "Detects compromised GitHub Actions workflow patterns"
    strings:
        $action1 = "uses:" ascii
        $action2 = "run:" ascii
        $action3 = "github.token" ascii
        $exfil1 = "curl " ascii
        $exfil2 = "wget " ascii
        $secret1 = "secrets." ascii
        $secret2 = "GITHUB_TOKEN" ascii
        $base64 = "base64" ascii
        $rev_shell = "bash -i" ascii
    condition:
        2 of ($action*) and
        (1 of ($exfil*) and $secret1) or
        ($rev_shell) or
        ($base64 and $secret2)
}
