/*
    YARA Rules for Webshell and Backdoor Detection
    Downpour v29 Titanium

    Detects web shells, reverse shells, and persistent backdoors
    commonly used for maintaining access after initial compromise.
*/

rule webshell_generic_php
{
    meta:
        author = "Downpour Security"
        version = "29.81"
        date = "2026-09-16"
        category = "persistence"
        severity = "critical"
        mitre = "T1505.003"
        description = "Detects generic PHP webshell patterns"
    strings:
        $php = "<?php" ascii nocase
        $eval1 = "eval(" ascii nocase
        $eval2 = "assert(" ascii nocase
        $eval3 = "preg_replace" ascii nocase
        $cmd1 = "system(" ascii nocase
        $cmd2 = "exec(" ascii nocase
        $cmd3 = "passthru(" ascii nocase
        $cmd4 = "shell_exec(" ascii nocase
        $cmd5 = "popen(" ascii nocase
        $obf1 = "base64_decode" ascii nocase
        $obf2 = "gzuncompress" ascii nocase
        $obf3 = "str_rot13" ascii nocase
        $obf4 = "gzinflate" ascii nocase
        $input1 = "$_REQUEST" ascii
        $input2 = "$_POST" ascii
        $input3 = "$_GET" ascii
        $input4 = "$_FILES" ascii
    condition:
        $php and
        (1 of ($eval*) or 1 of ($cmd*)) and
        (1 of ($obf*) or 1 of ($input*))
}

rule webshell_aspx
{
    meta:
        author = "Downpour Security"
        version = "29.81"
        date = "2026-09-16"
        category = "persistence"
        severity = "critical"
        mitre = "T1505.003"
        description = "Detects ASPX webshell patterns"
    strings:
        $aspx = "<%@" ascii nocase
        $cmd1 = "Process.Start" ascii
        $cmd2 = "ProcessStartInfo" ascii
        $cmd3 = "cmd.exe" ascii
        $cmd4 = "powershell" ascii nocase
        $io1 = "Request.Form" ascii
        $io2 = "Request.QueryString" ascii
        $io3 = "Request.Params" ascii
        $reflect = "Assembly.Load" ascii
        $compile = "CompileAssemblyFromSource" ascii
    condition:
        $aspx and
        (1 of ($cmd*) or $reflect or $compile) and
        1 of ($io*)
}

rule reverse_shell_generic
{
    meta:
        author = "Downpour Security"
        version = "29.81"
        date = "2026-09-16"
        category = "command_and_control"
        severity = "critical"
        mitre = "T1059"
        description = "Detects reverse shell patterns across languages"
    strings:
        $py1 = "socket.socket" ascii
        $py2 = "subprocess.call" ascii
        $_py3 = "pty.spawn" ascii
        $py_rev = "s.connect((" ascii

        $ps1 = "TCPClient" ascii
        $ps2 = "GetStream" ascii
        $ps3 = "StreamReader" ascii

        $bash1 = "/dev/tcp/" ascii
        $bash2 = "bash -i" ascii
        $bash3 = "nc -e" ascii
        $bash4 = "ncat -e" ascii

        $generic1 = "reverse_tcp" ascii nocase
        $generic2 = "reverse_shell" ascii nocase
        $generic3 = "bind_shell" ascii nocase
    condition:
        ($py1 and $py2 and $py_rev) or
        ($ps1 and $ps2 and $ps3) or
        ($bash2 and $bash1) or
        ($bash3 or $bash4) or
        2 of ($generic*)
}

rule persistent_backdoor_registry
{
    meta:
        author = "Downpour Security"
        version = "29.81"
        date = "2026-09-16"
        category = "persistence"
        severity = "high"
        mitre = "T1547.001"
        description = "Detects scripts/binaries that install registry persistence"
    strings:
        $reg1 = "RegSetValueEx" ascii wide
        $reg2 = "RegCreateKeyEx" ascii wide
        $reg3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $reg4 = "CurrentVersion\\RunOnce" ascii wide nocase
        $reg5 = "Winlogon\\Shell" ascii wide nocase
        $reg6 = "Winlogon\\Userinit" ascii wide nocase
    condition:
        ($reg1 or $reg2) and 2 of ($reg3, $reg4, $reg5, $reg6)
}
