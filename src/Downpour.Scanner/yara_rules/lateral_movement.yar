rule PsExec_Lateral_Movement {
    meta:
        author = "Downpour v29 Titanium"
        version = "1.0"
        date = "2026-09-16"
        category = "lateral_movement"
        severity = "critical"
        mitre = "T1021.002"
        description = "Detects PsExec and PsExec-like lateral movement tools"
    strings:
        $psexec1 = "psexec" ascii nocase
        $psexec2 = "PSEXESVC" ascii nocase
        $psexec3 = "PsExec" ascii
        $paexec = "paexec" ascii nocase
        $remcom = "remcom" ascii nocase
        $csexec = "csexec" ascii nocase
        $winexe = "winexesvc" ascii nocase
        $svc1 = "\\pipe\\psexesvc" ascii nocase
        $svc2 = "\\pipe\\remcomsvc" ascii nocase
        $impacket1 = "impacket" ascii nocase
        $impacket2 = "wmiexec" ascii nocase
        $impacket3 = "smbexec" ascii nocase
        $impacket4 = "atexec" ascii nocase
        $impacket5 = "dcomexec" ascii nocase
    condition:
        any of ($psexec*, $paexec, $remcom, $csexec, $winexe, $svc*) or
        2 of ($impacket*)
}

rule WinRM_Lateral_Movement {
    meta:
        author = "Downpour v29 Titanium"
        version = "1.0"
        date = "2026-09-16"
        category = "lateral_movement"
        severity = "high"
        mitre = "T1021.006"
        description = "Detects WinRM-based lateral movement"
    strings:
        $winrm1 = "evil-winrm" ascii nocase
        $winrm2 = "New-PSSession" ascii nocase
        $winrm3 = "Enter-PSSession" ascii nocase
        $winrm4 = "Invoke-Command" ascii nocase
        $winrs = "winrs" ascii nocase
        $port1 = ":5985" ascii
        $port2 = ":5986" ascii
        $wsman = "WSMan" ascii nocase
    condition:
        any of ($winrm*) or
        ($winrs and any of ($port*)) or
        ($wsman and any of ($winrm*))
}

rule SMB_Share_Abuse {
    meta:
        author = "Downpour v29 Titanium"
        version = "1.0"
        date = "2026-09-16"
        category = "lateral_movement"
        severity = "high"
        mitre = "T1021.002"
        description = "Detects SMB share abuse for lateral movement"
    strings:
        $admin1 = "\\C$\\" ascii
        $admin2 = "\\ADMIN$\\" ascii
        $admin3 = "\\IPC$" ascii
        $net1 = "net use \\\\" ascii nocase
        $net2 = "net share" ascii nocase
        $cme1 = "crackmapexec" ascii nocase
        $cme2 = "cme smb" ascii nocase
        $cme3 = "nxcsmb" ascii nocase
        $secretsdump = "secretsdump" ascii nocase
    condition:
        2 of ($admin*) or
        (any of ($net*) and any of ($admin*)) or
        any of ($cme*, $secretsdump)
}

rule RDP_Lateral_Movement {
    meta:
        author = "Downpour v29 Titanium"
        version = "1.0"
        date = "2026-09-16"
        category = "lateral_movement"
        severity = "medium"
        mitre = "T1021.001"
        description = "Detects RDP abuse for lateral movement"
    strings:
        $rdp1 = "xfreerdp" ascii nocase
        $rdp2 = "rdesktop" ascii nocase
        $rdp3 = "SharpRDP" ascii nocase
        $rdp4 = "mstsc.exe /v:" ascii nocase
        $hijack1 = "tscon" ascii nocase
        $hijack2 = "RDP session hijack" ascii nocase
        $nla_bypass = "DisableRestrictedAdmin" ascii nocase
        $sticky = "sethc.exe" ascii nocase
        $util = "utilman.exe" ascii nocase
    condition:
        any of ($rdp*) or
        any of ($hijack*) or
        ($nla_bypass) or
        ($sticky and $util)
}
