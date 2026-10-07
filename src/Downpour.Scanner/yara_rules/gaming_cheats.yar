rule Gaming_Cheat_Engine
{
    meta:
        author = "Downpour v29 Titanium"
        version = "1.0"
        date = "2024-12-01"
        category = "gaming-protection"
        severity = "critical"
        mitre = "T1055"
        description = "Detects Cheat Engine and similar memory editors targeting games"

    strings:
        $ce1 = "cheatengine" ascii nocase
        $ce2 = "Cheat Engine" ascii wide
        $ce3 = "CheatEngine" ascii nocase
        $ce4 = "ce.exe" ascii nocase
        $am1 = "artmoney" ascii nocase
        $am2 = "ArtMoney" ascii wide
        $gg1 = "GameGuardian" ascii nocase
        $wemod = "WeMod" ascii nocase
        $plitch = "PLITCH" ascii nocase
        $cosmos = "CosmosProject" ascii nocase
        $reclass = "ReClass" ascii nocase
        $speed1 = "speedhack" ascii nocase
        $speed2 = "SpeedHack" ascii wide
        $trainer1 = "GameTrainer" ascii nocase
        $trainer2 = "FLiNG Trainer" ascii nocase
        $trainer3 = "MrAntiFun" ascii nocase

    condition:
        any of them
}

rule DLL_Injection_Gaming
{
    meta:
        author = "Downpour v29 Titanium"
        version = "1.0"
        date = "2024-12-01"
        category = "gaming-protection"
        severity = "critical"
        mitre = "T1055.001"
        description = "Detects DLL injectors commonly used for game hacking"

    strings:
        $inj1 = "Extreme Injector" ascii wide
        $inj2 = "Process Injector" ascii nocase
        $inj3 = "DLL Injector" ascii nocase
        $inj4 = "Xenos" ascii nocase
        $inj5 = "GDIHook" ascii nocase
        $inj6 = "CreateRemoteThread" ascii
        $inj7 = "NtCreateThreadEx" ascii
        $inj8 = "RtlCreateUserThread" ascii
        $inj9 = "QueueUserAPC" ascii
        $inj10 = "SetWindowsHookEx" ascii

    condition:
        2 of them
}

rule Network_DDoS_Gaming
{
    meta:
        author = "Downpour v29 Titanium"
        version = "1.0"
        date = "2024-12-01"
        category = "gaming-protection"
        severity = "critical"
        mitre = "T1498"
        description = "Detects DDoS and lag tools used against gamers"

    strings:
        $loic1 = "LOIC" ascii
        $loic2 = "LowOrbitIonCannon" ascii nocase
        $hoic = "HOIC" ascii
        $xerxes = "xerxes" ascii nocase
        $slowloris = "slowloris" ascii nocase
        $goldeneye = "GoldenEye" ascii nocase
        $hulk = "hulk.py" ascii nocase
        $hping = "hping" ascii nocase
        $lagswitch1 = "lag switch" ascii nocase
        $lagswitch2 = "LagSwitch" ascii nocase
        $clumsy = "clumsy.exe" ascii nocase
        $netlim = "NetLimiter" ascii nocase

    condition:
        any of them
}
