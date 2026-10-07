rule WMI_Persistence_Setup
{
    meta:
        author = "Downpour v29 Titanium"
        version = "1.0"
        date = "2024-12-01"
        category = "persistence"
        severity = "critical"
        mitre = "T1546.003"
        description = "Detects WMI event subscription persistence setup"

    strings:
        $wmi1 = "CommandLineEventConsumer" ascii nocase
        $wmi2 = "ActiveScriptEventConsumer" ascii nocase
        $wmi3 = "__EventFilter" ascii nocase
        $wmi4 = "__FilterToConsumerBinding" ascii nocase
        $wmi5 = "Set-WmiInstance" ascii nocase
        $wmi6 = "Create-WMIEventSubscription" ascii nocase
        $wmi7 = "__InstanceModificationEvent" ascii nocase
        $wmi8 = "__InstanceCreationEvent" ascii nocase
        $wmi9 = "__TimerEvent" ascii nocase
        $mof1 = "#pragma namespace" ascii nocase
        $mof2 = "mofcomp" ascii nocase

    condition:
        2 of them
}

rule Scheduled_Task_Persistence
{
    meta:
        author = "Downpour v29 Titanium"
        version = "1.0"
        date = "2024-12-01"
        category = "persistence"
        severity = "high"
        mitre = "T1053.005"
        description = "Detects suspicious scheduled task creation for persistence"

    strings:
        $schtask1 = "schtasks /create" ascii nocase
        $schtask2 = "schtasks /change" ascii nocase
        $schtask3 = "Register-ScheduledTask" ascii nocase
        $schtask4 = "New-ScheduledTask" ascii nocase
        $hidden = "/RL HIGHEST" ascii nocase
        $system = "/RU SYSTEM" ascii nocase
        $onstart = "/SC ONSTART" ascii nocase
        $onlogon = "/SC ONLOGON" ascii nocase
        $_xml_task = "<?xml" ascii nocase
        $_task_ns = "http://schemas.microsoft.com/windows/2004/02/mit/task" ascii nocase

    condition:
        ($schtask1 or $schtask2 or $schtask3 or $schtask4) and ($hidden or $system or $onstart or $onlogon)
}
