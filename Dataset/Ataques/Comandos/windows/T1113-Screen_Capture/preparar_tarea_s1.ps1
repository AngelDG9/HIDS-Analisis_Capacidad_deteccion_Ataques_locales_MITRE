param(
    [Parameter(Mandatory=$true)][datetime]$TriggerLocal,
    [string]$Ata = 'ATA071'
)
$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c C:\lab-attack\$Ata\run.cmd"
$trigger = New-ScheduledTaskTrigger -Once -At $TriggerLocal
$principal = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\angel" -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName "TFG-Attack-$Ata" -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
Write-Output "tarea=TFG-Attack-$Ata trigger=$($TriggerLocal.ToString('yyyy-MM-ddTHH:mm:ss'))"
