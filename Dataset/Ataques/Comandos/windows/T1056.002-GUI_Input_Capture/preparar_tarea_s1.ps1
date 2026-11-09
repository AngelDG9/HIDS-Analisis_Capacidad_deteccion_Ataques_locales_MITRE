# Prepara la tarea S1 de ATA104 (sesion interactiva GUI).
# Uso: powershell -NoProfile -ExecutionPolicy Bypass -File preparar_tarea_s1.ps1
# La tarea dispara a los 30 s; el runner tambien la crea en su ruta -S1.
$taskName = 'TFG-Attack-ATA104'
$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c C:\lab-attack\ATA104\run.cmd'
$trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddSeconds(30))
$principal = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\angel" -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
$info = Get-ScheduledTask -TaskName $taskName | Select-Object -ExpandProperty Principal | Format-List LogonType,UserId
Write-Output "tarea=$taskName trigger=+30s"
Write-Output $info
