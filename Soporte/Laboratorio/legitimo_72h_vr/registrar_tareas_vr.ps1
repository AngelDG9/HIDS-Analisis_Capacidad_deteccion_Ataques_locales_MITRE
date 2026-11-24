# ============================================================================
# registrar_tareas_vr.ps1 - tareas del HOST para la ventana de 72 h con Velociraptor (V1-L).
# Adaptacion de `legitimo_72h/registrar_tareas.ps1` (Wazuh; no se modifica). Diferencias DECLARADAS:
#   - SOLO dos tareas, y NINGUNA necesita la contrasena de la VM (la regla es «solo en memoria»):
#       TFG-LegitVR-Watch     cada 30 min desde t0: vigilancia (solo lee el servidor VR y el PC; sin SSH a la victima)
#       TFG-LegitVR-Servidor  cada 30 min desde t0-60 min: reinicia el servidor de Velociraptor si ha caido (idempotente; archiva el log)
#   - Prep, Arm y la cosecha NO se programan: los ejecuta el operador en vivo con la contrasena SOLO en la memoria de su proceso.
#   - NO hay tarea de parada (la VM se para a mano, despues de verificar la cosecha).
#   - NO existe -SetSecret: no se guarda ninguna contrasena (ni en variables de usuario ni en el registro).
# Uso:  powershell -NoProfile -ExecutionPolicy Bypass -File registrar_tareas_vr.ps1 -T0 2026-11-30T00:00:00Z -T1 2026-12-03T00:00:00Z [-Verificar | -Eliminar]
# Requiere sesion de administrador. ASCII puro. Sin secretos.
# ============================================================================
param(
  [string]$T0 = '2026-11-30T00:00:00Z',
  [string]$T1 = '2026-12-03T00:00:00Z',
  [switch]$Verificar,
  [switch]$Eliminar
)
$ErrorActionPreference = 'Stop'
$Repo = 'D:\TFG\HIDS-Analisis_Capacidad_deteccion_Ataques_locales_MITRE'
$Ctl  = Join-Path $Repo 'Soporte\Laboratorio\legitimo_72h_vr\legitimo_host_control_vr.ps1'
$Srv  = Join-Path $Repo 'Soporte\Laboratorio\velociraptor\arrancar_servidor.ps1'
$User = "$env:USERDOMAIN\$env:USERNAME"
$WATCH = 'TFG-LegitVR-Watch'; $SERV = 'TFG-LegitVR-Servidor'
$NOMBRES = @($WATCH, $SERV)

if ($Eliminar) {
  foreach ($n in $NOMBRES) { Unregister-ScheduledTask -TaskName $n -Confirm:$false -ErrorAction SilentlyContinue; Write-Host "eliminada: $n" }
  exit 0
}
if ($Verificar) {
  $t = Get-ScheduledTask -TaskName $NOMBRES -ErrorAction SilentlyContinue
  if (-not $t) { Write-Host 'NO hay tareas TFG-LegitVR-* registradas.'; exit 0 }
  $t | Get-ScheduledTaskInfo | ForEach-Object {
    [pscustomobject]@{ TaskName = $_.TaskName; NextRun_local = $_.NextRunTime
      NextRun_UTC = if ($_.NextRunTime) { $_.NextRunTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '-' }
      LastRun = $_.LastRunTime; Result = $_.LastTaskResult }
  } | Format-Table -AutoSize
  exit 0
}

$t0u = [datetime]::Parse($T0).ToUniversalTime(); $t1u = [datetime]::Parse($T1).ToUniversalTime()
if ($t1u -le $t0u) { throw "T1 ($T1) debe ser posterior a T0 ($T0)" }
$t0l = $t0u.ToLocalTime()
$durHoras = [math]::Ceiling(($t1u - $t0u).TotalHours) + 1

function New-TfgTask($name, $exe, $arg, [datetime]$at, $repeticionMin, $durHoras, $limitHoras) {
  $action = New-ScheduledTaskAction -Execute $exe -Argument $arg
  $trigger = New-ScheduledTaskTrigger -Once -At $at -RepetitionInterval (New-TimeSpan -Minutes $repeticionMin) -RepetitionDuration (New-TimeSpan -Hours $durHoras)
  $principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours $limitHoras) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
  Write-Host ("registrada: {0}  local={1}  UTC={2}  cada {3} min" -f $name, $at.ToString('yyyy-MM-dd HH:mm'), $at.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), $repeticionMin)
}

New-TfgTask $WATCH 'powershell.exe' ("-NoProfile -ExecutionPolicy Bypass -File `"$Ctl`" -Phase watch -T0 $T0 -T1 $T1") $t0l 30 $durHoras 1
New-TfgTask $SERV  'powershell.exe' ("-NoProfile -ExecutionPolicy Bypass -File `"$Srv`"") $t0l.AddMinutes(-60) 30 ($durHoras + 1) 1
Write-Host ''
Write-Host 'RECUERDA: Prep, Arm y la cosecha los ejecuta el operador en vivo (contrasena solo en memoria). No hay tarea de parada.'
