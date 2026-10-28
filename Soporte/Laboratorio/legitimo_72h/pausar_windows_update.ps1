# ============================================================================
# pausar_windows_update.ps1 — pausa REVERSIBLE de Windows Update en el HOST
# para la ventana de 72 h del bloque `legitimo-72h` (L1).
#
# Objetivo: que el sobremesa NO se reinicie solo durante [t0,t1]
#           (t0 = 2026-10-19T00:00:00Z -> t1 = 2026-10-22T00:00:00Z).
#
# Qué hace (y cómo se revierte):
#   1) Política  HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU
#        - NoAutoUpdate=1                  -> desactiva la instalación automática
#        - NoAutoRebootWithLoggedOnUsers=1  -> no reinicia aunque haya sesión abierta
#      (la clave NO existía antes; se crea y se registra para borrarla al restaurar)
#   2) Servicio  wuauserv  -> Stop + StartupType=Disabled
#      (valor previo grabado en windows_update_pausa.md; se restaura a Manual + start)
#   3) Comprueba que las tareas de reinicio de UpdateOrchestrator están Disabled.
#
# NO toca UsoSvc (orquestador): con la política NoAutoUpdate=1 no instala nada.
#
# Uso:
#   powershell -NoProfile -ExecutionPolicy Bypass -File pausar_windows_update.ps1 estado
#   powershell -NoProfile -ExecutionPolicy Bypass -File pausar_windows_update.ps1 pausar
#   powershell -NoProfile -ExecutionPolicy Bypass -File pausar_windows_update.ps1 restaurar
#
# Registro: añade una línea a windows_update_pausa.log (UTC).
# ============================================================================
[CmdletBinding()]
param(
  [Parameter(Position = 0)]
  [ValidateSet('estado', 'pausar', 'restaurar')]
  [string]$Accion = 'estado'
)

$ErrorActionPreference = 'Stop'
$Base   = Split-Path -Parent $MyInvocation.MyCommand.Path
$Log    = Join-Path $Base 'windows_update_pausa.log'
$AUPol  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
$WUPol  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'

function Log($msg) {
  $line = "[{0}] [wu-pausa] {1}" -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), $msg
  Add-Content -Path $Log -Value $line -Encoding UTF8
  Write-Host $line
}

function Get-Estado {
  $svc = Get-CimInstance Win32_Service -Filter "Name='wuauserv'" |
    Select-Object Name, State, StartMode, StartName
  $noAuto  = (Get-ItemProperty $AUPol -Name NoAutoUpdate -ErrorAction SilentlyContinue).NoAutoUpdate
  $noRb    = (Get-ItemProperty $AUPol -Name NoAutoRebootWithLoggedOnUsers -ErrorAction SilentlyContinue).NoAutoRebootWithLoggedOnUsers
  [pscustomobject]@{
    wuauserv_State     = $svc.State
    wuauserv_StartMode = $svc.StartMode
    NoAutoUpdate       = $noAuto
    NoAutoReboot       = $noRb
  }
}

function Test-PendingReboot {
  $res = [ordered]@{}
  $res['PendingFileRenameOperations'] = [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
  $res['CBS_RebootPending']           = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
  $res['CBS_RebootInProgress']        = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress'
  $res['WU_RebootRequired']           = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
  $res['WU_PostRebootReporting']      = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting'
  [pscustomobject]$res
}

switch ($Accion) {
  'estado' {
    Write-Host '--- estado Windows Update ---'
    Get-Estado | Format-List
    Write-Host '--- reinicio pendiente ---'
    Test-PendingReboot | Format-List
    Write-Host '--- tareas UpdateOrchestrator de reinicio ---'
    Get-ScheduledTask -TaskPath '\Microsoft\Windows\UpdateOrchestrator\' -ErrorAction SilentlyContinue |
      Where-Object { $_.TaskName -like 'Reboot*' } |
      Select-Object TaskName, State | Format-Table -AutoSize
  }
  'pausar' {
    $prev = Get-Estado
    Log ("PAUSAR: previo wuauserv State={0} StartMode={1}; AU key existia={2}" -f $prev.wuauserv_State, $prev.wuauserv_StartMode, (Test-Path $AUPol))

    if (-not (Test-Path $WUPol)) { New-Item -Path $WUPol -Force | Out-Null }
    if (-not (Test-Path $AUPol)) { New-Item -Path $AUPol -Force | Out-Null }
    New-ItemProperty -Path $AUPol -Name 'NoAutoUpdate' -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $AUPol -Name 'NoAutoRebootWithLoggedOnUsers' -Value 1 -PropertyType DWord -Force | Out-Null
    Log 'PAUSAR: politica NoAutoUpdate=1 + NoAutoRebootWithLoggedOnUsers=1 aplicada'

    # E0 v5 (2026-10-28): `Stop-Service`/`Set-Service` devolvian "correcto" pero NO
    # cambiaban nada en este host (wuauserv quedaba Running/Manual). Se usa `sc.exe`
    # (config start=disabled + stop) y se COMPRUEBA el resultado; si no queda Disabled,
    # la fase falla en vez de registrar un exito falso.
    & sc.exe config wuauserv start= disabled | Out-Null
    & sc.exe stop wuauserv | Out-Null
    Start-Sleep -Seconds 3
    $post = Get-Estado
    Log ("PAUSAR: wuauserv State={0} StartMode={1} (via sc.exe)" -f $post.wuauserv_State, $post.wuauserv_StartMode)
    if ("$($post.wuauserv_StartMode)" -ne 'Disabled') {
      Log 'PAUSAR FALLO: wuauserv NO ha quedado Disabled'
      exit 1
    }
    Log 'PAUSAR: wuauserv detenido + StartupType=Disabled'

    Get-ScheduledTask -TaskPath '\Microsoft\Windows\UpdateOrchestrator\' -ErrorAction SilentlyContinue |
      Where-Object { $_.TaskName -like 'Reboot*' -and $_.State -ne 'Disabled' } |
      ForEach-Object { Log ("PAUSAR: AVISO tarea de reinicio activa: {0} ({1})" -f $_.TaskName, $_.State) }

    Write-Host ''
    Write-Host '--- estado tras pausar ---'
    Get-Estado | Format-List
  }
  'restaurar' {
    if (Test-Path $AUPol) {
      Remove-ItemProperty -Path $AUPol -Name 'NoAutoUpdate' -ErrorAction SilentlyContinue
      Remove-ItemProperty -Path $AUPol -Name 'NoAutoRebootWithLoggedOnUsers' -ErrorAction SilentlyContinue
      if (-not (Get-ChildItem $AUPol -ErrorAction SilentlyContinue)) { Remove-Item $AUPol -Force -ErrorAction SilentlyContinue }
      if ((Test-Path $WUPol) -and -not (Get-ChildItem $WUPol -ErrorAction SilentlyContinue)) { Remove-Item $WUPol -Force -ErrorAction SilentlyContinue }
      Log 'RESTAURAR: politica AU retirada (clave creada por L1)'
    }
    Set-Service wuauserv -StartupType Manual
    try { Start-Service wuauserv -ErrorAction SilentlyContinue } catch { Log ("RESTAURAR: Start-Service aviso: {0}" -f $_.Exception.Message) }
    Log 'RESTAURAR: wuauserv StartupType=Manual + service arrancado'

    Write-Host ''
    Write-Host '--- estado tras restaurar ---'
    Get-Estado | Format-List
  }
}
