# ============================================================================
# test_il.ps1 - mide el IntegrityLevel real de una tarea del invitado segun el
# LogonType (Interactive vs Password). Evidencia de D-W3-3 / B10-W.
# Bloque `windows-legit-prep` (W3). NO contiene secretos.
# ----------------------------------------------------------------------------
# Interactive : tarea en la sesion de consola de `angel` -> se espera Medium.
# Password    : tarea con credencial guardada (sesion 0) -> se espera High.
# La contrasena se lee de STDIN con -ClaveDesdeStdin (nunca va en el fichero
# ni en la linea de comandos). Las tareas y los .txt se borran al terminar.
# Uso: <clave> | powershell -NoProfile -ExecutionPolicy Bypass -File test_il.ps1 -ClaveDesdeStdin
# ============================================================================
param([switch]$ClaveDesdeStdin)

$ErrorActionPreference = 'Continue'
$u  = "{0}\angel" -f $env:COMPUTERNAME
$pw = $null
if ($ClaveDesdeStdin) { $pw = [Console]::In.ReadLine() }

$set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
  -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 2)

function Probar([string]$nombre, [string]$logon) {
  $f = "C:\Users\angel\$nombre.txt"
  Remove-Item $f -Force -ErrorAction SilentlyContinue
  $acc = New-ScheduledTaskAction -Execute 'C:\Windows\System32\cmd.exe' `
    -Argument ('/c whoami /groups > "' + $f + '" 2>&1') -WorkingDirectory 'C:\Users\angel'
  try {
    if ($logon -eq 'Password') {
      if (-not $pw) { Write-Output "$nombre REGISTRO=FAIL (sin clave por STDIN)"; return }
      # LogonType=Password exige la credencial EN EL REGISTRO (si no, rc=ERROR_LOGON_FAILURE).
      Register-ScheduledTask -TaskName $nombre -Action $acc -Settings $set `
        -User $u -Password $pw -RunLevel Limited -Force -ErrorAction Stop | Out-Null
    } else {
      $pri = New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Limited
      Register-ScheduledTask -TaskName $nombre -Action $acc -Principal $pri `
        -Settings $set -Force -ErrorAction Stop | Out-Null
    }
    Write-Output "$nombre REGISTRO=OK"
  } catch {
    Write-Output ("$nombre REGISTRO=FAIL " + $_.Exception.Message)
    return
  }
  & schtasks /run /tn $nombre 2>&1 | Out-Null
  Start-Sleep -Seconds 8
  if (Test-Path $f) {
    $il = (Get-Content $f | Select-String -Pattern 'Mandatory Label').Line
    Write-Output ("$nombre IL=" + ($il -replace '\s+', ' ').Trim())
  } else {
    Write-Output "$nombre SIN_SALIDA (no corrio)"
  }
  & schtasks /delete /tn $nombre /f 2>&1 | Out-Null
  Remove-Item $f -Force -ErrorAction SilentlyContinue
}

Probar 'TFG-IL-Interactive' 'Interactive'
Probar 'TFG-IL-Password' 'Password'
