# ============================================================================
# prueba_negativa_GW11.ps1 - artefacto REPRODUCIBLE de la prueba negativa de G-W11
# Bloque `windows-legit-prep` (W3, deuda D1).
# ----------------------------------------------------------------------------
# Que demuestra:
#   Con `armado.flag` presente y CERO procesos `ghosts.exe`, `G-W11` NO puede pasar:
#   el `drytest` de `watch` debe devolver `G-W11 FALLO`, `DRYTEST watch FAIL` y exit 1.
#   (El defecto F1 era `ok = ($lineas.Count -le 1)`, que aceptaba 0 procesos.)
#
# Requisitos:
#   - invitado `victima-windows` ENCENDIDO y con SSH (clave `id_ed25519_tfg_win`)
#   - manager apagado (da igual: G-W5/G-W7 salen SKIP y no afectan al veredicto)
#
# Efectos: crea y BORRA `C:\Users\angel\ghosts-client\armado.flag`; mata cualquier
# `ghosts.exe` que hubiera (fuera de ventana no debe haber ninguno). No toca nada mas.
#
# Uso (HOST):
#   powershell -NoProfile -ExecutionPolicy Bypass -File `
#     Soporte\Laboratorio\windows\legit\evidencia\prueba_negativa_GW11.ps1
# Salida: consola + `prueba_negativa_GW11.txt` (versionado).
# ============================================================================
[CmdletBinding()]
param(
  [string]$Salida = ''
)

$ErrorActionPreference = 'Continue'

$Win  = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Ctl  = Join-Path $Win 'windows_legit_host_control.ps1'
$Vmrun = 'C:\Program Files\VMware\VMware Workstation\vmrun.exe'
$Vmx   = 'D:\TFG-VMs\victima-windows\victima-windows.vmx'
$Ssh   = 'C:\Program Files\Git\usr\bin\ssh.exe'
$Key   = Join-Path $env:USERPROFILE '.ssh\id_ed25519_tfg_win'
$Target = 'angel@192.168.65.130'

# `$PSScriptRoot` no esta disponible al enlazar los parametros: se resuelve aqui.
if (-not $Salida) { $Salida = Join-Path $PSScriptRoot 'prueba_negativa_GW11.txt' }

$lineas = New-Object System.Collections.Generic.List[string]
function Emit([string]$m) { $lineas.Add($m); Write-Output $m }

function Invoke-Guest([string]$Cmd) {
  $out = & $Ssh -i $Key -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR $Target $Cmd 2>&1
  return @{ rc = $LASTEXITCODE; out = (($out | Out-String).Trim()) }
}

Emit "=== PRUEBA NEGATIVA G-W11 $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) ==="

# --- 0) precondiciones ------------------------------------------------------
$vms = (& $Vmrun -T ws list 2>&1 | Out-String)
if ($vms -notmatch [regex]::Escape($Vmx)) {
  Emit 'RESULT=FAIL motivo=la VM victima-windows no esta encendida'
  $lineas | Add-Content -Path $Salida -Encoding utf8
  exit 2
}

# --- 1) estado: 0 procesos ghosts.exe + flag creado ------------------------
$k = Invoke-Guest 'taskkill /f /im ghosts.exe 2>nul'
Emit ("PASO 1 taskkill rc={0} out={1}" -f $k.rc, ($k.out -replace '\s+', ' '))
# OJO (hallazgo): las comillas dobles en el comando SSH (Git/MSYS) se comen las
# barras invertidas y crean el flag en una ruta relativa. Se usa la MISMA forma
# sin comillas que `Get-FlagArmado` en el controlador.
$f = Invoke-Guest 'type nul > C:\Users\angel\ghosts-client\armado.flag'
Emit ("PASO 2 flag rc={0}" -f $f.rc)
$chk = Invoke-Guest 'if exist C:\Users\angel\ghosts-client\armado.flag (echo FLAG_SI) else (echo FLAG_NO)'
Emit ("PASO 2b flag={0}" -f $chk.out)
$p = Invoke-Guest 'tasklist /nh | findstr /i ghosts.exe'
$nProc = @($p.out -split "`r?`n" | Where-Object { $_.Trim() }).Count
Emit ("PASO 3 procesos_ghosts={0}" -f $nProc)

# --- 2) drytest de `watch` (debe FALLAR) -----------------------------------
$out = (& powershell -NoProfile -ExecutionPolicy Bypass -File $Ctl -Phase drytest -DryPhase watch -DryLogPath (Join-Path $PSScriptRoot 'prueba_negativa_GW11_drytest.log') 2>&1 | Out-String)
$rc = $LASTEXITCODE
foreach ($l in ($out -split "`r?`n")) { if ($l.Trim()) { Emit ("  | " + $l.TrimEnd()) } }
Emit ("PASO 4 drytest_rc={0}" -f $rc)

# --- 3) limpieza SIEMPRE ---------------------------------------------------
$d = Invoke-Guest 'del /f /q C:\Users\angel\ghosts-client\armado.flag'
Emit ("PASO 5 borrado_flag rc={0}" -f $d.rc)

# --- 4) veredicto ----------------------------------------------------------
$ok = ($rc -ne 0) -and ($out -match 'G-W11\s+FALLO') -and ($out -match 'DRYTEST watch FAIL')
Emit ("RESULT={0} (esperado: exit<>0 + 'G-W11 FALLO' + 'DRYTEST watch FAIL')" -f $(if ($ok) { 'PASS' } else { 'FAIL' }))
$lineas | Add-Content -Path $Salida -Encoding utf8
if ($ok) { exit 0 }
exit 1
