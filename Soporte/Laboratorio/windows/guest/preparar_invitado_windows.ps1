# ============================================================================
# preparar_invitado_windows.ps1 - prepara (o revierte) el INVITADO para W3
# Bloque `windows-legit-prep` (W3). Se ejecuta como `angel` por SSH.
# ----------------------------------------------------------------------------
# Modo PREPARAR (por defecto), idempotente:
#   - crea las carpetas base del `cwd` de la receta (espejo de deploy_client.ps1)
#   - crea `C:\lab-legit\campana\` (y, con -LimpiarCampana, borra los `W-*` previos)
#   - crea `errores.log` vacio si no existe (NUNCA lo trunca)
#   - asegura el alias `intranet.local` en `drivers\etc\hosts` (idempotente)
#   - deja `armado.flag` FUERA (un `prep` no arma la ventana)
#
# Modo REVERTIR (-Revertir), idempotente:
#   - borra `C:\Users\angel\ghosts-client`, `C:\lab-legit\campana` y `errores.log`
#   - borra las carpetas base SOLO si quedan vacias
#   - NO toca `C:\lab-legit\tools` (material historico) ni la linea de `hosts`
#   - las tareas las quita `deploy_windows.ps1` (necesita privilegios de registro)
#
# Sin secretos. Uso:
#   powershell -NoProfile -ExecutionPolicy Bypass -File preparar_invitado_windows.ps1 [-LimpiarCampana|-Revertir]
# ============================================================================
[CmdletBinding()]
param(
  [switch]$LimpiarCampana,
  [switch]$Revertir,
  # Ruta del ZIP del payload (lo sube `deploy_windows.ps1`). Si se pasa, se extrae y
  # se copia `client\` -> ClienteDir y `campana\` -> CampanaDir (robocopy /E, sin purgar).
  [string]$PayloadZip = '',
  [string]$ClienteDir = 'C:\Users\angel\ghosts-client',
  [string]$CampanaDir = 'C:\lab-legit\campana',
  [string]$CwdBase = 'C:\Users\angel',
  [string]$ErrLog = 'C:\Users\angel\Documentos\errores.log'
)

$ErrorActionPreference = 'Continue'

$CarpetasCwd = @(
  (Join-Path $CwdBase 'Documentos'),
  (Join-Path $CwdBase 'Documentos\informes'),
  (Join-Path $CwdBase 'Documentos\actas'),
  (Join-Path $CwdBase 'Documentos\copias'),
  (Join-Path $CwdBase 'Documentos\correo'),
  (Join-Path $CwdBase 'Descargas'),
  (Join-Path $CwdBase '.cache\tfg-web')
)

if ($Revertir) {
  # --- tareas que puedan quedar vivas: se pide al deploy, pero se avisa ------
  foreach ($n in @('TFG-WinLegit-Actividad', 'TFG-WinLegit-Keepalive')) {
    $t = Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue
    if ($t) { Write-Output "AVISO: la tarea $n sigue registrada (la quita deploy_windows.ps1 -Phase revert)" }
  }

  # --- procesos --------------------------------------------------------------
  Get-Process -Name ghosts -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 2

  # --- arboles del despliegue ------------------------------------------------
  foreach ($p in @($ClienteDir, $CampanaDir, $ErrLog)) {
    if (Test-Path $p) {
      Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue
      Write-Output ("BORRADO " + $p + " -> existe=" + (Test-Path $p))
    }
  }

  # --- carpetas base SOLO si estan vacias -----------------------------------
  foreach ($d in ($CarpetasCwd | Sort-Object -Property Length -Descending)) {
    if (Test-Path $d) {
      $n = @(Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue).Count
      if ($n -eq 0) {
        Remove-Item -LiteralPath $d -Force -ErrorAction SilentlyContinue
        Write-Output "BORRADO_DIR_VACIO $d"
      } else {
        Write-Output "CONSERVADO_DIR_NO_VACIO $d ($n entradas)"
      }
    }
  }

  # --- verificacion de cero residuos ----------------------------------------
  $res = @()
  if (Test-Path $ClienteDir) { $res += $ClienteDir }
  if (Test-Path $CampanaDir) { $res += $CampanaDir }
  if (Test-Path $ErrLog) { $res += $ErrLog }
  if (@(Get-Process -Name ghosts -ErrorAction SilentlyContinue).Count -gt 0) { $res += 'proceso_ghosts' }
  if ($res.Count -eq 0) { Write-Output 'RESIDUOS=0'; Write-Output 'RESULT=PASS'; exit 0 }
  Write-Output ("RESIDUOS=" + ($res -join ','))
  Write-Output 'RESULT=FAIL'
  exit 1
}

# --- PREPARAR ---------------------------------------------------------------
if ($PayloadZip) {
  if (-not (Test-Path $PayloadZip)) { Write-Output "RESULT=FAIL"; throw "no existe el payload $PayloadZip" }
  $tmp = 'C:\Windows\Temp\tfg-win-legit'
  if (Test-Path $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
  New-Item -ItemType Directory -Force -Path $tmp | Out-Null
  & tar.exe -xf $PayloadZip -C $tmp
  if ($LASTEXITCODE -ne 0) { Write-Output 'RESULT=FAIL'; throw "tar rc=$LASTEXITCODE al extraer $PayloadZip" }
  foreach ($par in @(@('client', $ClienteDir), @('campana', $CampanaDir))) {
    $origen = Join-Path $tmp $par[0]
    if (-not (Test-Path $origen)) { continue }
    New-Item -ItemType Directory -Force -Path $par[1] | Out-Null
    $rc = (Start-Process -FilePath 'robocopy.exe' -Wait -PassThru -NoNewWindow `
        -ArgumentList @($origen, $par[1], '/E', '/NFL', '/NDL', '/NJH', '/NJS', '/NP', '/R:1', '/W:1')).ExitCode
    # robocopy: 0-7 = exito (8+ = error)
    if ($rc -ge 8) { Write-Output 'RESULT=FAIL'; throw "robocopy $($par[0]) rc=$rc" }
    Write-Output ("COPIADO {0} -> {1} (robocopy rc={2})" -f $par[0], $par[1], $rc)
  }
  Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $PayloadZip -Force -ErrorAction SilentlyContinue
}

foreach ($d in $CarpetasCwd) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
New-Item -ItemType Directory -Force -Path $CampanaDir | Out-Null

if (-not (Test-Path $ErrLog)) {
  New-Item -ItemType File -Force -Path $ErrLog | Out-Null
  Write-Output "CREADO $ErrLog"
} else {
  Write-Output ("CONSERVADO $ErrLog (bytes=" + (Get-Item $ErrLog).Length + ")")
}

if ($LimpiarCampana) {
  # Prerrequisito bloqueante de B6: sin carpeta limpia las marcas se mezclan.
  $viejos = @(Get-ChildItem -LiteralPath $CampanaDir -Directory -Filter 'W-*' -ErrorAction SilentlyContinue)
  foreach ($v in $viejos) { Remove-Item -LiteralPath $v.FullName -Recurse -Force -ErrorAction SilentlyContinue }
  Write-Output ("CAMPANA_LIMPIADA dirs_borrados=" + $viejos.Count)
}

$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$txt = ''
try { $txt = Get-Content -LiteralPath $hosts -Raw -ErrorAction Stop } catch { }
if ($txt -notmatch 'intranet\.local') {
  Add-Content -LiteralPath $hosts -Value "192.168.65.1 intranet.local nube.local paste.local hook.local"
  Write-Output 'HOSTS_ANADIDO intranet.local'
} else {
  Write-Output 'HOSTS_OK intranet.local'
}

$flag = Join-Path $ClienteDir 'armado.flag'
if (Test-Path $flag) { Remove-Item -LiteralPath $flag -Force; Write-Output 'FLAG_ARMADO_QUITADO' }

Write-Output 'RESULT=PASS'
exit 0
