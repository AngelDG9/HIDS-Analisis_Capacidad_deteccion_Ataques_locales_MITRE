# ============================================================================
# manifiesto_snapshot.ps1 - sella el manifiesto esperado del invitado (T2b-2)
# Bloque `windows-legit-prep` (W3-bis). Se ejecuta en el HOST.
# ----------------------------------------------------------------------------
# Lee del invitado, con `verificar_windows.ps1 -Manifiesto -Detalle` (READ-ONLY):
#   - payload + recetas del arbol del cliente (sin volatiles)
#   - campana
#   - C:\lab-legit\tools
#   - fichero hosts
#   - descriptor canonico de las 2 tareas
#   - versiones y sha256 de ghosts.exe / Ghosts.Domain.dll
# y escribe `manifiesto_esperado.json` + su `.sha256`.
#
# `dia_aplicado.txt`, logs, instance, client.out*, flags y el timeline ACTIVO quedan
# excluidos por `verificar_windows.ps1`. NO escribe nada en el invitado.
#
# Uso (HOST):
#   powershell -NoProfile -ExecutionPolicy Bypass -File manifiesto_snapshot.ps1
# ============================================================================
[CmdletBinding()]
param(
  [string]$OutFile = '',
  [string]$ClienteDir = 'C:\Users\angel\ghosts-client'
)

$ErrorActionPreference = 'Stop'

$Repo = 'D:\TFG\HIDS-Analisis_Capacidad_deteccion_Ataques_locales_MITRE'
$Win  = Join-Path $Repo 'Soporte\Laboratorio\windows'
if (-not $OutFile) { $OutFile = Join-Path $Win 'legit\evidencia\manifiesto_esperado.json' }

$Ssh = 'C:\Program Files\Git\usr\bin\ssh.exe'
$Key = Join-Path $env:USERPROFILE '.ssh\id_ed25519_tfg_win'
$Target = 'angel@192.168.65.130'
$RVerif = 'C:/Users/angel/ghosts-client/verificar_windows.ps1'

function Ts { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }

$eap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$salida = & $Ssh -i $Key -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR $Target "powershell -NoProfile -ExecutionPolicy Bypass -File `"$RVerif`" -Manifiesto -Detalle" 2>&1
$rc = $LASTEXITCODE
$ErrorActionPreference = $eap
$txt = ($salida | Out-String)
if ($rc -ne 0) { throw "verificar_windows -Manifiesto rc=$rc`n$txt" }

$shaMan = if ($txt -match 'MANIFEST_SHA256=([0-9a-f]{64})') { $Matches[1] } else { '' }
$nFiles = if ($txt -match 'MANIFEST_FILES=(\d+)') { [int]$Matches[1] } else { 0 }
if (-not $shaMan) { throw "el invitado no devolvio MANIFEST_SHA256`n$txt" }

$ficheros = @()
foreach ($l in ($txt -split "`r?`n")) {
  if ($l -match '^MFILE\t(.*?)\t([0-9a-f]{64}|AUSENTE)\t(\d+)\t(\S+)$') {
    $ficheros += [ordered]@{ ruta = $Matches[1]; sha256 = $Matches[2]; bytes = [int64]$Matches[3]; tipo = $Matches[4] }
  }
}
if ($ficheros.Count -ne $nFiles) { throw "MFILE=$($ficheros.Count) != MANIFEST_FILES=$nFiles" }

$cliente = [ordered]@{}
foreach ($k in @('GHOSTS_EXE_FILEVERSION', 'GHOSTS_EXE_PRODUCTVERSION', 'GHOSTS_EXE_SHA256',
                 'GHOSTS_DOMAIN_FILEVERSION', 'GHOSTS_DOMAIN_PRODUCTVERSION', 'GHOSTS_DOMAIN_SHA256')) {
  $m = [regex]::Match($txt, "CLIENTE_$k=(.+)")
  $cliente[$k.ToLower()] = if ($m.Success) { $m.Groups[1].Value.Trim() } else { '' }
}

$j = [ordered]@{
  generado_utc       = (Ts)
  cliente_dir        = $ClienteDir
  cliente            = $cliente
  excluidos          = @('logs\*', 'instance\*', 'client.out*', 'keepalive.log', 'recovery.log',
                         'estado.json', 'armado.flag', 'stop.flag', 'heartbeat.seq', 'dia_aplicado.txt',
                         'config\timeline.json')
  MANIFEST_FILES     = $nFiles
  MANIFEST_SHA256    = $shaMan
  ficheros           = $ficheros
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutFile) | Out-Null
($j | ConvertTo-Json -Depth 6) | Set-Content -Path $OutFile -Encoding utf8
$shaJson = (Get-FileHash -LiteralPath $OutFile -Algorithm SHA256).Hash.ToLower()
"$shaJson  manifiesto_esperado.json" | Set-Content -Path ($OutFile + '.sha256') -Encoding ascii

Write-Output "MANIFIESTO_ESPERADO=$OutFile"
Write-Output "MANIFIESTO_ESPERADO_SHA256=$shaJson"
Write-Output "MANIFEST_FILES=$nFiles"
Write-Output "MANIFEST_SHA256=$shaMan"
