# ATA109 - T1114.003 Email Forwarding Rule (Windows)
# manual: perfil de correo sintetico + regla de reenvio + sink local; .eml reenviado; guardarrail C:\lab-attack\ATA109\; sin red externa.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA109*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null

$perfil = Join-Path $dir 'perfil'
$inbox = Join-Path $perfil 'inbox'
$sink = Join-Path $dir 'sink'
New-Item -ItemType Directory -Force -Path $inbox, $sink | Out-Null
$eml = Join-Path $inbox 'mensaje.eml'
@(
    'From: remitente@tfg.local',
    'To: victima@tfg.local',
    'Subject: TFG email forwarding',
    'Date: Mon, 09 Nov 2026 21:00:00 +0000',
    '',
    'Contenido de juguete para la regla de reenvio.'
) | Set-Content -Path $eml -Encoding ascii
$regla = Join-Path $perfil 'regla_reenvio.json'
'{ "nombre": "TFG-Forward", "destino": "sink@tfg.local", "activa": true }' | Set-Content -Path $regla -Encoding ascii
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$destino = Join-Path $sink 'mensaje.eml'
Copy-Item $eml -Destination $destino -Force
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$ok = Test-Path $destino
$bytes = 0
if ($ok) { $bytes = (Get-Item $destino).Length }
@(
    "ata=ATA109", "tecnica=T1114.003", "fuente=manual",
    "t0=$t0", "t1=$t1", "perfil=$perfil", "regla=$regla",
    "destino=sink@tfg.local", "eml_reenviado=$ok", "eml_bytes=$bytes"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
