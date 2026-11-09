# ATA082 - T1185 Browser Session Hijacking (Windows)
# Manual: perfil de navegador sintetico; no hay navegador real.
# Se crean Cookies y Login Data con cabecera SQLite ("SQLite format 3") y se copian.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA082*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$perfil = Join-Path $dir 'perfil\Default'
New-Item -ItemType Directory -Force -Path $perfil | Out-Null
$header = [Text.Encoding]::ASCII.GetBytes("SQLite format 3`0")
function New-SqliteToy([string]$path, [byte]$fill) {
    $bytes = New-Object byte[] (16 + 512)
    [Array]::Copy($header, 0, $bytes, 0, 16)
    $body = New-Object byte[] 512
    for ($i = 0; $i -lt $body.Length; $i++) { $body[$i] = $fill }
    [Array]::Copy($body, 0, $bytes, 16, 512)
    [IO.File]::WriteAllBytes($path, $bytes)
}
$cookies = Join-Path $perfil 'Cookies'
$login = Join-Path $perfil 'Login Data'
New-SqliteToy $cookies 0x43
New-SqliteToy $login 0x4C
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$out = Join-Path $ev 'browser'
New-Item -ItemType Directory -Force -Path $out | Out-Null
Copy-Item $cookies $out -Force
Copy-Item $login $out -Force
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$chk = [IO.File]::ReadAllBytes((Join-Path $out 'Cookies'))
$cab = [Text.Encoding]::ASCII.GetString($chk[0..14])
$nullOk = ($chk[15] -eq 0)
@(
    "ata=ATA082", "tecnica=T1185", "fuente=manual",
    "t0=$t0", "t1=$t1",
    "cookies=$((Get-Item (Join-Path $out 'Cookies')).Length)",
    "login=$((Get-Item (Join-Path $out 'Login Data')).Length)",
    "cabecera=$cab", "cabecera_null=$nullOk"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
