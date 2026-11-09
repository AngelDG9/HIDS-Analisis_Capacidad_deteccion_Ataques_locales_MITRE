$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA069*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'; New-Item -ItemType Directory -Force -Path $ev | Out-Null
$datos = Join-Path $dir 'datos'; New-Item -ItemType Directory -Force -Path $datos | Out-Null
1..20 | ForEach-Object { Set-Content -Path (Join-Path $datos ("doc_$_.txt")) -Value ("TFG doc $_ " + ('Y' * 64)) -Encoding ascii }
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$zip = Join-Path $ev 'datos.zip'
Compress-Archive -Path (Join-Path $datos '*') -DestinationPath $zip -Force
Add-Type -AssemblyName System.IO.Compression.FileSystem
$z = [System.IO.Compression.ZipFile]::OpenRead($zip)
$n = $z.Entries.Count
$z.Dispose()
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@(
    "ata=ATA069", "tecnica=T1560.001", "fuente=ART_adaptado",
    "guid=02ea31cb-3b4c-4a2d-9bf1-e4e70ebcf5d0",
    "t0=$t0", "t1=$t1", "zip=$zip", "entradas=$n", "bytes=$((Get-Item $zip).Length)"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
