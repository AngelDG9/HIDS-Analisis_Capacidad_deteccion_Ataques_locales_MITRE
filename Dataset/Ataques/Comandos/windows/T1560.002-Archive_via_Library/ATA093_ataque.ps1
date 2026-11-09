# ATA093 - T1560.002 Archive via Library (Windows)
# Manual: .zip por System.IO.Compression.ZipFile (NO Compress-Archive); 20 entradas.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA093*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$datos = Join-Path $dir 'datos'
New-Item -ItemType Directory -Force -Path $datos | Out-Null
1..20 | ForEach-Object { Set-Content -Path (Join-Path $datos ("doc_$_.txt")) -Value ("TFG archive $_ " + ('A' * 64)) -Encoding ascii }
$files = Get-ChildItem $datos -File
if ($files.Count -gt 200) { Write-Error 'GUARDARRAIL: demasiados ficheros'; exit 2 }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = Join-Path $dir 'archivo.zip'
if (Test-Path $zip) { Remove-Item $zip -Force }
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
[System.IO.Compression.ZipFile]::CreateFromDirectory($datos, $zip)
$zipSha = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
$zipObj = [System.IO.Compression.ZipFile]::OpenRead($zip)
$n = $zipObj.Entries.Count
$zipObj.Dispose()
$extraido = Join-Path $dir 'extraido'
if (Test-Path $extraido) { Remove-Item $extraido -Recurse -Force }
[System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $extraido)
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$ok = $true
foreach ($f in $files) {
    $a = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower()
    $b = (Get-FileHash (Join-Path $extraido $f.Name) -Algorithm SHA256).Hash.ToLower()
    if ($a -ne $b) { $ok = $false }
}
@(
    "ata=ATA093", "tecnica=T1560.002", "fuente=manual",
    "t0=$t0", "t1=$t1", "zip=$zip", "entradas=$n",
    "zip_sha256=$zipSha", "extraido_ok=$ok"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
