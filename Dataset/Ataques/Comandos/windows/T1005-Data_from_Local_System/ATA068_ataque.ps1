$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA068*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'; New-Item -ItemType Directory -Force -Path $ev | Out-Null
$datos = Join-Path $dir 'datos'; New-Item -ItemType Directory -Force -Path $datos | Out-Null
1..20 | ForEach-Object { Set-Content -Path (Join-Path $datos ("doc_$_.txt")) -Value ("TFG doc $_ " + ('X' * 64)) -Encoding ascii }
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$inv = Join-Path $ev 'inventario.txt'
$files = Get-ChildItem $datos -Recurse -File | Sort-Object FullName
$files | ForEach-Object { "{0}|{1}|{2}" -f $_.FullName, $_.Length, $_.LastWriteTimeUtc.ToString('o') } | Out-File -FilePath $inv -Encoding ascii
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@(
    "ata=ATA068", "tecnica=T1005", "fuente=ART_adaptado",
    "guid=d3d9af44-b8ad-4375-8b0a-4bff4b7e419c",
    "t0=$t0", "t1=$t1", "ficheros=$($files.Count)", "inventario=$inv"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
