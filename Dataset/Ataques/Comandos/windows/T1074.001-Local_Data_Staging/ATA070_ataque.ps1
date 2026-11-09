$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA070*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'; New-Item -ItemType Directory -Force -Path $ev | Out-Null
$datos = Join-Path $dir 'datos'; New-Item -ItemType Directory -Force -Path $datos | Out-Null
$staging = Join-Path $dir 'staging'; New-Item -ItemType Directory -Force -Path $staging | Out-Null
1..30 | ForEach-Object { Set-Content -Path (Join-Path $datos ("item_$_.txt")) -Value ("TFG item $_ " + ('Z' * 32)) -Encoding ascii }
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
& robocopy.exe $datos $staging /E /NFL /NDL /NJH /NJS /NP | Out-File (Join-Path $ev 'robocopy.out') -Encoding ascii
$rc = $LASTEXITCODE
$n = (Get-ChildItem $staging -Recurse -File).Count
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@(
    "ata=ATA070", "tecnica=T1074.001", "fuente=ART_adaptado",
    "guid=a57fbe4b-3440-452a-88a7-943531ac872a",
    "t0=$t0", "t1=$t1", "staging=$staging", "ficheros=$n", "robocopy_rc=$rc"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
