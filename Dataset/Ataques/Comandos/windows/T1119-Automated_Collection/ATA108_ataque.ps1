# ATA108 - T1119 Automated Collection (Windows)
# ART_adaptado: bucle automatico sobre fuentes\ que copia 20 ficheros a staging\; guardarrail C:\lab-attack\ATA108\; sin red externa.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA108*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null

$fuentes = Join-Path $dir 'fuentes'
$staging = Join-Path $dir 'staging'
New-Item -ItemType Directory -Force -Path $fuentes, $staging | Out-Null
1..20 | ForEach-Object { Set-Content -Path (Join-Path $fuentes ("doc_{0:D2}.docx" -f $_)) -Value ("TFG collect $_ " + ('H' * 64)) -Encoding ascii }
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$n = 0
foreach ($f in Get-ChildItem $fuentes -File -Recurse) {
    Copy-Item $f.FullName -Destination $staging -Force
    $n++
}
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@(
    "ata=ATA108", "tecnica=T1119", "fuente=ART_adaptado",
    "t0=$t0", "t1=$t1", "fuentes=$fuentes", "staging=$staging",
    "ficheros_recolectados=$n", "recoleccion_ok=$($n -eq 20)"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
