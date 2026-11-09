$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA072*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'; New-Item -ItemType Directory -Force -Path $ev | Out-Null
$seed = 'TFG-CLIP-2026-B1.3'
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
Set-Clipboard -Value $seed
Start-Sleep -Milliseconds 300
$leido = (Get-Clipboard -Raw).TrimEnd()
$leido | Out-File -FilePath (Join-Path $ev 'clipboard.txt') -Encoding ascii
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@(
    "ata=ATA072", "tecnica=T1115", "fuente=ART_adaptado",
    "guid=d6dc21af-bec9-4152-be86-326b6babd416",
    "t0=$t0", "t1=$t1", "seed=$seed", "leido=$leido",
    "coincide=" + [bool]($leido -eq $seed)
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
