# ATA086 - T1499.001 OS Exhaustion Flood (Windows)
# Manual: 8 bloques de 64 MiB = 512 MiB retenidos 15 s; efecto Available MBytes.
# El HIDS no tiene capa de recursos: la deteccion esperada es de proceso.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA086*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
function Get-AvailMB { [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1024, 1) }
$before = Get-AvailMB
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$blocks = @()
1..8 | ForEach-Object { $blocks += ,(New-Object byte[] (64 * 1024 * 1024)) }
$during = Get-AvailMB
Start-Sleep -Seconds 15
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$blocks = $null
[GC]::Collect()
$after = Get-AvailMB
@(
    "ata=ATA086", "tecnica=T1499.001", "fuente=manual",
    "t0=$t0", "t1=$t1", "bloques=8", "bytes=536870912",
    "available_before_mb=$before", "available_during_mb=$during", "available_after_mb=$after"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
