$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA067*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'; New-Item -ItemType Directory -Force -Path $ev | Out-Null
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@(
    "ata=ATA067", "tecnica=T1529", "fuente=ART_adaptado",
    "guid=f4648f0d-bf78-483c-bafc-3ec99cd1c302",
    "t0=$t0", "boot_before=$boot",
    "comando=shutdown /r /t 5 /f",
    "nota=el efecto se cierra en el host con boot_after tras el reinicio"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
$sh = & shutdown.exe /r /t 5 /f 2>&1 | Out-String
@("shutdown_rc=$LASTEXITCODE", "shutdown_out=$sh") | Out-File -FilePath (Join-Path $ev 'shutdown.out') -Encoding ascii
exit 0
