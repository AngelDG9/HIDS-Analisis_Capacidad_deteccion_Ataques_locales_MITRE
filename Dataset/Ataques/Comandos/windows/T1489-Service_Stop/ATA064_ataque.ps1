$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA064*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'; New-Item -ItemType Directory -Force -Path $ev | Out-Null
$svc = 'TFG-Svc-1489'
$bin = 'cmd.exe /c ping -n 60 127.0.0.1 >nul'
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
& sc.exe create $svc binPath= $bin start= demand 2>&1 | Out-File (Join-Path $ev 'sc_create.out') -Encoding ascii
& sc.exe start $svc 2>&1 | Out-File (Join-Path $ev 'sc_start.out') -Encoding ascii
Start-Sleep -Seconds 1
$q0 = & sc.exe query $svc 2>&1 | Out-String
& sc.exe stop $svc 2>&1 | Out-File (Join-Path $ev 'sc_stop.out') -Encoding ascii
Start-Sleep -Seconds 1
$q1 = & sc.exe query $svc 2>&1 | Out-String
& sc.exe delete $svc 2>&1 | Out-File (Join-Path $ev 'sc_delete.out') -Encoding ascii
Start-Sleep -Seconds 1
$q2 = & sc.exe query $svc 2>&1 | Out-String
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$estado0 = (($q0 -split "`n") | Where-Object { $_ -match 'STATE' } | Select-Object -First 1)
$estado1 = (($q1 -split "`n") | Where-Object { $_ -match 'STATE' } | Select-Object -First 1)
$salida = @(
    "ata=ATA064", "tecnica=T1489", "fuente=ART_adaptado",
    "guid=21dfb440-830d-4c86-a3e5-2a491d5a8d04",
    "t0=$t0", "t1=$t1", "servicio=$svc",
    "estado_antes=$($estado0 -replace '\s+',' ')".Trim(),
    "estado_despues=$($estado1 -replace '\s+',' ')".Trim(),
    "borrado=" + [bool]($q2 -match '1060|does not exist|no existe')
)
$salida | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
