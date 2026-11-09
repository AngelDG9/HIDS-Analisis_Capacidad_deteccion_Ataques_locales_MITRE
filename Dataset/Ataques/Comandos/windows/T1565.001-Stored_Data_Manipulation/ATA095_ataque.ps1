# ATA095 - T1565.001 Stored Data Manipulation (Windows)
# Manual: alterar libro.csv in situ; sha256 antes != despues.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA095*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$libro = Join-Path $dir 'libro.csv'
@("cuenta,saldo", "A,5000", "B,1000", "C,250") | Set-Content -Path $libro -Encoding ascii
$before = (Get-FileHash $libro -Algorithm SHA256).Hash.ToLower()
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$rows = Import-Csv $libro
$rows | ForEach-Object { if ($_.cuenta -eq 'A') { $_.saldo = '9999' } }
$rows | Export-Csv -Path $libro -NoTypeInformation -Encoding ascii
$after = (Get-FileHash $libro -Algorithm SHA256).Hash.ToLower()
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@(
    "ata=ATA095", "tecnica=T1565.001", "fuente=manual",
    "t0=$t0", "t1=$t1", "libro=$libro",
    "sha256_antes=$before", "sha256_despues=$after",
    "alterado=$($before -ne $after)"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
