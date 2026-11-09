# ATA084 - T1657 Financial Theft (Windows)
# Manual: libro local de juguete; transferencia y saldo alterado. Sin red.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA084*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$libro = Join-Path $dir 'libro.csv'
@("cuenta,saldo", "A,5000", "B,1000") | Set-Content -Path $libro -Encoding ascii
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$importe = 1500
$rows = Import-Csv $libro
$rows | ForEach-Object {
    if ($_.cuenta -eq 'A') { $_.saldo = [int]$_.saldo - $importe }
    if ($_.cuenta -eq 'B') { $_.saldo = [int]$_.saldo + $importe }
}
$after = Join-Path $dir 'libro_after.csv'
$rows | Export-Csv -Path $after -NoTypeInformation -Encoding ascii
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$saldoA = ($rows | Where-Object { $_.cuenta -eq 'A' }).saldo
$saldoB = ($rows | Where-Object { $_.cuenta -eq 'B' }).saldo
@(
    "ata=ATA084", "tecnica=T1657", "fuente=manual",
    "t0=$t0", "t1=$t1", "libro=$libro", "libro_after=$after",
    "importe=$importe", "saldo_A=$saldoA", "saldo_B=$saldoB",
    "alterado=$($saldoA -eq 3500 -and $saldoB -eq 2500)"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
