# ATA083 - T1667 Email Bombing (Windows)
# Manual: mailbox local de juguete; 25 .eml. Sin red.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA083*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$mailbox = Join-Path $dir 'mailbox'
New-Item -ItemType Directory -Force -Path $mailbox | Out-Null
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
1..25 | ForEach-Object {
    $eml = Join-Path $mailbox ("bomb_{0:D2}.eml" -f $_)
    @(
        "From: bomb@tfg.local",
        "To: angel@tfg.local",
        "Subject: TFG bomb $_",
        "Date: Mon, 09 Nov 2026 12:00:00 +0000",
        "",
        "Mensaje $_"
    ) | Set-Content -Path $eml -Encoding ascii
}
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$files = Get-ChildItem $mailbox -File
@(
    "ata=ATA083", "tecnica=T1667", "fuente=manual",
    "t0=$t0", "t1=$t1", "mailbox=$mailbox",
    "ficheros=$($files.Count)", "bytes=$(($files | Measure-Object Length -Sum).Sum)"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
