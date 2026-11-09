# ATA088 - T1496.002 Bandwidth Hijacking (Windows)
# Manual: 32 MiB en 1 conexion TCP al sink 192.168.65.1:9091. Sin internet.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA088*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$sink = '192.168.65.1'
$port = 9091
if ($sink -notlike '192.168.65.*') { 'GUARDARRAIL: destino no permitido' | Out-File (Join-Path $ev 'efecto_local.txt') -Encoding ascii; exit 2 }
$chunk = New-Object byte[] 65536
for ($i = 0; $i -lt $chunk.Length; $i++) { $chunk[$i] = 0x42 }
$total = 32 * 1024 * 1024
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$client = New-Object System.Net.Sockets.TcpClient
$client.Connect($sink, $port)
$stream = $client.GetStream()
$sent = 0
while ($sent -lt $total) {
    $n = [Math]::Min($chunk.Length, $total - $sent)
    $stream.Write($chunk, 0, $n)
    $sent += $n
}
$stream.Flush()
$client.Close()
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@(
    "ata=ATA088", "tecnica=T1496.002", "fuente=manual",
    "t0=$t0", "t1=$t1", "destino=$sink`:$port",
    "conexiones=1", "bytes=$total"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
