# ATA085 - T1498.001 Direct Network Flood (Windows)
# Manual: 8 conexiones TCP de 8 MiB (64 MiB total) al sink 192.168.65.1:9091.
# Sin internet; solo 192.168.65.0/24.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA085*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$sink = '192.168.65.1'
$port = 9091
if ($sink -notlike '192.168.65.*') { 'GUARDARRAIL: destino no permitido' | Out-File (Join-Path $ev 'efecto_local.txt') -Encoding ascii; exit 2 }
$chunk = New-Object byte[] 65536
for ($i = 0; $i -lt $chunk.Length; $i++) { $chunk[$i] = 0x41 }
$perConn = 8 * 1024 * 1024
$total = 0
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
for ($c = 1; $c -le 8; $c++) {
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect($sink, $port)
    $stream = $client.GetStream()
    $sent = 0
    while ($sent -lt $perConn) {
        $n = [Math]::Min($chunk.Length, $perConn - $sent)
        $stream.Write($chunk, 0, $n)
        $sent += $n
    }
    $stream.Flush()
    $client.Close()
    $total += $sent
}
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@(
    "ata=ATA085", "tecnica=T1498.001", "fuente=manual",
    "t0=$t0", "t1=$t1", "destino=$sink`:$port",
    "conexiones=8", "bytes_conexion=$perConn", "bytes_total=$total"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
