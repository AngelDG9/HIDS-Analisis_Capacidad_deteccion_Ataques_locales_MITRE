# ATA090 - T1498.002 Reflection Amplification (Windows)
# Manual: amplificador UDP 127.0.0.1:5353 + victima 127.0.0.2:5354.
# 100 consultas de 64 B -> respuestas de 4 KB (~400 KB en la victima). Sin spoofing.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA090*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$amp = '127.0.0.1'
$ampPort = 5353
$victim = '127.0.0.2'
$victimPort = 5354
$queries = 100
$queryBytes = 64
$respBytes = 4096
$ampJob = Start-Job -ScriptBlock {
    param($ip, $p, $rb)
    $u = New-Object System.Net.Sockets.UdpClient
    $u.ExclusiveAddressUse = $false
    $u.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
    $u.Client.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($ip), $p)))
    $end = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $end) {
        if ($u.Available -gt 0) {
            $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $data = $u.Receive([ref]$ep)
            $big = New-Object byte[] $rb
            [Array]::Copy($data, 0, $big, 0, [Math]::Min($data.Length, $rb))
            $u.Send($big, $big.Length, $ep) | Out-Null
        } else { Start-Sleep -Milliseconds 20 }
    }
    $u.Close()
} -ArgumentList $amp, $ampPort, $respBytes
Start-Sleep -Seconds 2
$victimClient = New-Object System.Net.Sockets.UdpClient
$victimClient.ExclusiveAddressUse = $false
$victimClient.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
$victimClient.Client.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($victim), $victimPort)))
$victimClient.Client.ReceiveTimeout = 5000
$query = New-Object byte[] $queryBytes
for ($i = 0; $i -lt $query.Length; $i++) { $query[$i] = 0x51 }
$sent = 0
$recv = 0
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
for ($i = 0; $i -lt $queries; $i++) {
    $victimClient.Send($query, $query.Length, $amp, $ampPort) | Out-Null
    $sent += $query.Length
    try {
        $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $r = $victimClient.Receive([ref]$ep)
        $recv += $r.Length
    } catch {}
}
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$victimClient.Close()
Stop-Job $ampJob -ErrorAction SilentlyContinue
Remove-Job $ampJob -Force -ErrorAction SilentlyContinue
@(
    "ata=ATA090", "tecnica=T1498.002", "fuente=manual",
    "t0=$t0", "t1=$t1", "amplificador=$amp`:$ampPort", "victima=$victim`:$victimPort",
    "consultas=$queries", "sent_bytes=$sent", "recv_bytes=$recv",
    "ratio=$([math]::Round($recv / [math]::Max($sent, 1), 2))"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
