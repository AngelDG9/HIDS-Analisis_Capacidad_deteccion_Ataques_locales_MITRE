# ATA092 - T1557.003 DHCP Spoofing (Windows)
# Manual: servidor DHCP sintetico en 127.0.0.1:67 + cliente sintetico; lease.txt.
# Sin NIC/lease real; sin VMnet1.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA092*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$server = '127.0.0.1'
$port = 67
$clientIp = '192.168.65.200'
$gw = '192.168.65.1'
$dns = '192.168.65.1'
$serverJob = Start-Job -ScriptBlock {
    param($ip, $p, $cip, $gw, $dns)
    $u = New-Object System.Net.Sockets.UdpClient
    $u.ExclusiveAddressUse = $false
    $u.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
    $u.Client.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($ip), $p)))
    $end = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $end) {
        if ($u.Available -gt 0) {
            $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $data = $u.Receive([ref]$ep)
            $msg = [Text.Encoding]::ASCII.GetString($data)
            if ($msg -like 'DHCPDISCOVER*') {
                $resp = [Text.Encoding]::ASCII.GetBytes("DHCPOFFER ip=$cip gw=$gw dns=$dns xid=$($msg.Split(' ')[1])")
                $u.Send($resp, $resp.Length, $ep) | Out-Null
            } elseif ($msg -like 'DHCPREQUEST*') {
                $resp = [Text.Encoding]::ASCII.GetBytes("DHCPACK ip=$cip gw=$gw dns=$dns xid=$($msg.Split(' ')[1])")
                $u.Send($resp, $resp.Length, $ep) | Out-Null
            }
        } else { Start-Sleep -Milliseconds 20 }
    }
    $u.Close()
} -ArgumentList $server, $port, $clientIp, $gw, $dns
Start-Sleep -Seconds 2
$client = New-Object System.Net.Sockets.UdpClient
$client.ExclusiveAddressUse = $false
$client.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
$client.Client.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse('127.0.0.1'), 0)))
$client.Client.ReceiveTimeout = 5000
$xid = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$discover = [Text.Encoding]::ASCII.GetBytes("DHCPDISCOVER xid=$xid")
$client.Send($discover, $discover.Length, $server, $port) | Out-Null
$ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
$offer = [Text.Encoding]::ASCII.GetString($client.Receive([ref]$ep))
$request = [Text.Encoding]::ASCII.GetBytes("DHCPREQUEST xid=$xid ip=$clientIp")
$client.Send($request, $request.Length, $server, $port) | Out-Null
$ack = [Text.Encoding]::ASCII.GetString($client.Receive([ref]$ep))
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$client.Close()
Stop-Job $serverJob -ErrorAction SilentlyContinue
Remove-Job $serverJob -Force -ErrorAction SilentlyContinue
$lease = Join-Path $ev 'lease.txt'
@(
    "ata=ATA092", "tecnica=T1557.003", "fuente=manual",
    "t0=$t0", "t1=$t1", "server=$server`:$port", "xid=$xid",
    "offer=$offer", "ack=$ack"
) | Out-File -FilePath $lease -Encoding ascii
@(
    "ata=ATA092", "tecnica=T1557.003", "fuente=manual",
    "t0=$t0", "t1=$t1", "lease=$lease", "ip=$clientIp", "gw=$gw", "dns=$dns",
    "ack_ok=$($ack -like 'DHCPACK*')"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
