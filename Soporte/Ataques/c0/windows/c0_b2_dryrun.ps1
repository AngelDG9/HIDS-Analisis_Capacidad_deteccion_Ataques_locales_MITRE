# c0_b2_dryrun.ps1 - B2.0: dry run BENIGNO de las clases nuevas de B2.
# NO es un ataque. Solo provoca eventos de SMB, SMTP, UDP, proxy, VHD, portal y API hooking.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$ev = 'C:\lab-attack\c0_b2'
New-Item -ItemType Directory -Force $ev | Out-Null
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

# SMB
$shareDir = Join-Path $ev 'labshare'
New-Item -ItemType Directory -Force $shareDir | Out-Null
Set-Content -Path (Join-Path $shareDir 'hola.txt') -Value 'TFG C0 SMB' -Encoding ascii
New-SmbShare -Name labshare -Path $shareDir -ReadAccess 'angel' -ErrorAction SilentlyContinue | Out-Null
Get-ChildItem '\\127.0.0.1\labshare' -ErrorAction SilentlyContinue | Out-Null

# SMTP 2525
$smtp = Start-Job -ScriptBlock {
    $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 2525)
    $l.Server.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
    $l.Start(5)
    Start-Sleep -Seconds 8
    $l.Stop()
}
Start-Sleep -Seconds 2
try {
    $c = New-Object System.Net.Sockets.TcpClient
    $c.Connect('127.0.0.1', 2525)
    $s = $c.GetStream()
    $b = [Text.Encoding]::ASCII.GetBytes("EHLO c0`r`n")
    $s.Write($b, 0, $b.Length); $s.Flush(); Start-Sleep -Milliseconds 300; $c.Close()
} catch {}

# UDP 5353
try {
    $u = New-Object System.Net.Sockets.UdpClient
    $u.ExclusiveAddressUse = $false
    $u.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
    $u.Client.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Loopback, 5353)))
    $p = [Text.Encoding]::ASCII.GetBytes('TFG-C0-UDP')
    $u.Send($p, $p.Length, '127.0.0.1', 5353) | Out-Null
    Start-Sleep -Milliseconds 300; $u.Close()
} catch {}
# UDP 67
try {
    $u2 = New-Object System.Net.Sockets.UdpClient(67)
    $p2 = [Text.Encoding]::ASCII.GetBytes('TFG-C0-DHCP')
    $u2.Send($p2, $p2.Length, '127.0.0.1', 67) | Out-Null
    Start-Sleep -Milliseconds 300; $u2.Close()
} catch {}

# Proxy 9095
$proxy = Start-Job -ScriptBlock {
    $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 9095)
    $l.Server.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
    $l.Start(5)
    Start-Sleep -Seconds 8
    $l.Stop()
}
Start-Sleep -Seconds 2
try {
    $c2 = New-Object System.Net.Sockets.TcpClient
    $c2.Connect('127.0.0.1', 9095)
    $s2 = $c2.GetStream()
    $b2 = [Text.Encoding]::ASCII.GetBytes("GET http://example.local/ HTTP/1.1`r`nHost: example.local`r`n`r`n")
    $s2.Write($b2, 0, $b2.Length); $s2.Flush(); Start-Sleep -Milliseconds 300; $c2.Close()
} catch {}

# Portal 8081
$portal = Start-Job -ScriptBlock {
    $l = New-Object System.Net.HttpListener
    $l.Prefixes.Add('http://127.0.0.1:8081/')
    $l.Start()
    $task = $l.GetContextAsync()
    if ($task.Wait(5000)) { $ctx = $task.Result; $ctx.Response.StatusCode = 200; $ctx.Response.Close() }
    $l.Stop()
}
Start-Sleep -Seconds 2
try { Invoke-WebRequest 'http://127.0.0.1:8081/' -UseBasicParsing -TimeoutSec 5 | Out-Null } catch {}

# VHD (crear, NO montar)
$vhdDir = 'C:\lab-attack\ATA098'
New-Item -ItemType Directory -Force $vhdDir | Out-Null
$vhd = Join-Path $vhdDir 'labdisk100.vhd'
if (Test-Path $vhd) { Remove-Item $vhd -Force }
$script = 'create vdisk file="' + $vhd + '" maximum=100 type=fixed'
$script | diskpart | Out-Null

# API hooking: NO se ejecuta en B2.0 (DLL pre-staged; la clase se mide en B2.4).
$dll = 'C:\lab-attack\ATA106\T1056.004x64.dll (pre-staged; no cargada en C0)'

# Cierre
foreach ($j in @($smtp, $proxy, $portal)) {
    if ($j) { Stop-Job $j -ErrorAction SilentlyContinue; Remove-Job $j -Force -ErrorAction SilentlyContinue }
}
Remove-SmbShare -Name labshare -Force -ErrorAction SilentlyContinue | Out-Null
Remove-Item -Recurse -Force $shareDir -ErrorAction SilentlyContinue
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@(
    "c0_b2_start=$t0", "c0_b2_end=$t1",
    "smb=1", "smtp=1", "udp5353=1", "udp67=1", "proxy=1", "portal=1",
    "vhd=$vhd", "dll=$dll"
) | Out-File (Join-Path $ev 'markers.txt') -Encoding ascii
exit 0
