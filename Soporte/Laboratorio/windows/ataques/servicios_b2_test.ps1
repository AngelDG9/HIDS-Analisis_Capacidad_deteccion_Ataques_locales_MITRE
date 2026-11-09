# servicios_b2_test.ps1 - B2.0: prueba benigna de los servicios locales de B2.
# NO es un ataque. Levanta SMB/SMTP/proxy/app/UDP/portal en loopback, los prueba
# y los apaga. Todo bajo C:\lab-attack. Sin secretos.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$root = 'C:\lab-attack'
$shareDir = Join-Path $root 'labshare'
$ev = Join-Path $root 'evidencias_servicios_b2.txt'
New-Item -ItemType Directory -Force -Path $shareDir | Out-Null
Set-Content -Path (Join-Path $shareDir 'hola.txt') -Value 'TFG B2 labshare' -Encoding ascii

function Log([string]$m) {
    $line = ((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) + ' ' + $m
    Add-Content -Path $ev -Value $line -Encoding ascii
    Write-Host $line
}
Set-Content -Path $ev -Value '# B2.0 servicios locales - prueba benigna' -Encoding ascii

# SMB share (loopback, solo C:\lab-attack\labshare)
try {
    $existing = Get-SmbShare -Name labshare -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-SmbShare -Name labshare -Path $shareDir -ReadAccess 'angel' -ErrorAction Stop | Out-Null
        Log 'smb_create=OK'
    } else {
        Log 'smb_create=EXISTE'
    }
} catch { Log "smb_create=FAIL $($_.Exception.Message)" }

# SMTP sink 127.0.0.1:2525
$smtp = Start-Job -ScriptBlock {
    $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 2525)
    $l.Server.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
    $l.Start(5)
    $end = (Get-Date).AddSeconds(40)
    while ((Get-Date) -lt $end) {
        if ($l.Pending()) {
            $c = $l.AcceptTcpClient()
            $s = $c.GetStream()
            $buf = New-Object byte[] 1024
            $n = $s.Read($buf, 0, $buf.Length)
            $resp = [Text.Encoding]::ASCII.GetBytes("220 TFG-SMTP`r`n250 OK`r`n")
            $s.Write($resp, 0, $resp.Length)
            $s.Flush(); $c.Close()
        } else { Start-Sleep -Milliseconds 50 }
    }
    $l.Stop()
}
# Proxy 127.0.0.1:9095 (responde 200 a cualquier peticion)
$proxy = Start-Job -ScriptBlock {
    $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 9095)
    $l.Server.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
    $l.Start(5)
    $end = (Get-Date).AddSeconds(40)
    while ((Get-Date) -lt $end) {
        if ($l.Pending()) {
            $c = $l.AcceptTcpClient()
            $s = $c.GetStream()
            $buf = New-Object byte[] 4096
            $null = $s.Read($buf, 0, $buf.Length)
            $resp = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: 2`r`n`r`nOK")
            $s.Write($resp, 0, $resp.Length)
            $s.Flush(); $c.Close()
        } else { Start-Sleep -Milliseconds 50 }
    }
    $l.Stop()
}
# App 127.0.0.1:9093 (HttpListener)
$app = Start-Job -ScriptBlock {
    $l = New-Object System.Net.HttpListener
    $l.Prefixes.Add('http://127.0.0.1:9093/')
    $l.Start()
    $end = (Get-Date).AddSeconds(40)
    while ((Get-Date) -lt $end) {
        $task = $l.GetContextAsync()
        if (-not $task.Wait(1000)) { continue }
        $ctx = $task.Result
        $body = [Text.Encoding]::UTF8.GetBytes('APP-OK')
        $ctx.Response.StatusCode = 200
        $ctx.Response.ContentLength64 = $body.Length
        $ctx.Response.OutputStream.Write($body, 0, $body.Length)
        $ctx.Response.Close()
    }
    $l.Stop()
}
# UDP 5353 (amplificador 4x) y 67 (DHCP sintetico)
$udp5353 = Start-Job -ScriptBlock {
    $u = New-Object System.Net.Sockets.UdpClient
    $u.ExclusiveAddressUse = $false
    $u.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
    $u.Client.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Loopback, 5353)))
    $end = (Get-Date).AddSeconds(40)
    while ((Get-Date) -lt $end) {
        if ($u.Available -gt 0) {
            $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $data = $u.Receive([ref]$ep)
            $big = New-Object byte[] ($data.Length * 4)
            for ($i = 0; $i -lt 4; $i++) { [Array]::Copy($data, 0, $big, $i * $data.Length, $data.Length) }
            $u.Send($big, $big.Length, $ep) | Out-Null
        } else { Start-Sleep -Milliseconds 50 }
    }
    $u.Close()
}
$udp67 = Start-Job -ScriptBlock {
    $u = New-Object System.Net.Sockets.UdpClient(67)
    $end = (Get-Date).AddSeconds(40)
    while ((Get-Date) -lt $end) {
        if ($u.Available -gt 0) {
            $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $null = $u.Receive([ref]$ep)
            $resp = [Text.Encoding]::ASCII.GetBytes('DHCP-OFFER-TFG')
            $u.Send($resp, $resp.Length, $ep) | Out-Null
        } else { Start-Sleep -Milliseconds 50 }
    }
    $u.Close()
}
# Portal 127.0.0.1:8081 (HttpListener)
$portal = Start-Job -ScriptBlock {
    $l = New-Object System.Net.HttpListener
    $l.Prefixes.Add('http://127.0.0.1:8081/')
    $l.Start()
    $end = (Get-Date).AddSeconds(40)
    while ((Get-Date) -lt $end) {
        $task = $l.GetContextAsync()
        if (-not $task.Wait(1000)) { continue }
        $ctx = $task.Result
        $body = [Text.Encoding]::UTF8.GetBytes('<html><form action="/login" method="post"><input name="user"></form></html>')
        $ctx.Response.StatusCode = 200
        $ctx.Response.ContentLength64 = $body.Length
        $ctx.Response.OutputStream.Write($body, 0, $body.Length)
        $ctx.Response.Close()
    }
    $l.Stop()
}
Start-Sleep -Seconds 10

# SMB probe
try {
    $items = Get-ChildItem '\\127.0.0.1\labshare' -ErrorAction Stop
    Log "smb_probe=OK items=$($items.Count)"
} catch { Log "smb_probe=FAIL $($_.Exception.Message)" }

# SMTP probe
try {
    $c = New-Object System.Net.Sockets.TcpClient
    $c.Connect('127.0.0.1', 2525)
    $s = $c.GetStream()
    $msg = [Text.Encoding]::ASCII.GetBytes("EHLO test`r`n")
    $s.Write($msg, 0, $msg.Length); $s.Flush()
    $buf = New-Object byte[] 512
    $n = $s.Read($buf, 0, $buf.Length)
    $txt = [Text.Encoding]::ASCII.GetString($buf, 0, $n)
    $c.Close()
    Log "smtp_probe=OK resp=$($txt.Trim())"
} catch { Log "smtp_probe=FAIL $($_.Exception.Message)" }

# Proxy probe
try {
    $c = New-Object System.Net.Sockets.TcpClient
    $c.Connect('127.0.0.1', 9095)
    $s = $c.GetStream()
    $req = [Text.Encoding]::ASCII.GetBytes("GET http://example.local/ HTTP/1.1`r`nHost: example.local`r`n`r`n")
    $s.Write($req, 0, $req.Length); $s.Flush()
    $buf = New-Object byte[] 1024
    $n = $s.Read($buf, 0, $buf.Length)
    $txt = [Text.Encoding]::ASCII.GetString($buf, 0, $n)
    $c.Close()
    Log "proxy_probe=OK resp=$($txt.Split("`r")[0])"
} catch { Log "proxy_probe=FAIL $($_.Exception.Message)" }

# App probe
try {
    $r = Invoke-WebRequest -Uri 'http://127.0.0.1:9093/' -UseBasicParsing -TimeoutSec 5
    Log "app_probe=OK status=$([int]$r.StatusCode) body=$($r.Content)"
} catch { Log "app_probe=FAIL $($_.Exception.Message)" }

# UDP 5353 probe
try {
    $u = New-Object System.Net.Sockets.UdpClient
    $u.Client.ReceiveTimeout = 3000
    $payload = [Text.Encoding]::ASCII.GetBytes('TFG-UDP-AMPLIFIER-64-BYTES-' + ('X' * 36))
    $u.Send($payload, $payload.Length, '127.0.0.1', 5353) | Out-Null
    $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    $resp = $u.Receive([ref]$ep)
    $u.Close()
    Log "udp5353_probe=OK sent=$($payload.Length) recv=$($resp.Length)"
} catch { Log "udp5353_probe=FAIL $($_.Exception.Message)" }

# UDP 67 probe
try {
    $u = New-Object System.Net.Sockets.UdpClient
    $u.Client.ReceiveTimeout = 3000
    $payload = [Text.Encoding]::ASCII.GetBytes('DHCP-DISCOVER-TFG')
    $u.Send($payload, $payload.Length, '127.0.0.1', 67) | Out-Null
    $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    $resp = $u.Receive([ref]$ep)
    $u.Close()
    Log "udp67_probe=OK recv=$([Text.Encoding]::ASCII.GetString($resp))"
} catch { Log "udp67_probe=FAIL $($_.Exception.Message)" }

# Portal probe
try {
    $r = Invoke-WebRequest -Uri 'http://127.0.0.1:8081/' -UseBasicParsing -TimeoutSec 5
    Log "portal_probe=OK status=$([int]$r.StatusCode)"
} catch { Log "portal_probe=FAIL $($_.Exception.Message)" }

# Cierre
foreach ($j in @($smtp, $proxy, $app, $udp5353, $udp67, $portal)) {
    if ($j) { Stop-Job $j -ErrorAction SilentlyContinue; Remove-Job $j -Force -ErrorAction SilentlyContinue }
}
try { Remove-SmbShare -Name labshare -Force -ErrorAction SilentlyContinue | Out-Null; Log 'smb_delete=OK' } catch { Log "smb_delete=FAIL $($_.Exception.Message)" }
Remove-Item -Recurse -Force $shareDir -ErrorAction SilentlyContinue
Log 'fin servicios_b2'
exit 0
