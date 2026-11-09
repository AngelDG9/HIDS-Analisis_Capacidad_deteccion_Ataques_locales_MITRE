# ATA087 - T1499.002 Service Exhaustion Flood (Windows)
# Manual: servicio TCP desechable en loopback 9094; 200 peticiones; el servicio deja de responder.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA087*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$endpoint = '127.0.0.1'
$port = 9094
$service = Start-Job -ScriptBlock {
    param($p)
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $p)
    $listener.Start(1)
    $end = (Get-Date).AddSeconds(90)
    while ((Get-Date) -lt $end) {
        if ($listener.Pending()) {
            $client = $listener.AcceptTcpClient()
            Start-Sleep -Seconds 5
            $client.Close()
        } else {
            Start-Sleep -Milliseconds 50
        }
    }
    $listener.Stop()
} -ArgumentList $port
Start-Sleep -Seconds 2
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$ok = 0
$fail = 0
for ($i = 0; $i -lt 200; $i++) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($endpoint, $port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne(200)) { $c.EndConnect($iar); $ok++ } else { $fail++ }
    } catch { $fail++ }
    $c.Close()
}
$probe = New-Object System.Net.Sockets.TcpClient
$probeOk = $false
try {
    $pi = $probe.BeginConnect($endpoint, $port, $null, $null)
    $probeOk = $pi.AsyncWaitHandle.WaitOne(1000)
} catch { $probeOk = $false }
$probe.Close()
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
Stop-Job $service
Remove-Job $service -Force
@(
    "ata=ATA087", "tecnica=T1499.002", "fuente=manual",
    "t0=$t0", "t1=$t1", "endpoint=$endpoint`:$port",
    "peticiones=200", "ok=$ok", "fail=$fail", "servicio_responde=$probeOk"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
