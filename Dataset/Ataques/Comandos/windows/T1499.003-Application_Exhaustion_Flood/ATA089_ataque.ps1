# ATA089 - T1499.003 Application Exhaustion Flood (Windows)
# Manual: app de juguete 127.0.0.1:9093 (single-thread, /slow 200 ms); 200 peticiones.
# No se toca ningun servicio del host: la app es del invitado (loopback).
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA089*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$endpoint = '127.0.0.1'
$port = 9093
$app = Start-Job -ScriptBlock {
    param($p)
    $l = New-Object System.Net.HttpListener
    $l.Prefixes.Add("http://127.0.0.1:$p/")
    $l.Start()
    $end = (Get-Date).AddSeconds(90)
    while ((Get-Date) -lt $end) {
        $task = $l.GetContextAsync()
        if (-not $task.Wait(500)) { continue }
        $ctx = $task.Result
        if ($ctx.Request.Url.AbsolutePath -eq '/slow') { Start-Sleep -Milliseconds 200 }
        $body = [Text.Encoding]::UTF8.GetBytes('OK')
        $ctx.Response.StatusCode = 200
        $ctx.Response.ContentLength64 = $body.Length
        $ctx.Response.OutputStream.Write($body, 0, $body.Length)
        $ctx.Response.Close()
    }
    $l.Stop()
} -ArgumentList $port
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    try { Invoke-WebRequest "http://$endpoint`:$port/health" -UseBasicParsing -TimeoutSec 2 | Out-Null; $ready = $true; break } catch { Start-Sleep -Milliseconds 500 }
}
if (-not $ready) {
    'GUARDARRAIL: app no responde' | Out-File (Join-Path $ev 'efecto_local.txt') -Encoding ascii
    Stop-Job $app -ErrorAction SilentlyContinue; Remove-Job $app -Force -ErrorAction SilentlyContinue
    exit 2
}
function Get-Latency([string]$url) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try { Invoke-WebRequest $url -UseBasicParsing -TimeoutSec 5 | Out-Null } catch {}
    $sw.Stop()
    return [int]$sw.ElapsedMilliseconds
}
$before = (1..3 | ForEach-Object { Get-Latency "http://$endpoint`:$port/health" } | Measure-Object -Average).Average
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$workers = @()
1..10 | ForEach-Object {
    $workers += Start-Job -ScriptBlock {
        param($u)
        1..20 | ForEach-Object { try { Invoke-WebRequest "$u/slow" -UseBasicParsing -TimeoutSec 5 | Out-Null } catch {} }
    } -ArgumentList "http://$endpoint`:$port"
}
Start-Sleep -Milliseconds 500
$during = Get-Latency "http://$endpoint`:$port/health"
Wait-Job $workers -Timeout 60 | Out-Null
$workers | ForEach-Object { Stop-Job $_ -ErrorAction SilentlyContinue; Remove-Job $_ -Force -ErrorAction SilentlyContinue }
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$after = Get-Latency "http://$endpoint`:$port/health"
Stop-Job $app -ErrorAction SilentlyContinue
Remove-Job $app -Force -ErrorAction SilentlyContinue
$exhausted = ($during -gt [Math]::Max(1000, 2 * $before))
@(
    "ata=ATA089", "tecnica=T1499.003", "fuente=manual",
    "t0=$t0", "t1=$t1", "endpoint=$endpoint`:$port", "peticiones=200",
    "before_ms=$([math]::Round($before,1))", "during_ms=$during", "after_ms=$after",
    "exhausted=$exhausted"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
