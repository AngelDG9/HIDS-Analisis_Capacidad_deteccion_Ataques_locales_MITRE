# ATA105 - T1056.003 Web Portal Capture (Windows)
# manual: portal HttpListener en 127.0.0.1:8081 que captura un POST de juguete en creds.txt; guardarrail C:\lab-attack\ATA105\; sin red externa.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA105*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null

$port = 8081
$creds = Join-Path $dir 'creds.txt'
$job = Start-Job -ScriptBlock {
    param($p, $out)
    $l = New-Object System.Net.HttpListener
    $l.Prefixes.Add("http://127.0.0.1:$p/")
    $l.Start()
    $ctx = $l.GetContext()
    $reader = New-Object System.IO.StreamReader($ctx.Request.InputStream)
    $body = $reader.ReadToEnd()
    $reader.Close()
    $resp = [Text.Encoding]::UTF8.GetBytes('<html><body>TFG portal OK</body></html>')
    $ctx.Response.ContentType = 'text/html'
    $ctx.Response.OutputStream.Write($resp, 0, $resp.Length)
    $ctx.Response.Close()
    $l.Stop()
    Set-Content -Path $out -Value $body -Encoding ascii
} -ArgumentList $port, $creds
Start-Sleep -Seconds 2
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
try {
    $body = 'username=tfg_user&password=TFG-DUMMY-PASS'
    Invoke-WebRequest -Uri "http://127.0.0.1:$port/login" -Method POST -Body $body -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing -TimeoutSec 10 | Out-Null
} catch {
    'ERROR: ' + $_.Exception.Message | Out-File (Join-Path $ev 'efecto_error.txt') -Encoding ascii
}
Wait-Job $job -Timeout 15 | Out-Null
Receive-Job $job -ErrorAction SilentlyContinue | Out-Null
Remove-Job $job -Force -ErrorAction SilentlyContinue
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$capturado = Test-Path $creds
$usuario = ''
$passLen = 0
if ($capturado) {
    $c = Get-Content $creds -Raw
    if ($c -match 'username=([^&]+)') { $usuario = $Matches[1] }
    if ($c -match 'password=([^&]+)') { $passLen = $Matches[1].Length }
}
@(
    "ata=ATA105", "tecnica=T1056.003", "fuente=manual",
    "t0=$t0", "t1=$t1", "portal=127.0.0.1:$port", "creds=$creds",
    "creds_capturadas=$capturado", "usuario=$usuario", "password_longitud=$passLen"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
