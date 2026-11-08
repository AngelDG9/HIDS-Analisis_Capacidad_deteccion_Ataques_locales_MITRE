# ATA061 - T1486 Data Encrypted for Impact (Windows)
# Manual (el atomic T1486 exige GPG4Win/DiskCryptor o solo cifra extension .akira).
# AES-256-CBC con .NET sobre los ficheros pre-staged en .\datos.
# Prueba de efecto: sha256(original) != sha256(.enc) y descifrado == original.
# Guardarrail: solo escribe bajo la carpeta del caso (datos/*.enc, datos/*.dec).
$ErrorActionPreference = 'Continue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$datos = Join-Path $dir 'datos'
if (-not (Test-Path $datos)) {
    "ERROR: falta $datos (pre-staging)" | Out-File (Join-Path $ev 'efecto_local.txt') -Encoding ascii
    exit 3
}

$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$key = [byte[]](0..31)
$iv = [byte[]](0..15)
$lineas = @()
$ok = 0
$total = 0
Get-ChildItem $datos -File -Filter *.txt | Sort-Object Name | ForEach-Object {
    $total++
    $f = $_
    $before = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower()
    $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.IV = $iv
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $enc = $aes.CreateEncryptor().TransformFinalBlock($bytes, 0, $bytes.Length)
    $encPath = $f.FullName + '.enc'
    [System.IO.File]::WriteAllBytes($encPath, $enc)
    $after = (Get-FileHash $encPath -Algorithm SHA256).Hash.ToLower()
    $dec = $aes.CreateDecryptor().TransformFinalBlock($enc, 0, $enc.Length)
    $decPath = $f.FullName + '.dec'
    [System.IO.File]::WriteAllBytes($decPath, $dec)
    $decHash = (Get-FileHash $decPath -Algorithm SHA256).Hash.ToLower()
    $aes.Dispose()
    $cifrado = ($before -ne $after)
    $roundtrip = ($decHash -eq $before)
    if ($cifrado -and $roundtrip) { $ok++ }
    $lineas += ("file={0} before={1} enc={2} dec={3} cifrado={4} roundtrip={5}" -f $f.Name, $before, $after, $decHash, $cifrado, $roundtrip)
}
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$cabecera = @(
    "ata=ATA061",
    "tecnica=T1486",
    "fuente=propio",
    "algoritmo=AES-256-CBC",
    "t0=$t0",
    "t1=$t1",
    "ficheros_total=$total",
    "ficheros_cifrados_ok=$ok"
)
$salida = $cabecera + $lineas
$salida | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
@("t0=$t0", "t1=$t1") | Out-File -FilePath (Join-Path $ev 'times.log') -Encoding ascii
if ($ok -ne $total) { exit 4 }
exit 0
