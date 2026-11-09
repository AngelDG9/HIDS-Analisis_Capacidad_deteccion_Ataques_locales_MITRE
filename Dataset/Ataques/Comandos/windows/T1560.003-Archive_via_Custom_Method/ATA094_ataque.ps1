# ATA094 - T1560.003 Archive via Custom Method (Windows)
# Manual: formato propio TFGARCH1 (cabecera + XOR 0x5A) con 20 ficheros; decodificado verificado.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA094*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$datos = Join-Path $dir 'datos'
New-Item -ItemType Directory -Force -Path $datos | Out-Null
1..20 | ForEach-Object { Set-Content -Path (Join-Path $datos ("doc_$_.txt")) -Value ("TFG custom $_ " + ('B' * 64)) -Encoding ascii }
$files = Get-ChildItem $datos -File | Sort-Object Name
if ($files.Count -gt 200) { Write-Error 'GUARDARRAIL: demasiados ficheros'; exit 2 }
$archivo = Join-Path $dir 'custom.tfg'
$ms = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter($ms)
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$bw.Write([Text.Encoding]::ASCII.GetBytes('TFGARCH1'))
$bw.Write([int]$files.Count)
foreach ($f in $files) {
    $name = [Text.Encoding]::UTF8.GetBytes($f.Name)
    $data = [IO.File]::ReadAllBytes($f.FullName)
    $bw.Write([int]$name.Length)
    $bw.Write($name)
    $bw.Write([int]$data.Length)
    for ($i = 0; $i -lt $data.Length; $i++) { $data[$i] = $data[$i] -bxor 0x5A }
    $bw.Write($data)
}
$bw.Flush()
[IO.File]::WriteAllBytes($archivo, $ms.ToArray())
$bw.Close()
$ms.Close()
$sha = (Get-FileHash $archivo -Algorithm SHA256).Hash.ToLower()
$br = New-Object System.IO.BinaryReader([IO.File]::OpenRead($archivo))
$magic = [Text.Encoding]::ASCII.GetString($br.ReadBytes(8))
$n = $br.ReadInt32()
$extraido = Join-Path $dir 'extraido'
if (Test-Path $extraido) { Remove-Item $extraido -Recurse -Force }
New-Item -ItemType Directory -Force -Path $extraido | Out-Null
for ($k = 0; $k -lt $n; $k++) {
    $nl = $br.ReadInt32()
    $name = [Text.Encoding]::UTF8.GetString($br.ReadBytes($nl))
    $size = $br.ReadInt32()
    $data = $br.ReadBytes($size)
    for ($i = 0; $i -lt $data.Length; $i++) { $data[$i] = $data[$i] -bxor 0x5A }
    [IO.File]::WriteAllBytes((Join-Path $extraido $name), $data)
}
$br.Close()
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$ok = $true
foreach ($f in $files) {
    $a = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower()
    $b = (Get-FileHash (Join-Path $extraido $f.Name) -Algorithm SHA256).Hash.ToLower()
    if ($a -ne $b) { $ok = $false }
}
@(
    "ata=ATA094", "tecnica=T1560.003", "fuente=manual",
    "t0=$t0", "t1=$t1", "archivo=$archivo", "magic=$magic",
    "ficheros=$n", "custom_sha256=$sha", "decodificado_ok=$ok"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
