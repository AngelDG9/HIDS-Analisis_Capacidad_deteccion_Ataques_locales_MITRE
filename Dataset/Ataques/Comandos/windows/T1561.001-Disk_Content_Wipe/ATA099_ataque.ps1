# ATA099 - T1561.001 Disk Content Wipe (Windows)
# Manual: sembrar patron 0xAA y poner a cero el contenido del VHD; footer intacto; solo el VHD del caso; nunca PhysicalDrive/C:/sistema.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$vhd = Join-Path $dir 'labdisk100.vhd'
if ($dir -notlike 'C:\lab-attack\ATA099*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
if ($vhd -ne 'C:\lab-attack\ATA099\labdisk100.vhd') { Write-Error 'GUARDARRAIL: VHD no permitido'; exit 2 }
if (-not (Test-Path $vhd)) { Write-Error 'GUARDARRAIL: VHD ausente'; exit 2 }
if ((Get-Item $vhd).Length -ne 104858112) { Write-Error 'GUARDARRAIL: tamano VHD inesperado'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null

function Test-VhdFooter([string]$path) {
    $fs = [IO.File]::OpenRead($path)
    try {
        $fs.Seek(-512, [IO.SeekOrigin]::End) | Out-Null
        $buf = New-Object byte[] 8
        $fs.Read($buf, 0, 8) | Out-Null
        return ([Text.Encoding]::ASCII.GetString($buf) -eq 'conectix')
    } finally { $fs.Close() }
}

function Set-VhdPattern([string]$path, [byte]$value) {
    $chunk = New-Object byte[] (1048576)
    for ($i = 0; $i -lt $chunk.Length; $i++) { $chunk[$i] = $value }
    $fs = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite)
    try {
        $remaining = 104857600
        while ($remaining -gt 0) {
            $n = [Math]::Min($chunk.Length, $remaining)
            $fs.Write($chunk, 0, $n)
            $remaining -= $n
        }
        $fs.Flush()
    } finally { $fs.Close() }
}

function Clear-VhdRange([string]$path, [long]$offset, [long]$count) {
    $chunk = New-Object byte[] (1048576)
    $fs = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite)
    try {
        $fs.Seek($offset, [IO.SeekOrigin]::Begin) | Out-Null
        $remaining = $count
        while ($remaining -gt 0) {
            $n = [Math]::Min($chunk.Length, $remaining)
            $fs.Write($chunk, 0, $n)
            $remaining -= $n
        }
        $fs.Flush()
    } finally { $fs.Close() }
}

if (-not (Test-VhdFooter $vhd)) {
    'GUARDARRAIL: no es un VHD valido' | Out-File (Join-Path $ev 'efecto_local.txt') -Encoding ascii
    exit 2
}
Set-VhdPattern $vhd 0xAA
$antes = (Get-FileHash $vhd -Algorithm SHA256).Hash.ToLower()
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
Clear-VhdRange $vhd 0 104857600
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$despues = (Get-FileHash $vhd -Algorithm SHA256).Hash.ToLower()
$fs = [IO.File]::OpenRead($vhd)
$buf = New-Object byte[] 1048576
$fs.Read($buf, 0, $buf.Length) | Out-Null
$fs.Seek(-1024, [IO.SeekOrigin]::End) | Out-Null
$tail = New-Object byte[] 512
$fs.Read($tail, 0, 512) | Out-Null
$fs.Close()
$primero_cero = ($buf | Where-Object { $_ -ne 0 }).Count -eq 0
$ultimo_cero = ($tail | Where-Object { $_ -ne 0 }).Count -eq 0
$footer_ok = Test-VhdFooter $vhd
$borrado = $primero_cero -and $ultimo_cero -and $footer_ok -and ($antes -ne $despues)
@(
    "ata=ATA099", "tecnica=T1561.001", "fuente=manual",
    "t0=$t0", "t1=$t1", "vhd=$vhd", "bytes=$((Get-Item $vhd).Length)",
    "sha256_antes=$antes", "sha256_despues=$despues",
    "primero_cero=$primero_cero", "ultimo_cero=$ultimo_cero", "footer_conectix=$footer_ok",
    "contenido_borrado=$borrado"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
