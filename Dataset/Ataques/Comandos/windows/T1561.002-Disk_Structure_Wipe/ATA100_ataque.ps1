# ATA100 - T1561.002 Disk Structure Wipe (Windows)
# Manual: sembrar patron + MBR falso y poner a cero los primeros 1 MiB y el footer; VHD no montable; solo el VHD del caso; nunca PhysicalDrive/C:/sistema.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$vhd = Join-Path $dir 'labdisk100.vhd'
if ($dir -notlike 'C:\lab-attack\ATA100*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
if ($vhd -ne 'C:\lab-attack\ATA100\labdisk100.vhd') { Write-Error 'GUARDARRAIL: VHD no permitido'; exit 2 }
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
$fs = [IO.File]::Open($vhd, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite)
$fs.Seek(510, [IO.SeekOrigin]::Begin) | Out-Null
$fs.Write([byte[]](0x55, 0xAA), 0, 2)
$fs.Flush()
$fs.Close()
$antes = (Get-FileHash $vhd -Algorithm SHA256).Hash.ToLower()
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
Clear-VhdRange $vhd 0 1048576
Clear-VhdRange $vhd 104857600 512
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$despues = (Get-FileHash $vhd -Algorithm SHA256).Hash.ToLower()
$footer_ok = Test-VhdFooter $vhd
$montable = $true
try {
    $img = Mount-DiskImage -ImagePath $vhd -PassThru -ErrorAction Stop
    if ($img) { Dismount-DiskImage -ImagePath $vhd -ErrorAction SilentlyContinue | Out-Null }
} catch {
    Dismount-DiskImage -ImagePath $vhd -ErrorAction SilentlyContinue | Out-Null
    $montable = $false
}
$no_montable = (-not $montable) -and (-not $footer_ok) -and ($antes -ne $despues)
@(
    "ata=ATA100", "tecnica=T1561.002", "fuente=manual",
    "t0=$t0", "t1=$t1", "vhd=$vhd", "bytes=$((Get-Item $vhd).Length)",
    "sha256_antes=$antes", "sha256_despues=$despues",
    "footer_conectix=$footer_ok", "montable=$montable",
    "no_montable=$no_montable"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
