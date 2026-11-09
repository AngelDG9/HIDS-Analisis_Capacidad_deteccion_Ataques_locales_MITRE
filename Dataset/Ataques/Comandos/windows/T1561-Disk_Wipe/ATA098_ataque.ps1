# ATA098 - T1561 Disk Wipe (Windows)
# Manual: sembrar patron 0xAA y sobrescribir el volumen con 0xFF (corrupcion); footer VHD intacto; solo el VHD del caso; nunca PhysicalDrive/C:/sistema.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$vhd = Join-Path $dir 'labdisk100.vhd'
if ($dir -notlike 'C:\lab-attack\ATA098*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
if ($vhd -ne 'C:\lab-attack\ATA098\labdisk100.vhd') { Write-Error 'GUARDARRAIL: VHD no permitido'; exit 2 }
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

function Open-VhdForWrite([string]$path) {
    for ($i = 0; $i -lt 40; $i++) {
        try {
            return [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite)
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    throw "no se pudo abrir el VHD para escritura: $path"
}

function Set-VhdPattern([string]$path, [byte]$value) {
    $chunk = New-Object byte[] (1048576)
    for ($i = 0; $i -lt $chunk.Length; $i++) { $chunk[$i] = $value }
    $fs = Open-VhdForWrite $path
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
    $fs = Open-VhdForWrite $path
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
Set-VhdPattern $vhd 0xFF
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$despues = (Get-FileHash $vhd -Algorithm SHA256).Hash.ToLower()
$fs = [IO.File]::OpenRead($vhd)
$buf = New-Object byte[] 16
$fs.Read($buf, 0, 16) | Out-Null
$fs.Close()
$cabecera_ff = ($buf | Where-Object { $_ -ne 0xFF }).Count -eq 0
$footer_ok = Test-VhdFooter $vhd
$corrupto = $cabecera_ff -and $footer_ok -and ($antes -ne $despues)
@(
    "ata=ATA098", "tecnica=T1561", "fuente=manual",
    "t0=$t0", "t1=$t1", "vhd=$vhd", "bytes=$((Get-Item $vhd).Length)",
    "sha256_antes=$antes", "sha256_despues=$despues",
    "cabecera_ff=$cabecera_ff", "footer_conectix=$footer_ok",
    "vhd_corrupto=$corrupto"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
