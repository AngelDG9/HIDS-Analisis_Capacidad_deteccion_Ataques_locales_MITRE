# ATA101 - T1025 Data from Removable Media (Windows)
# ART_adaptado: montar el VHD, crear 20 documentos de juguete y copiarlos a C:\lab-attack\ATA101\copiados; solo el VHD del caso; nunca PhysicalDrive/C:/sistema.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$vhd = Join-Path $dir 'labdisk100.vhd'
if ($dir -notlike 'C:\lab-attack\ATA101*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
if ($vhd -ne 'C:\lab-attack\ATA101\labdisk100.vhd') { Write-Error 'GUARDARRAIL: VHD no permitido'; exit 2 }
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

function Mount-LabVhd([string]$path) {
    $img = Get-DiskImage -ImagePath $path -ErrorAction SilentlyContinue
    if ($img -and $img.Attached) { Dismount-DiskImage -ImagePath $path -ErrorAction SilentlyContinue | Out-Null; Start-Sleep -Seconds 2 }
    Mount-DiskImage -ImagePath $path -PassThru -ErrorAction Stop | Out-Null
    Start-Sleep -Seconds 2
    $disk = Get-Disk | Where-Object { $_.BusType -eq 'File Backed Virtual' -and $_.Location -eq $path } | Select-Object -First 1
    if (-not $disk) { throw 'GUARDARRAIL: no se encontro el disco del VHD' }
    if ($disk.IsSystem -or $disk.IsBoot) { throw 'GUARDARRAIL: disco de sistema' }
    if ($disk.Size -ne 104857600) { throw 'GUARDARRAIL: tamano de disco inesperado' }
    Set-Disk -Number $disk.Number -IsOffline $false -ErrorAction SilentlyContinue
    Set-Disk -Number $disk.Number -IsReadOnly $false -ErrorAction SilentlyContinue
    if ($disk.PartitionStyle -eq 'RAW') {
        Initialize-Disk -Number $disk.Number -PartitionStyle MBR -Confirm:$false -ErrorAction Stop
    }
    $part = $null
    for ($k = 0; $k -lt 20; $k++) {
        $part = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue | Sort-Object Size -Descending | Select-Object -First 1
        if ($part) { break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $part) {
        $part = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter -ErrorAction Stop
    }
    if (-not $part.DriveLetter) {
        Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -AssignDriveLetter -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        $part = Get-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber
    }
    $vol = Get-Volume -DriveLetter $part.DriveLetter -ErrorAction SilentlyContinue
    if (-not $vol -or -not $vol.FileSystem) {
        Start-Sleep -Seconds 1
        Format-Volume -DriveLetter $part.DriveLetter -FileSystem NTFS -NewFileSystemLabel 'TFGLAB' -Confirm:$false -ErrorAction Stop | Out-Null
        Start-Sleep -Seconds 2
        $vol = Get-Volume -DriveLetter $part.DriveLetter
    }
    return [pscustomobject]@{ Disk = $disk; Partition = $part; Root = ($part.DriveLetter + ':\') }
}

$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$m = $null
$ok = $false
$n = 0
$sha_ok = $false
try {
    $m = Mount-LabVhd $vhd
    $media = Join-Path $m.Root 'media'
    New-Item -ItemType Directory -Force -Path $media | Out-Null
    1..20 | ForEach-Object { Set-Content -Path (Join-Path $media ("doc_{0:D2}.txt" -f $_)) -Value ("TFG removable media $_ " + ('D' * 64)) -Encoding ascii }
    $copiados = Join-Path $dir 'copiados'
    if (Test-Path $copiados) { Remove-Item $copiados -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $copiados | Out-Null
    Copy-Item -Path (Join-Path $media '*') -Destination $copiados -Force
    $src = Get-ChildItem $media -File
    $dst = Get-ChildItem $copiados -File
    $n = $dst.Count
    $sha_ok = $true
    foreach ($f in $src) {
        $a = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower()
        $b = (Get-FileHash (Join-Path $copiados $f.Name) -Algorithm SHA256).Hash.ToLower()
        if ($a -ne $b) { $sha_ok = $false }
    }
    $ok = ($n -eq 20) -and $sha_ok
} catch {
    'ERROR: ' + $_.Exception.Message | Out-File (Join-Path $ev 'efecto_error.txt') -Encoding ascii
} finally {
    Dismount-DiskImage -ImagePath $vhd -ErrorAction SilentlyContinue | Out-Null
}
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@(
    "ata=ATA101", "tecnica=T1025", "fuente=ART_adaptado",
    "t0=$t0", "t1=$t1", "vhd=$vhd", "bytes=$((Get-Item $vhd).Length)",
    "ficheros_copiados=$n", "sha256_coinciden=$sha_ok", "copiado_ok=$ok"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
