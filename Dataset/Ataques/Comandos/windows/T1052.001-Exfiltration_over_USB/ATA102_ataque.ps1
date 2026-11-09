# ATA102 - T1052.001 Exfiltration over USB (Windows)
# Manual: crear 20 ficheros de botin y copiarlos al VHD montado; desmontar y verificar; solo el VHD del caso; nunca PhysicalDrive/C:/sistema.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$vhd = Join-Path $dir 'labdisk100.vhd'
if ($dir -notlike 'C:\lab-attack\ATA102*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
if ($vhd -ne 'C:\lab-attack\ATA102\labdisk100.vhd') { Write-Error 'GUARDARRAIL: VHD no permitido'; exit 2 }
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

function Mount-LabVhd([string]$path) {
    $img = Get-DiskImage -ImagePath $path -ErrorAction SilentlyContinue
    if ($img -and $img.Attached) { Dismount-DiskImage -ImagePath $path -ErrorAction SilentlyContinue | Out-Null; Start-Sleep -Seconds 2 }
    $img = Mount-DiskImage -ImagePath $path -PassThru -ErrorAction Stop
    $disk = $img | Get-Disk
    if ($disk.IsSystem -or $disk.IsBoot) { throw 'GUARDARRAIL: disco de sistema' }
    if ($disk.Size -ne 104857600) { throw 'GUARDARRAIL: tamano de disco inesperado' }
    Set-Disk -Number $disk.Number -IsOffline $false -IsReadOnly $false -ErrorAction SilentlyContinue
    if ($disk.PartitionStyle -eq 'RAW') {
        Initialize-Disk -Number $disk.Number -PartitionStyle MBR -Confirm:$false -ErrorAction Stop
    }
    $part = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 'Basic' } | Select-Object -First 1
    if (-not $part) {
        $part = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter -ErrorAction Stop
    }
    if (-not $part.DriveLetter) {
        Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -AssignDriveLetter -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        $part = Get-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber
    }
    $vol = Get-Volume -Partition $part -ErrorAction SilentlyContinue
    if (-not $vol -or -not $vol.FileSystem) {
        Start-Sleep -Seconds 1
        Format-Volume -Partition $part -FileSystem NTFS -NewFileSystemLabel 'TFGLAB' -Confirm:$false -ErrorAction Stop | Out-Null
        Start-Sleep -Seconds 2
        $vol = Get-Volume -Partition $part
    }
    return [pscustomobject]@{ Disk = $disk; Partition = $part; Root = ($part.DriveLetter + ':\') }
}

$botin = Join-Path $dir 'botin'
New-Item -ItemType Directory -Force -Path $botin | Out-Null
1..20 | ForEach-Object { Set-Content -Path (Join-Path $botin ("loot_{0:D2}.txt" -f $_)) -Value ("TFG loot $_ " + ('E' * 64)) -Encoding ascii }
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$m = $null
$n = 0
$persistido = $false
try {
    $m = Mount-LabVhd $vhd
    $exfil = Join-Path $m.Root 'exfil'
    New-Item -ItemType Directory -Force -Path $exfil | Out-Null
    Copy-Item -Path (Join-Path $botin '*') -Destination $exfil -Force
    $n = (Get-ChildItem $exfil -File).Count
} catch {
    'ERROR: ' + $_.Exception.Message | Out-File (Join-Path $ev 'efecto_error.txt') -Encoding ascii
} finally {
    Dismount-DiskImage -ImagePath $vhd -ErrorAction SilentlyContinue | Out-Null
}
Start-Sleep -Seconds 2
try {
    $m2 = Mount-LabVhd $vhd
    $n2 = (Get-ChildItem (Join-Path $m2.Root 'exfil') -File -ErrorAction SilentlyContinue).Count
    $persistido = ($n2 -eq $n) -and ($n -eq 20)
} catch {
    'ERROR remount: ' + $_.Exception.Message | Out-File (Join-Path $ev 'efecto_error.txt') -Encoding ascii
} finally {
    Dismount-DiskImage -ImagePath $vhd -ErrorAction SilentlyContinue | Out-Null
}
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@(
    "ata=ATA102", "tecnica=T1052.001", "fuente=manual",
    "t0=$t0", "t1=$t1", "vhd=$vhd", "bytes=$((Get-Item $vhd).Length)",
    "ficheros_en_vhd=$n", "persistido=$persistido", "exfil_ok=$($persistido -and $n -eq 20)"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
