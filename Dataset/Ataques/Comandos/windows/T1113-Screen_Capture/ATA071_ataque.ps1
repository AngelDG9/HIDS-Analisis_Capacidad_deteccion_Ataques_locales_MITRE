$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA071*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'; New-Item -ItemType Directory -Force -Path $ev | Out-Null
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$screen = [Windows.Forms.SystemInformation]::VirtualScreen
$bmp = New-Object Drawing.Bitmap $screen.Width, $screen.Height
$g = [Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($screen.Left, $screen.Top, 0, 0, $bmp.Size)
$png = Join-Path $ev 'screen.png'
$bmp.Save($png, [Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$fi = Get-Item $png
@(
    "ata=ATA071", "tecnica=T1113", "fuente=ART_adaptado",
    "guid=e9313014-985a-48ef-80d9-cde604ffc187",
    "t0=$t0", "t1=$t1", "png=$png", "bytes=$($fi.Length)",
    "width=$($screen.Width)", "height=$($screen.Height)"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
