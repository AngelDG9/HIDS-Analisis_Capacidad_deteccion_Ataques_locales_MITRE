# c0_b2_gui_dryrun.ps1 - B2.0: dry run BENIGNO de la clase GUI (S1).
# NO es un ataque: SendKeys benigno + captura de pantalla para ver que eventos genera.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$ev = 'C:\lab-attack\c0_b2_gui'
New-Item -ItemType Directory -Force $ev | Out-Null
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.SendKeys]::SendWait('tfg-c0')
Start-Sleep -Milliseconds 500
$bmp = New-Object Drawing.Bitmap 800, 600
$g = [Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen(0, 0, 0, 0, $bmp.Size)
$bmp.Save((Join-Path $ev 'screen.png'), [Drawing.Imaging.ImageFormat]::Png)
$g.Dispose()
$bmp.Dispose()
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@("gui_start=$t0", "gui_end=$t1", "png=1") | Out-File (Join-Path $ev 'markers.txt') -Encoding ascii
exit 0
