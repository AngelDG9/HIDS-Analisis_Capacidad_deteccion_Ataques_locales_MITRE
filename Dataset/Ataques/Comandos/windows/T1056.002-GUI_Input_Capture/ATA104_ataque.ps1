# ATA104 - T1056.002 GUI Input Capture (Windows)
# ART_adaptado: formulario GUI de juguete + SendKeys + captura PNG (S1, sesion interactiva); guardarrail C:\lab-attack\ATA104\; sin red externa.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA104*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$form = New-Object System.Windows.Forms.Form
$form.Text = 'TFG GUI Capture'
$form.Width = 460
$form.Height = 220
$form.TopMost = $true
$label = New-Object System.Windows.Forms.Label
$label.Text = 'Escribe el texto de juguete:'
$label.SetBounds(20, 20, 320, 20)
$form.Controls.Add($label)
$tb = New-Object System.Windows.Forms.TextBox
$tb.SetBounds(20, 50, 400, 25)
$form.Controls.Add($tb)
$form.Show()
$form.Activate()
$tb.Focus()
[System.Windows.Forms.Application]::DoEvents()
Start-Sleep -Milliseconds 700
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
[System.Windows.Forms.SendKeys]::SendWait('TFG-GUI-TEXT')
[System.Windows.Forms.Application]::DoEvents()
Start-Sleep -Milliseconds 700
$texto = $tb.Text
$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
$png = Join-Path $dir 'captura.png'
$bmp.Save($png, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose()
$bmp.Dispose()
$form.Close()
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$bytes = 0
if (Test-Path $png) { $bytes = (Get-Item $png).Length }
$ok = ($bytes -gt 0) -and ($texto -eq 'TFG-GUI-TEXT')
@(
    "ata=ATA104", "tecnica=T1056.002", "fuente=ART_adaptado",
    "t0=$t0", "t1=$t1", "png=$png", "png_bytes=$bytes",
    "texto=$texto", "captura_ok=$ok"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
