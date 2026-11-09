# ATA081 - T1114.001 Local Email Collection (Windows)
# Fuente ART: T1114.001 "Email Collection with PowerShell Get-Inbox"
# (guid 3f1b5096-0139-4736-9b78-19bcb02bb1cb).
# Adaptacion declarada: no hay Outlook; se crea un perfil de correo sintetico
# (.eml + .pst de juguete) y se copia a evidencias\mail. Sin red.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA081*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$perfil = Join-Path $dir 'perfil'
New-Item -ItemType Directory -Force -Path $perfil | Out-Null
1..20 | ForEach-Object {
    $eml = Join-Path $perfil ("msg_$_.eml")
    @(
        "From: remitente$_@tfg.local",
        "To: angel@tfg.local",
        "Subject: TFG mail $_",
        "Date: Mon, 09 Nov 2026 12:00:00 +0000",
        "",
        "Cuerpo del mensaje $_"
    ) | Set-Content -Path $eml -Encoding ascii
}
$pst = Join-Path $perfil 'outlook.pst'
[IO.File]::WriteAllBytes($pst, [Text.Encoding]::ASCII.GetBytes('TFG-PST-SINTETICO-' + ('P' * 256)))
$mail = Join-Path $ev 'mail'
New-Item -ItemType Directory -Force -Path $mail | Out-Null
$files = Get-ChildItem $perfil -File
if ($files.Count -gt 200) { Write-Error 'GUARDARRAIL: demasiados ficheros'; exit 2 }
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$files | Copy-Item -Destination $mail -Force
$inv = Join-Path $ev 'mail.csv'
$files | ForEach-Object { "{0}|{1}|{2}" -f $_.Name, $_.Length, (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower() } | Set-Content -Path $inv -Encoding ascii
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@(
    "ata=ATA081", "tecnica=T1114.001", "fuente=ART_adaptado",
    "guid=3f1b5096-0139-4736-9b78-19bcb02bb1cb",
    "t0=$t0", "t1=$t1", "eml=20", "pst=1",
    "copiados=$($files.Count)", "inventario=$inv"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
