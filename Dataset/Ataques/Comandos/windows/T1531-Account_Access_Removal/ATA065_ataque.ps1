$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA065*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'; New-Item -ItemType Directory -Force -Path $ev | Out-Null
$user = 'tfg_toy_1531'
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$err = ''
if (Get-LocalUser -Name $user -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $user -ErrorAction SilentlyContinue }
$creado = $false
try { New-LocalUser -Name $user -NoPassword -AccountNeverExpires -Description 'TFG toy user' -ErrorAction Stop; $creado = $true } catch { $err = $_.Exception.Message }
$antes = [bool](Get-LocalUser -Name $user -ErrorAction SilentlyContinue)
try { Remove-LocalUser -Name $user -ErrorAction Stop } catch { $err = $_.Exception.Message }
$despues = [bool](Get-LocalUser -Name $user -ErrorAction SilentlyContinue)
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$salida = @(
    "ata=ATA065", "tecnica=T1531", "fuente=ART_adaptado",
    "guid=f21a1d7d-a62f-442a-8c3a-2440d43b19e5",
    "t0=$t0", "t1=$t1", "usuario=$user",
    "creado=$creado", "existe_antes=$antes", "existe_despues=$despues", "error=$err"
)
$salida | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
