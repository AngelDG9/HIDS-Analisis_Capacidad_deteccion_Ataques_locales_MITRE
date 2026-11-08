$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA066*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'; New-Item -ItemType Directory -Force -Path $ev | Out-Null
$web = Join-Path $dir 'web'; New-Item -ItemType Directory -Force -Path $web | Out-Null
$idx = Join-Path $web 'index.html'
if (-not (Test-Path $idx)) { Set-Content -Path $idx -Value '<html><body>TFG original</body></html>' -Encoding ascii }
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$antes = (Get-FileHash $idx -Algorithm SHA256).Hash.ToLower()
Set-Content -Path $idx -Value '<html><body><h1>TFG-DEFACED</h1><p>HIDS lab - T1491.001</p></body></html>' -Encoding ascii
$despues = (Get-FileHash $idx -Algorithm SHA256).Hash.ToLower()
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$salida = @(
    "ata=ATA066", "tecnica=T1491.001", "fuente=ART_adaptado",
    "guid=30558d53-9d76-41c4-9267-a7bd5184bed3",
    "t0=$t0", "t1=$t1", "fichero=$idx",
    "sha256_antes=$antes", "sha256_despues=$despues",
    "cambiado=" + [bool]($antes -ne $despues),
    "contiene_deface=" + [bool]((Get-Content $idx -Raw) -match 'TFG-DEFACED')
)
$salida | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
