$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA062*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'; New-Item -ItemType Directory -Force -Path $ev | Out-Null
$datos = Join-Path $dir 'datos'; New-Item -ItemType Directory -Force -Path $datos | Out-Null
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$files = @()
1..5 | ForEach-Object {
    $p = Join-Path $datos ("toy_$_.txt")
    Set-Content -Path $p -Value ("TFG toy file $_ " + ('A' * 128)) -Encoding ascii
    $files += $p
}
$antes = @()
foreach ($f in $files) { $antes += ("{0}={1}" -f (Split-Path -Leaf $f), (Get-FileHash $f -Algorithm SHA256).Hash.ToLower()) }
$sobrescritos = 0; $borrados = 0
foreach ($f in $files) {
    $len = (Get-Item $f).Length
    [System.IO.File]::WriteAllBytes($f, [byte[]]::new($len))
    $sobrescritos++
    Remove-Item $f -Force
    if (-not (Test-Path $f)) { $borrados++ }
}
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$existe = @($files | Where-Object { Test-Path $_ }).Count
$salida = @(
    "ata=ATA062", "tecnica=T1485", "fuente=ART_adaptado",
    "guid=476419b5-aebf-4366-a131-ae3e8dae5fc2",
    "t0=$t0", "t1=$t1", "ficheros=5",
    "sobrescritos=$sobrescritos", "borrados=$borrados", "existe_after=$existe"
)
$salida + ($antes | ForEach-Object { "sha256_antes_$_" }) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
