# ATA080 - T1213.006 Data from Information Repositories: Databases (Windows)
# Manual: el clon ART 388942ad no trae T1213.006. Se implementa sqlite3 .dump.
# sqlite3.exe pre-staged fuera del repo en C:\tfg-tools\sqlite3\sqlite3.exe.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA080*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$sqlite = 'C:\tfg-tools\sqlite3\sqlite3.exe'
if (-not (Test-Path $sqlite)) { 'GUARDARRAIL: sqlite3.exe no pre-staged' | Out-File (Join-Path $ev 'efecto_local.txt') -Encoding ascii; exit 2 }
$db = Join-Path $dir 'datos.db'
if (Test-Path $db) { Remove-Item $db -Force }
$sql = Join-Path $dir 'crear.sql'
$lines = @('CREATE TABLE clientes (id INTEGER PRIMARY KEY, nombre TEXT, email TEXT, saldo REAL);')
1..20 | ForEach-Object { $lines += "INSERT INTO clientes (nombre,email,saldo) VALUES ('cliente_$_','c$_@tfg.local',$($_ * 10));" }
$lines | Set-Content -Path $sql -Encoding ascii
& $sqlite $db ".read $sql" | Out-Null
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$dump = Join-Path $dir 'dump.sql'
& $sqlite $db ".dump" | Set-Content -Path $dump -Encoding ascii
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$filas = (& $sqlite $db "SELECT COUNT(*) FROM clientes;" | Out-String).Trim()
$sha = (Get-FileHash $dump -Algorithm SHA256).Hash.ToLower()
@(
    "ata=ATA080", "tecnica=T1213.006", "fuente=manual",
    "t0=$t0", "t1=$t1", "db=$db", "dump=$dump",
    "filas=$filas", "sha256=$sha"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
