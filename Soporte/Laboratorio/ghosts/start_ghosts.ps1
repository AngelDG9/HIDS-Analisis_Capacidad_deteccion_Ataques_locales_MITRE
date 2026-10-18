# start_ghosts.ps1 — arranca el servidor GHOSTS en el HOST (bloque L0)
#
# Levanta la "pila" GHOSTS fuera de las VMs medidas:
#   1) PostgreSQL 16 portable (escucha SOLO en 127.0.0.1:5432)
#   2) GHOSTS API (.NET 8) en 192.168.65.1:5000
#
# Ruta del material: D:\TFG-VMs\material-ghosts (fuera del repo). Sin secretos.
# Uso (HOST, PowerShell):
#   powershell -ExecutionPolicy Bypass -File Soporte\Laboratorio\ghosts\start_ghosts.ps1

$ErrorActionPreference = "Stop"

$PgRoot  = "D:\TFG-VMs\material-ghosts\pgsql"
$PgData  = "D:\TFG-VMs\material-ghosts\pgdata"
$ApiDir  = "D:\TFG-VMs\material-ghosts\api"
$LogDir  = "D:\TFG-VMs\material-ghosts\logs"
$ApiBind = "192.168.65.1:5000"
# Cadena SOLO para localhost. PostgreSQL se inicializo con `initdb -A trust` (autenticacion
# local sin contrasena); por eso la cadena NO lleva credencial (no es un secreto).
$DbConn  = "Host=127.0.0.1;Port=5432;Database=ghosts;User Id=ghosts;"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# --- 1) PostgreSQL ---------------------------------------------------------
$pgCtl = Join-Path $PgRoot "bin\pg_ctl.exe"
& (Join-Path $PgRoot "bin\pg_isready.exe") -h 127.0.0.1 -p 5432 *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Arrancando PostgreSQL..."
    & $pgCtl -D $PgData -l (Join-Path $LogDir "postgres.log") -o "-c listen_addresses=127.0.0.1 -p 5432" start
    Start-Sleep -Seconds 3
} else {
    Write-Host "PostgreSQL ya estaba en marcha."
}

# --- 2) GHOSTS API ---------------------------------------------------------
$env:ASPNETCORE_URLS = "http://$ApiBind"
$env:ConnectionStrings__DefaultConnection = $DbConn
$env:ASPNETCORE_ENVIRONMENT = "Production"
# El cliente sella sus reportes con fecha en formato en-US ("MM/dd/yyyy h:mm:ss tt");
# QueueSyncService usa Convert.ToDateTime con la cultura del SO (es-ES en el host) y
# fallaria. Con globalizacion invariante se parsea ese formato correctamente.
$env:DOTNET_SYSTEM_GLOBALIZATION_INVARIANT = "1"

Write-Host "Arrancando GHOSTS API en http://$ApiBind ..."
Start-Process -FilePath "dotnet" -ArgumentList "ghosts.api.dll" -WorkingDirectory $ApiDir `
    -RedirectStandardOutput (Join-Path $LogDir "ghosts-api.out.log") `
    -RedirectStandardError  (Join-Path $LogDir "ghosts-api.err.log") -WindowStyle Hidden

Start-Sleep -Seconds 8
try {
    $r = Invoke-WebRequest -Uri "http://$ApiBind/api/machines?q=" -UseBasicParsing -TimeoutSec 10
    Write-Host "API OK: HTTP $($r.StatusCode)"
} catch {
    Write-Host "AVISO: la API no respondio: $($_.Exception.Message)"
}
