# stop_ghosts.ps1 — detiene el servidor GHOSTS en el HOST (bloque L0)
#
# Para la GHOSTS API y PostgreSQL. No borra datos.
# Uso (HOST, PowerShell):
#   powershell -ExecutionPolicy Bypass -File Soporte\Laboratorio\ghosts\stop_ghosts.ps1

$ErrorActionPreference = "Continue"

$PgRoot = "D:\TFG-VMs\material-ghosts\pgsql"
$PgData = "D:\TFG-VMs\material-ghosts\pgdata"

# --- 1) GHOSTS API ---------------------------------------------------------
$api = Get-CimInstance Win32_Process -Filter "Name='dotnet.exe'" |
       Where-Object { $_.CommandLine -like "*ghosts.api.dll*" }
foreach ($p in $api) {
    Write-Host "Deteniendo GHOSTS API (PID $($p.ProcessId))..."
    Stop-Process -Id $p.ProcessId -Force
}

# --- 2) PostgreSQL ---------------------------------------------------------
$pgCtl = Join-Path $PgRoot "bin\pg_ctl.exe"
& $pgCtl -D $PgData stop -m fast
Write-Host "PostgreSQL detenido."

# --- 3) Verificacion -------------------------------------------------------
& (Join-Path $PgRoot "bin\pg_isready.exe") -h 127.0.0.1 -p 5432
Write-Host "Fin."
