# ============================================================================
# arrancar_servidor.ps1 - arranca (o comprueba) el servidor de Velociraptor del laboratorio, sin duplicarlo.
#   powershell -NoProfile -ExecutionPolicy Bypass -File arrancar_servidor.ps1 [-Parar] [-Estado]
# Frontend: https://192.168.65.1:8000/ (clientes, red de las VMs)  |  GUI: https://127.0.0.1:8889/ (solo local).
# Requisitos (ya hechos 2026-11-21): regla de entrada `TFG-velociraptor-8000` y SIN reglas de BLOQUEO para velociraptor.exe.
# Sin secretos: la config con las claves vive en D:\TFG-VMs\velociraptor-server\ (fuera del repo). ASCII puro.
# ============================================================================
param([switch]$Parar, [switch]$Estado)
$ErrorActionPreference = 'Stop'
$Dir  = 'D:\TFG-VMs\velociraptor-server'
$Exe  = 'D:\TFG-VMs\material-velociraptor\velociraptor.exe'
$Cfg  = Join-Path $Dir 'server.config.yaml'
$Log  = Join-Path $Dir 'server.log'

function Get-Proc { @(Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'velociraptor.exe' -and $_.CommandLine -match 'frontend' }) }
function Get-Puertos { @(Get-NetTCPConnection -State Listen -LocalPort 8000, 8889 -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort) }

if ($Parar) {
  Get-Proc | ForEach-Object { Stop-Process -Id $_.ProcessId -Force; Write-Output ("parado pid " + $_.ProcessId) }
  exit 0
}
if (-not (Test-Path $Exe)) { Write-Output "ERROR: falta $Exe"; exit 2 }
if (-not (Test-Path $Cfg)) { Write-Output "ERROR: falta $Cfg"; exit 2 }
if (Get-Proc) {
  Write-Output 'servidor YA en marcha'
} elseif (-not $Estado) {
  $esAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $esAdmin) { $env:__COMPAT_LAYER = 'RunAsInvoker' }     # el exe pide elevacion; sin admin se arranca como el usuario
  $p = Start-Process -FilePath $Exe -ArgumentList @('--config', $Cfg, 'frontend', '-v') -WorkingDirectory $Dir -WindowStyle Hidden `
       -RedirectStandardOutput $Log -RedirectStandardError ($Log + '.err') -PassThru
  Write-Output ("arrancado pid " + $p.Id)
  Start-Sleep -Seconds 15
}
$pt = Get-Puertos
Write-Output ("proceso: " + @(Get-Proc).Count + " | puertos: " + (($pt | ForEach-Object { $_.LocalAddress + ':' + $_.LocalPort }) -join ', '))
if (@($pt | Where-Object { $_.LocalPort -eq 8000 }).Count -eq 0) { Write-Output 'AVISO: el frontend (8000) no escucha'; exit 1 }
exit 0
