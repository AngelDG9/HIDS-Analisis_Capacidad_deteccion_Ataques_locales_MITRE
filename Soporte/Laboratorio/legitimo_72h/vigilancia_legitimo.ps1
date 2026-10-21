# ============================================================================
# vigilancia_legitimo.ps1 — vigilancia pasiva durante [t0,t1] (patrón L1).
# NO toca la víctima: solo consulta la API de GHOSTS (host) y el manager (SSH lectura).
# Delega en legitimo_host_control.ps1 -Phase watch (una sola implementación).
# Uso: powershell -NoProfile -ExecutionPolicy Bypass -File vigilancia_legitimo.ps1
# ============================================================================
[CmdletBinding()]
param(
  [string]$T0 = '2026-10-19T00:00:00Z',
  [string]$T1 = '2026-10-22T00:00:00Z'
)
$Base = Split-Path -Parent $MyInvocation.MyCommand.Path
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Base 'legitimo_host_control.ps1') -Phase watch -T0 $T0 -T1 $T1
exit $LASTEXITCODE
