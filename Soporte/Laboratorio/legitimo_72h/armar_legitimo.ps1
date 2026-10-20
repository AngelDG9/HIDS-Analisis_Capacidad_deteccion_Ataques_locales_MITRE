# ============================================================================
# armar_legitimo.ps1 — arma el bloque L1 (tarea del invitado + cliente + checklist).
# Delega en legitimo_host_control.ps1 -Phase arm.
# Uso: powershell -NoProfile -ExecutionPolicy Bypass -File armar_legitimo.ps1
# Credenciales: TFG_GUEST_PW / TFG_MANAGER_PW (entorno; nunca en fichero).
# ============================================================================
[CmdletBinding()]
param()
$Base = Split-Path -Parent $MyInvocation.MyCommand.Path
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Base 'legitimo_host_control.ps1') -Phase arm
exit $LASTEXITCODE
