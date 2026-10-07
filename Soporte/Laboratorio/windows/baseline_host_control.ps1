# ============================================================================
# TFG · HIDS — Control del host para el baseline Windows (fase-02b-baseline)
# ============================================================================
# Encendido/apagado programado de las VMs con `vmrun` (local, sin -h).
# Se invoca desde el Programador de tareas de Windows (4 disparos, ver plan).
# NO contiene secretos. Log → %TEMP%\opencode\baseline_host_control.log (UTC).
#
# Fases:
#   night-start      : revert víctima a lab-listo-windows-baseline + start víctima + start manager
#   night-stop       : stop víctima (soft). El manager SIGUE encendido (§1.3 del plan).
#   afternoon-start  : revert víctima + start víctima (manager ya encendido; start idempotente)
#   afternoon-stop   : stop víctima (soft) + stop manager (soft)
#
# Uso:
#   powershell -NoProfile -ExecutionPolicy Bypass -File baseline_host_control.ps1 -Phase night-start
# ============================================================================
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('night-start','night-stop','afternoon-start','afternoon-stop')]
  [string]$Phase
)

$ErrorActionPreference = 'Continue'

$Vmrun   = 'C:\Program Files\VMware\VMware Workstation\vmrun.exe'
$Victim  = 'D:\TFG-VMs\victima-windows\victima-windows.vmx'
$Manager = 'D:\TFG-VMs\wazuh-server\wazuh-server.vmx'
$Snap    = 'lab-listo-windows-baseline'

$LogDir = Join-Path $env:TEMP 'opencode'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }
$Log = Join-Path $LogDir 'baseline_host_control.log'

function TsUtc { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }

function Write-Log([string]$msg) {
  $line = "[$((TsUtc))] [$Phase] $msg"
  Add-Content -Path $Log -Value $line -Encoding utf8
  Write-Output $line
}

function Invoke-Vmrun([string[]]$vmArgs) {
  Write-Log ("run: vmrun " + ($vmArgs -join ' '))
  try {
    $out = & $Vmrun @vmArgs 2>&1
    $code = $LASTEXITCODE
  } catch {
    $out = $_.Exception.Message
    $code = -1
  }
  Write-Log ("rc=$code out=" + (($out | Out-String).Trim()))
  return $code
}

if (-not (Test-Path $Vmrun)) { Write-Log "ERROR: no existe vmrun en $Vmrun"; exit 10 }

Write-Log "=== START fase=$Phase (host UTC $(TsUtc)) ==="

switch ($Phase) {

  'night-start' {
    Invoke-Vmrun @('-T','ws','revertToSnapshot',$Victim,$Snap) | Out-Null
    Invoke-Vmrun @('-T','ws','start',$Victim,'nogui')               | Out-Null
    Invoke-Vmrun @('-T','ws','start',$Manager,'nogui')              | Out-Null
  }

  'night-stop' {
    # §1.3 del plan: el manager permanece encendido entre las dos ventanas.
    Invoke-Vmrun @('-T','ws','stop',$Victim,'soft') | Out-Null
  }

  'afternoon-start' {
    Invoke-Vmrun @('-T','ws','revertToSnapshot',$Victim,$Snap) | Out-Null
    Invoke-Vmrun @('-T','ws','start',$Victim,'nogui')               | Out-Null
    # manager debe seguir encendido; `start` es idempotente (si ya corre, devuelve error inocuo)
    Invoke-Vmrun @('-T','ws','start',$Manager,'nogui')              | Out-Null
  }

  'afternoon-stop' {
    Invoke-Vmrun @('-T','ws','stop',$Victim,'soft')  | Out-Null
    Invoke-Vmrun @('-T','ws','stop',$Manager,'soft') | Out-Null
  }
}

Write-Log "=== END fase=$Phase ==="
exit 0
