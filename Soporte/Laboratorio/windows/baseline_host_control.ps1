# ============================================================================
# TFG · HIDS — Control del host para el baseline Windows (fase-02b-baseline)
# ============================================================================
# Encendido/apagado programado de las VMs con `vmrun` (local, sin -h).
# Se invoca desde el Programador de tareas de Windows (4 disparos, ver plan).
# NO contiene secretos. Log → %TEMP%\opencode\baseline_host_control.log (UTC).
#
# Fases:
#   night-start      : revert víctima a lab-listo-windows-baseline + start víctima + start manager
#                      + CHEQUEO de suspensión del invitado (STANDBYIDLE, solo lectura)
#   night-stop       : stop víctima (soft). El manager SIGUE encendido (§1.3 del plan).
#   afternoon-start  : revert víctima + start víctima (manager ya encendido; start idempotente)
#                      + CHEQUEO de suspensión del invitado (STANDBYIDLE, solo lectura)
#   afternoon-stop   : stop víctima (soft) + stop manager (soft)
#
# Chequeo de suspensión (fase *-start, ANTES de t0): tras arrancar la víctima se consulta
# `powercfg /q SCHEME_CURRENT SUB_SLEEP STANDBYIDLE` EN EL INVITADO (solo lectura) y el
# resultado se registra en el log del host + en %TEMP%\opencode\sleepcheck_guest_<fase>.txt.
# El valor esperado es 0x0 (nunca suspender). Es la salvaguarda pedida tras la ventana de
# noche fallida del 2026-10-07 (suspensión del invitado a los 30 min).
#
# Credenciales de VMware Tools: se leen de variables de ENTORNO (NUNCA del fichero, NUNCA al log):
#   TFG_GUEST_USER (por defecto 'angel') · TFG_GUEST_PW (obligatoria para el chequeo).
#   Si TFG_GUEST_PW no está definida, el chequeo se OMITE (se anota) sin abortar la ventana.
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

# Credenciales del invitado SOLO por entorno (sin secretos en el fichero ni en el log).
$GuestUser = if ($env:TFG_GUEST_USER) { $env:TFG_GUEST_USER } else { 'angel' }
$GuestPw   = $env:TFG_GUEST_PW

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

# Ejecuta una operación de invitado con -gu/-gp SIN registrar la contraseña en el log.
function Invoke-VmrunGuest([string[]]$guestArgs) {
  $full = @('-T','ws','-gu',$GuestUser,'-gp',$GuestPw) + $guestArgs
  $safe = @('-T','ws','-gu',$GuestUser,'-gp','***')    + $guestArgs
  Write-Log ("run: vmrun " + ($safe -join ' '))
  try {
    $out = & $Vmrun @full 2>&1
    $code = $LASTEXITCODE
  } catch {
    $out = $_.Exception.Message
    $code = -1
  }
  Write-Log ("rc=$code out=" + (($out | Out-String).Trim()))
  return $code
}

# Chequeo de SOLO LECTURA de que el sueño del invitado está desactivado (STANDBYIDLE = 0x0).
# Ocurre en las fases *-start, DESPUÉS de arrancar la víctima y ANTES de t0 (§ permitido).
function Test-GuestSleep([string]$when) {
  if (-not $GuestPw) {
    Write-Log "SLEEPCHECK($when) OMITIDO: falta la variable de entorno TFG_GUEST_PW"
    return
  }
  $guestTxt = 'C:\Windows\Temp\tfg_sleepcheck.txt'
  $hostTxt  = Join-Path $LogDir ('sleepcheck_guest_' + $Phase + '.txt')
  Remove-Item $hostTxt -Force -ErrorAction SilentlyContinue
  $inner    = "powercfg /q SCHEME_CURRENT SUB_SLEEP STANDBYIDLE | Out-File -Encoding ascii $guestTxt"
  $ok = $false
  for ($try = 1; $try -le 12; $try++) {
    $st = & $Vmrun -T ws checkToolsState $Victim 2>&1
    if ("$st" -match 'running') {
      Invoke-VmrunGuest @('runProgramInGuest',$Victim,'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe','-NoProfile','-Command',$inner) | Out-Null
      Invoke-VmrunGuest @('copyFileFromGuestToHost',$Victim,$guestTxt,$hostTxt) | Out-Null
      if ((Test-Path $hostTxt) -and (Select-String -Path $hostTxt -Pattern 'STANDBYIDLE' -Quiet -ErrorAction SilentlyContinue)) { $ok = $true; break }
    }
    Start-Sleep -Seconds 15
  }
  if (-not $ok) { Write-Log "SLEEPCHECK($when) FALLO: no se pudo leer STANDBYIDLE del invitado (evidencia: $hostTxt)"; return }
  $ac = ''; $dc = ''
  foreach ($ln in (Get-Content $hostTxt)) {
    if ($ln -match 'Current AC Power Setting Index:\s*(0x[0-9a-fA-F]+)') { $ac = $Matches[1] }
    if ($ln -match 'Current DC Power Setting Index:\s*(0x[0-9a-fA-F]+)') { $dc = $Matches[1] }
  }
  $verdict = if ($ac -eq '0x00000000' -and $dc -eq '0x00000000') { 'OK' } else { 'REVISAR' }
  Write-Log "SLEEPCHECK($when) STANDBYIDLE AC=$ac DC=$dc => $verdict (evidencia: $hostTxt)"
}

if (-not (Test-Path $Vmrun)) { Write-Log "ERROR: no existe vmrun en $Vmrun"; exit 10 }

Write-Log "=== START fase=$Phase (host UTC $(TsUtc)) ==="

switch ($Phase) {

  'night-start' {
    Invoke-Vmrun @('-T','ws','revertToSnapshot',$Victim,$Snap) | Out-Null
    Invoke-Vmrun @('-T','ws','start',$Victim,'nogui')               | Out-Null
    Invoke-Vmrun @('-T','ws','start',$Manager,'nogui')              | Out-Null
    Test-GuestSleep 'night-start'
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
    Test-GuestSleep 'afternoon-start'
  }

  'afternoon-stop' {
    Invoke-Vmrun @('-T','ws','stop',$Victim,'soft')  | Out-Null
    Invoke-Vmrun @('-T','ws','stop',$Manager,'soft') | Out-Null
  }
}

Write-Log "=== END fase=$Phase ==="
exit 0
