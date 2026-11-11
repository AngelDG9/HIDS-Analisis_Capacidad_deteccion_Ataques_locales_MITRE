# ============================================================================
# heartbeat_sink_ctl.ps1 - arranca / para el sink del latido desde el HOST
# Bloque `windows-legit-prep` (W3-bis, T2a). NO va en la VM.
# ----------------------------------------------------------------------------
#   start  : comprueba que 192.168.65.1:9095 esta libre, arranca
#            `heartbeat_sink.py` y deja constancia (pid + log). Si el puerto esta
#            ocupado NO hace fallback: sale con 48.
#   stop   : para el proceso del pid registrado y lo deja en el log.
#   status : dice si el puerto responde (GET /health) y si el pid vive.
#
# Sin secretos. Uso (HOST):
#   powershell -NoProfile -ExecutionPolicy Bypass -File Soporte\Laboratorio\windows\legit\heartbeat_sink_ctl.ps1 -Action start
# ============================================================================
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('start', 'stop', 'status')]
  [string]$Action,
  [string]$Bind = '192.168.65.1',
  [int]$Port = 9095,
  [string]$Python = 'python',
  [string]$OutDir = ''
)

$ErrorActionPreference = 'Continue'

$Win  = Split-Path -Parent $PSScriptRoot  # ...\windows
$Legit = $PSScriptRoot                     # ...\windows\legit
$Sink = Join-Path $Legit 'heartbeat_sink.py'
# G-4 (T2b-1b): MISMO `OutDir` por defecto que `windows_legit_host_control.ps1`
# (`legit/evidencia`). Antes era `evidencia/t2a` y el `watch` leia otro fichero.
if (-not $OutDir) { $OutDir = Join-Path $Legit 'evidencia' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$Out  = Join-Path $OutDir 'heartbeat.jsonl'
$Log  = Join-Path $OutDir 'heartbeat_sink.log'
$Ctl  = Join-Path $OutDir 'heartbeat_sink_ctl.log'
$PidF = Join-Path $OutDir 'heartbeat_sink.pid'
$StdO = Join-Path $OutDir 'heartbeat_sink.stdout.log'
$StdE = Join-Path $OutDir 'heartbeat_sink.stderr.log'
$StdI = Join-Path $OutDir 'heartbeat_sink.stdin.log'

function Ts { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
function CLog([string]$m) {
  $linea = "[$(Ts)] [$Action] $m"
  Add-Content -Path $Ctl -Value $linea -Encoding utf8
  Write-Output $linea
}

function Test-Puerto([string]$Ip, [int]$P) {
  $c = New-Object System.Net.Sockets.TcpClient
  try {
    $iar = $c.BeginConnect($Ip, $P, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne(800)) { return $false }
    $c.EndConnect($iar)
    return $true
  } catch { return $false } finally { $c.Close() }
}

function Get-PidSink {
  if (-not (Test-Path $PidF)) { return 0 }
  try { return [int]((Get-Content -LiteralPath $PidF -Raw).Trim()) } catch { return 0 }
}

switch ($Action) {

  'start' {
    if (Test-Puerto $Bind $Port) {
      CLog "PUERTO_OCUPADO $Bind`:$Port -> exit 48 (no se hace fallback)"
      exit 48
    }
    if (-not (Test-Path $Sink)) { CLog "FALTA $Sink"; exit 2 }
    # stdin a un fichero vacio: si el ctl se invoca dentro de una tuberia, el hijo NO
    # debe heredar el pipe (colgaria al padre esperando EOF). T2b-1b.
    if (-not (Test-Path $StdI)) { New-Item -ItemType File -Force -Path $StdI | Out-Null }
    $arg = @($Sink, '--bind', $Bind, '--port', [string]$Port, '--out', $Out, '--log', $Log)
    $p = Start-Process -FilePath $Python -ArgumentList $arg -PassThru -WindowStyle Hidden `
      -RedirectStandardInput $StdI `
      -RedirectStandardOutput $StdO -RedirectStandardError $StdE
    Set-Content -Path $PidF -Value ([string]$p.Id) -Encoding ascii
    Start-Sleep -Milliseconds 1200
    if ($p.HasExited) {
      CLog "FALLO el sink salio rc=$($p.ExitCode) (ver $StdE)"
      exit ([int]$p.ExitCode)
    }
    if (-not (Test-Puerto $Bind $Port)) {
      CLog "FALLO el sink no responde en $Bind`:$Port (pid=$($p.Id))"
      exit 3
    }
    CLog "SINK_ARRANCADO pid=$($p.Id) bind=$Bind port=$Port out=$Out"
    exit 0
  }

  'stop' {
    $spid = Get-PidSink
    if ($spid -le 0) { CLog 'SINK_NO_ARRANCADO (sin pid)'; exit 0 }
    $proc = Get-Process -Id $spid -ErrorAction SilentlyContinue
    if (-not $proc) { CLog "SINK_YA_PARADO pid=$spid"; Remove-Item $PidF -Force -ErrorAction SilentlyContinue; exit 0 }
    Stop-Process -Id $spid -Force -ErrorAction SilentlyContinue
    $t = 0
    while ((Test-Puerto $Bind $Port) -and $t -lt 10) { Start-Sleep -Milliseconds 300; $t++ }
    if (Test-Puerto $Bind $Port) { CLog "SINK_PUERTO_SIGUE_OCUPADO pid=$spid"; exit 4 }
    Remove-Item $PidF -Force -ErrorAction SilentlyContinue
    CLog "SINK_PARADO pid=$spid"
    exit 0
  }

  'status' {
    $spid = Get-PidSink
    $vivo = [bool](Get-Process -Id $spid -ErrorAction SilentlyContinue)
    $responde = Test-Puerto $Bind $Port
    CLog "SINK_PID=$spid VIVO=$vivo RESPONDE=$responde"
    if ($responde) { exit 0 } else { exit 1 }
  }
}
