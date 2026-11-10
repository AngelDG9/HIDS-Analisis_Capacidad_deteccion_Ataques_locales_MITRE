# ============================================================================
# tfg_keepalive_windows.ps1 - guardian del INVITADO (tarea SYSTEM cada 5 min)
# Bloque `windows-legit-prep` (W3). Espejo de `legitimo_72h/guest/tfg_keepalive.sh`.
# ----------------------------------------------------------------------------
# Un ciclo (la tarea lo lanza cada 5 min; NO es un proceso largo):
#   1) LATIDO: una linea TSV en `keepalive.log` + `estado.json`.
#   2) TOPE de `client.out` (20 MB) y de los logs del propio guardian.
#   3) GUARDA DE DISCO: si C: < 500 MB -> alarma, rota logs; si < 300 MB no arranca nada.
#   4) GUARDA DE WINDOWS UPDATE: re-aplica `NoAutoUpdate=1` y, si `wuauserv` esta
#      Running, lo para y lo deja Disabled. (El `wuauserv` se auto-repara; el plan ya
#      lo declara y el control efectivo es politica + aislamiento.)
#   5) ACTIVIDAD: si `armado.flag` existe y `ghosts.exe` no esta vivo, reinicia la
#      actividad con `schtasks /run /tn TFG-WinLegit-Actividad`. NUNCA lanza el
#      cliente directamente (lo lanzaria como SYSTEM y romperia D4/CA-W5).
#      Si la tarea figura "Running" pero el proceso no existe, primero `/end`.
#   6) ROTACION de receta (d1->d2->d3) SOLO si `TFG_MAPA_DIAS` no esta vacio
#      (lo fija `arm` con `--t0`). Fuera de ventana el mapa esta vacio: no rota.
#   7) `win_user`: registra el dueno real de `ghosts.exe` (debe ser angel).
#
# NO contiene secretos. NO escribe fuera de C:\Users\angel\ghosts-client.
# Uso (SYSTEM o a mano): powershell -NoProfile -ExecutionPolicy Bypass -File tfg_keepalive_windows.ps1
# ============================================================================
[CmdletBinding()]
param(
  # Solo prueba en seco: ignora `armado.flag` (no viaja a la ventana).
  [switch]$Force,
  [int]$DiskMinMb = 500,
  [int]$DiskHardMinMb = 300,
  [int]$ClientOutMaxMb = 20,
  [int]$LogMaxMb = 2,
  # Solo prueba en seco: no toca Windows Update (para poder ensayar sin cambiar el host).
  [switch]$SinWu
)

$ErrorActionPreference = 'Continue'

$Dir        = 'C:\Users\angel\ghosts-client'
$CwdBase    = 'C:\Users\angel'
$Log        = Join-Path $Dir 'keepalive.log'
$RecLog     = Join-Path $Dir 'recovery.log'
$Estado     = Join-Path $Dir 'estado.json'
$FlagArmado = Join-Path $Dir 'armado.flag'
$ClientOut  = Join-Path $Dir 'client.out'
$Bloques    = Join-Path $Dir 'recetas\bloques_windows.env'
$TareaAct   = 'TFG-WinLegit-Actividad'

function TsUtc { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }

function KLog([string]$msg) {
  $linea = "$(TsUtc)`tkeepalive`t$msg"
  try { Add-Content -Path $Log -Value $linea -Encoding utf8 } catch { }
}

function RLog([string]$tipo, [string]$msg) {
  $linea = "$(TsUtc)`t$tipo`t$msg"
  try { Add-Content -Path $RecLog -Value $linea -Encoding utf8 } catch { }
  KLog "$tipo $msg"
}

function Rotar([string]$Path, [int]$MaxMb) {
  try {
    if (-not (Test-Path $Path)) { return $false }
    $mb = (Get-Item $Path).Length / 1MB
    if ($mb -lt $MaxMb) { return $false }
    $dest = "$Path.1"
    if (Test-Path $dest) { Remove-Item $dest -Force -ErrorAction SilentlyContinue }
    Move-Item -LiteralPath $Path -Destination $dest -Force -ErrorAction SilentlyContinue
    # Un fichero abierto por el cliente no se puede mover: se informa de lo que paso.
    return (-not (Test-Path $Path))
  } catch { return $false }
}

function Get-TamMb([string]$Path) {
  try { if (Test-Path $Path) { return [math]::Round((Get-Item $Path).Length / 1MB, 2) } } catch { }
  return 0
}

function Get-DuenoProceso([string]$Nombre) {
  try {
    $p = Get-CimInstance Win32_Process -Filter "Name='$Nombre'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $p) { return '' }
    $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue
    if ($o -and $o.User) { return ("{0}\{1}" -f $o.Domain, $o.User) }
  } catch { }
  return ''
}

# --- 0) preparacion ---------------------------------------------------------
if (-not (Test-Path $Dir)) {
  # Sin cliente desplegado no hay nada que guardar (y no se crea nada).
  exit 0
}
New-Item -ItemType Directory -Force -Path (Join-Path $Dir 'logs') | Out-Null
if (-not (Test-Path $Log)) { New-Item -ItemType File -Force -Path $Log | Out-Null }
if (-not (Test-Path $RecLog)) { New-Item -ItemType File -Force -Path $RecLog | Out-Null }

# El cwd del guardian es el del usuario (no el del cliente): espejo de CA-05.
try { Set-Location $CwdBase } catch { Set-Location $Dir }

$rotKa = Rotar $Log $LogMaxMb
$rotRec = Rotar $RecLog $LogMaxMb
if ($rotKa -or $rotRec) { KLog "rotacion_logs ka=$rotKa rec=$rotRec" }

# --- 1) disco ---------------------------------------------------------------
$freeMb = 0
try { $freeMb = [math]::Round((Get-PSDrive C).Free / 1MB) } catch { $freeMb = -1 }
$puedeArrancar = $true
if ($freeMb -ge 0 -and $freeMb -lt $DiskMinMb) {
  RLog 'alarma_disco' "free_mb=$freeMb min_mb=$DiskMinMb"
  # Alivio: rota lo grande (client.out y logs del cliente) antes de rendirse.
  if (Rotar $ClientOut 1) { RLog 'rotacion' 'client_out_por_disco' }
  foreach ($f in @('app.log', 'clientupdates.log')) {
    $p = Join-Path $Dir "logs\$f"
    if (Rotar $p 1) { RLog 'rotacion' "log_por_disco=$f" }
  }
  try { $freeMb = [math]::Round((Get-PSDrive C).Free / 1MB) } catch { }
  if ($freeMb -lt $DiskHardMinMb) {
    $puedeArrancar = $false
    RLog 'alarma_disco' "sin_arranque free_mb=$freeMb hard_min_mb=$DiskHardMinMb"
  }
}

# --- 2) Windows Update ------------------------------------------------------
$wuSvc = ''
$wuPol = ''
if (-not $SinWu) {
  try {
    $au = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
    if ($null -eq $au -or $au.NoAutoUpdate -ne 1) {
      New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Force | Out-Null
      Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 1 -Type DWord
      Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name AUOptions -Value 1 -Type DWord
      Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoRebootWithLoggedOnUsers -Value 1 -Type DWord
      RLog 'wu' 'politica_re_aplicada NoAutoUpdate=1'
    }
    $wuPol = [string]$au.NoAutoUpdate
  } catch { RLog 'alarma_wu' "politica: $($_.Exception.Message)" }

  try {
    $svc = Get-Service -Name wuauserv -ErrorAction Stop
    if ($svc.Status -eq 'Running') {
      Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
      RLog 'wu' 'wuauserv_parado'
      $svc.Refresh()
    }
    if ($svc.StartType -ne 'Disabled') {
      Set-Service -Name wuauserv -StartupType Disabled -ErrorAction SilentlyContinue
      RLog 'wu' "wuauserv_startup_disabled (antes=$($svc.StartType))"
    }
    $wuSvc = [string](Get-Service -Name wuauserv -ErrorAction SilentlyContinue).Status
  } catch { RLog 'alarma_wu' "servicio: $($_.Exception.Message)" }
}

# --- 3) actividad -----------------------------------------------------------
$armado = (Test-Path $FlagArmado) -or $Force
$tarea = $null
try { $tarea = Get-ScheduledTask -TaskName $TareaAct -ErrorAction SilentlyContinue } catch { }
$tareaUser = ''
$tareaLogon = ''
$tareaEstado = ''
if ($tarea) {
  $tareaUser = [string]$tarea.Principal.UserId
  $tareaLogon = [string]$tarea.Principal.LogonType
  $tareaEstado = [string]$tarea.State
}
$userOk = ($tareaUser -match '(?i)(^|\\)angel$')

if ($tarea -and -not $userOk) {
  # Guarda D4: si alguien re-registro la tarea con otro principal, NO se relanza.
  RLog 'alarma' "tarea_principal_no_angel=$tareaUser (no se relanza)"
}

$proc = @(Get-Process -Name ghosts -ErrorAction SilentlyContinue)
$pid1 = if ($proc.Count -gt 0) { $proc[0].Id } else { 0 }
$dueno = if ($proc.Count -gt 0) { Get-DuenoProceso 'ghosts.exe' } else { '' }

# La tarea de actividad va en modo Interactive (IntegrityLevel=Medium): necesita una
# sesion abierta de `angel`. Si no la hay, `schtasks /run` fallaria en silencio.
$haySesion = $true
try {
  $ses = (& query session 2>$null | Out-String)
  $haySesion = ($ses -match '(?im)^\s*>?\S+\s+angel\s+\d+\s+')
} catch { }
if ($armado -and -not $haySesion) {
  RLog 'alarma' 'sin_sesion_angel (la tarea Interactive no puede arrancar)'
  $puedeArrancar = $false
}

if ($armado -and $userOk -and $puedeArrancar) {
  if ($proc.Count -eq 0) {
    if ($tareaEstado -eq 'Running') {
      # La tarea figura viva pero el cliente no: se cierra la instancia huerfana.
      & schtasks /end /tn $TareaAct 2>&1 | Out-Null
      RLog 'end' "tarea_huerfana state=Running pid=0"
      Start-Sleep -Seconds 2
    }
    & schtasks /run /tn $TareaAct 2>&1 | Out-Null
    $rcRun = $LASTEXITCODE
    Start-Sleep -Seconds 8
    $proc = @(Get-Process -Name ghosts -ErrorAction SilentlyContinue)
    if ($proc.Count -gt 0) {
      $pid1 = $proc[0].Id
      $dueno = Get-DuenoProceso 'ghosts.exe'
      RLog 'recuperacion' "pid=$pid1 user=$dueno rc_run=$rcRun"
    } else {
      RLog 'alarma' "no_arranca rc_run=$rcRun state=$tareaEstado"
    }
  }
} elseif (-not $armado) {
  # Sin `armado.flag` no se arranca nada (prep/stop/cleanup). Solo se deja constancia.
  if ($proc.Count -gt 0) { KLog "desarmado_pero_vivo pid=$pid1 user=$dueno" }
}

# --- 4) tope de client.out --------------------------------------------------
$outMb = Get-TamMb $ClientOut
if ($outMb -gt $ClientOutMaxMb) {
  $t = $null
  try { $t = Get-ScheduledTask -TaskName $TareaAct -ErrorAction SilentlyContinue } catch { }
  if ($t -and $t.State -eq 'Running') {
    & schtasks /end /tn $TareaAct 2>&1 | Out-Null
    Start-Sleep -Seconds 2
  }
  $dest = "$ClientOut.1"
  if (Test-Path $dest) { Remove-Item $dest -Force -ErrorAction SilentlyContinue }
  Move-Item -LiteralPath $ClientOut -Destination $dest -Force -ErrorAction SilentlyContinue
  RLog 'rotacion' "client_out_mb=$outMb max_mb=$ClientOutMaxMb"
  if ($armado -and $userOk -and $puedeArrancar) {
    & schtasks /run /tn $TareaAct 2>&1 | Out-Null
    Start-Sleep -Seconds 6
    $proc = @(Get-Process -Name ghosts -ErrorAction SilentlyContinue)
    if ($proc.Count -gt 0) { $pid1 = $proc[0].Id; $dueno = Get-DuenoProceso 'ghosts.exe' }
  }
  $outMb = Get-TamMb $ClientOut
}

# --- 5) rotacion de receta (solo con mapa de dias) --------------------------
$mapa = ''
if (Test-Path $Bloques) {
  $linea = Select-String -Path $Bloques -Pattern '^TFG_MAPA_DIAS=' -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($linea) { $mapa = ($linea.Line -replace '^TFG_MAPA_DIAS=', '').Trim() }
}
$diaK = 0
if ($mapa) {
  $hoy = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
  foreach ($par in $mapa.Split(',')) {
    $kv = $par.Split(':')
    if ($kv.Count -eq 2 -and $kv[0].Trim() -eq $hoy) { $diaK = [int]$kv[1] }
  }
}
if ($diaK -ge 1 -and $diaK -le 3) {
  $origen = Join-Path $Dir "config\timeline.d$diaK.json"
  $activo = Join-Path $Dir 'config\timeline.json'
  if ((Test-Path $origen) -and (Test-Path $activo)) {
    $h1 = (Get-FileHash $origen -Algorithm SHA256).Hash
    $h2 = (Get-FileHash $activo -Algorithm SHA256).Hash
    if ($h1 -ne $h2) {
      $t = $null
      try { $t = Get-ScheduledTask -TaskName $TareaAct -ErrorAction SilentlyContinue } catch { }
      if ($t -and $t.State -eq 'Running') {
        & schtasks /end /tn $TareaAct 2>&1 | Out-Null
        Start-Sleep -Seconds 2
      }
      Copy-Item -LiteralPath $origen -Destination $activo -Force
      RLog 'rotacion_dia' "dia=$diaK origen=timeline.d$diaK.json"
      if ($armado -and $userOk -and $puedeArrancar) {
        & schtasks /run /tn $TareaAct 2>&1 | Out-Null
        Start-Sleep -Seconds 6
        $proc = @(Get-Process -Name ghosts -ErrorAction SilentlyContinue)
        if ($proc.Count -gt 0) { $pid1 = $proc[0].Id; $dueno = Get-DuenoProceso 'ghosts.exe' }
      }
    }
  }
}

# --- 6) latido + estado -----------------------------------------------------
$t = $null
try { $t = Get-ScheduledTask -TaskName $TareaAct -ErrorAction SilentlyContinue } catch { }
if ($t) {
  $tareaEstado = [string]$t.State
  $tareaUser = [string]$t.Principal.UserId
  $tareaLogon = [string]$t.Principal.LogonType
}
$est = [ordered]@{
  ts_utc           = (TsUtc)
  armado           = $armado
  dia_k            = $diaK
  disco_libre_mb   = $freeMb
  wuauserv         = $wuSvc
  wu_noautoupdate  = $wuPol
  tarea            = $TareaAct
  tarea_estado     = $tareaEstado
  tarea_user       = $tareaUser
  tarea_logon      = $tareaLogon
  cliente_vivo     = ($proc.Count -gt 0)
  cliente_pid      = $pid1
  win_user         = $dueno
  client_out_mb    = $outMb
}
try { ($est | ConvertTo-Json -Compress) | Set-Content -Path $Estado -Encoding utf8 } catch { }

KLog ("latido armado=$armado dia_k=$diaK disco_mb=$freeMb wu=$wuSvc/$wuPol tarea=$tareaEstado user=$tareaUser vivo=$($proc.Count -gt 0) pid=$pid1 win_user=$dueno out_mb=$outMb")
exit 0
