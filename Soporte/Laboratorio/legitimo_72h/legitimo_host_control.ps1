# ============================================================================
# TFG · HIDS — Control del host para la captura de 72 h de actividad legítima
# Bloque `legitimo-72h` (L1). Ventana: t0=2026-10-19T00:00:00Z → t1=2026-10-22T00:00:00Z
# ----------------------------------------------------------------------------
# Se invoca desde el Programador de tareas de Windows (patrón del baseline) o a mano.
# NO contiene secretos: las contraseñas de las VMs se leen de VARIABLES DE ENTORNO
#   TFG_GUEST_PW   -> contraseña de `victima-linux` (usuario angel)
#   TFG_MANAGER_PW -> contraseña de `wazuh-server`  (si no está, se usa TFG_GUEST_PW)
# y se pasan por STDIN a los scripts remotos (nunca a fichero, nunca al log).
#
# Fases:
#   prep     : revert víctima a `lab-listo-legit` + start víctima + start manager
#              + arrancar_manager + internet local + GHOSTS + firewall TFG-ghosts-5000
#              + logall_json ON + verificación de aislamiento (desde la víctima)
#              + info de rotación de archives.json + reconciliar máquina GHOSTS
#              + entregar timeline_72h.json + parar el cliente (queda armado)
#   arm      : instala la tarea del invitado (systemd timer `tfg-ghosts-legit`) + arranca
#              el cliente + checklist previa (§4.1-D)
#   watch    : vigilancia pasiva (GHOSTS API + manager), SIN tocar la víctima
#   stop     : stop víctima (soft). El manager SIGUE encendido (para la extracción)
#   drytest  : ensayo general fuera de ventana (timeline dry + contador + rastro Wazuh)
#   cleanup  : parada total y restauración (logall_json OFF, VMs, GHOSTS, internet local)
#   status   : imprime el estado (VMs, API GHOSTS, manager, logall_json)
#
# Uso:
#   $env:TFG_GUEST_PW = '<pw>'    # solo en memoria
#   powershell -NoProfile -ExecutionPolicy Bypass -File legitimo_host_control.ps1 -Phase prep
# ============================================================================
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('prep','arm','watch','stop','drytest','cleanup','status')]
  [string]$Phase,
  [string]$T0 = '2026-10-19T00:00:00Z',
  [string]$T1 = '2026-10-22T00:00:00Z',
  [string]$DryTestSeconds = '150',
  # Vía normal: variables de entorno TFG_GUEST_PW / TFG_MANAGER_PW.
  # Estos parámetros existen para el ensayo a mano; NUNCA se escriben en fichero.
  [string]$GuestPw = $null,
  [string]$ManagerPw = $null
)

$ErrorActionPreference = 'Continue'

# --- Rutas / binarios ------------------------------------------------------
$Repo    = 'D:\TFG\HIDS-Analisis_Capacidad_deteccion_Ataques_locales_MITRE'
$Base    = Join-Path $Repo 'Soporte\Laboratorio\legitimo_72h'
$Ghosts  = Join-Path $Repo 'Soporte\Laboratorio\ghosts'
$Inet    = Join-Path $Repo 'Soporte\Laboratorio\internet_local'
$Guest   = Join-Path $Base 'guest'

$Vmrun   = 'C:\Program Files\VMware\VMware Workstation\vmrun.exe'
$Victim  = 'D:\TFG-VMs\victima-linux\victima-linux.vmx'
$Manager = 'D:\TFG-VMs\wazuh-server\wazuh-server.vmx'
$Snap    = 'lab-listo-legit'

$Ssh = 'C:\Program Files\Git\usr\bin\ssh.exe'
$Scp = 'C:\Program Files\Git\usr\bin\scp.exe'
$Key = Join-Path $env:USERPROFILE '.ssh\id_ed25519_tfg_lab'
$Vic = 'angel@192.168.65.129'
$Man = 'angel@192.168.65.128'
$GuestClient = '/home/angel/ghosts-client'

$ApiBase = 'http://192.168.65.1:5000/api'
$GhostsApiPy = Join-Path $Ghosts 'ghosts_api.py'
$Timeline72  = Join-Path $Base 'timeline_72h.json'
$TimelineDry = Join-Path $Base 'timeline_72h.dry.json'

$LogDir = Join-Path $env:TEMP 'opencode'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }
$Log = Join-Path $Base 'legitimo_host_control.log'
$VigLog = Join-Path $Base 'vigilancia_legitimo.log'

# --- Credenciales SOLO por entorno (nunca del fichero, nunca al log) -------
# Precedencia: parámetro (ensayo a mano) > variable de entorno.
if (-not $GuestPw)   { $GuestPw   = $env:TFG_GUEST_PW }
if (-not $ManagerPw) { $ManagerPw = if ($env:TFG_MANAGER_PW) { $env:TFG_MANAGER_PW } else { $GuestPw } }

function TsUtc { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }

function Write-Log([string]$msg) {
  $line = "[$(TsUtc)] [$Phase] $msg"
  Add-Content -Path $Log -Value $line -Encoding utf8
  Write-Output $line
}

function Invoke-Vmrun([string[]]$vmArgs) {
  try { $out = & $Vmrun @vmArgs 2>&1; $code = $LASTEXITCODE }
  catch { $out = $_.Exception.Message; $code = -1 }
  Write-Log ("vmrun " + ($vmArgs -join ' ') + " -> rc=$code " + ((($out | Out-String).Trim())))
  return $code
}

function Wait-VmSsh([string]$Target, [int]$TimeoutSec = 180) {
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $deadline) {
    & $Ssh -i $Key -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=5 $Target 'true' 2>$null
    if ($LASTEXITCODE -eq 0) { Write-Log "SSH OK -> $Target"; return $true }
    Start-Sleep -Seconds 5
  }
  Write-Log "SSH TIMEOUT -> $Target"
  return $false
}

# Sube un fichero local a /tmp/ del destino.
function Copy-ToVm([string]$Local, [string]$Target) {
  $out = & $Scp -i $Key -o StrictHostKeyChecking=accept-new -o BatchMode=yes $Local "${Target}:/tmp/" 2>&1
  Write-Log "scp $(Split-Path $Local -Leaf) -> $Target rc=$LASTEXITCODE $((($out | Out-String).Trim()))"
}

# Ejecuta un comando remoto; si $Pw, se pasa por STDIN (los scripts lo leen con `read`).
function Invoke-OnVm([string]$Target, [string]$RemoteCmd, [string]$Pw, [switch]$SinLog) {
  if ($Pw) { $out = ($Pw | & $Ssh -i $Key -o StrictHostKeyChecking=accept-new $Target $RemoteCmd 2>&1 | Out-String) }
  else     { $out = (& $Ssh -i $Key -o StrictHostKeyChecking=accept-new $Target $RemoteCmd 2>&1 | Out-String) }
  if (-not $SinLog) { Write-Log ("[$Target] $RemoteCmd`n" + $out.Trim()) }
  return $out
}

function Get-GhostsMachines {
  try { return Invoke-RestMethod -Uri "$ApiBase/machines?q=" -TimeoutSec 10 }
  catch { Write-Log "AVISO: GHOSTS API no responde: $($_.Exception.Message)"; return @() }
}

function Reconciliar-GhostsMachine([string]$Nombre) {
  $all = @(Get-GhostsMachines)
  $mine = @($all | Where-Object { $_.name -eq $Nombre })
  Write-Log ("reconciliar: máquinas '$Nombre' = " + $mine.Count)
  if ($mine.Count -le 1) { return }
  # Conservar la del instance/id.json si se puede leer; si no, la que reportó más tarde.
  $idTxt = Invoke-OnVm $Vic "cat $GuestClient/instance/id.json 2>/dev/null" '' -SinLog
  $m = [regex]::Match([string]$idTxt, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
  $keepId = if ($m.Success) { $m.Value } else { '' }
  $keep = $mine | Where-Object { $_.id -eq $keepId } | Select-Object -First 1
  if (-not $keep) { $keep = $mine | Sort-Object { [datetime]$_.lastReportedUtc } -Descending | Select-Object -First 1 }
  Write-Log ("reconciliar: conservo id=" + $keep.id + " last=" + $keep.lastReportedUtc)
  foreach ($mm in $mine) {
    if ($mm.id -ne $keep.id) {
      try { Invoke-RestMethod -Method Delete -Uri "$ApiBase/machines/$($mm.id)" -TimeoutSec 10 | Out-Null; Write-Log ("reconciliar: borrada id=" + $mm.id) }
      catch { Write-Log ("reconciliar: NO se pudo borrar id=" + $mm.id + " -> " + $_.Exception.Message) }
    }
  }
}

function Ensure-FirewallGhosts {
  $name = 'TFG-ghosts-5000'
  if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5000 -RemoteAddress 192.168.65.0/24 | Out-Null
    Write-Log "firewall: regla $name creada (TCP 5000 desde 192.168.65.0/24)"
  } else { Write-Log "firewall: regla $name ya existe" }
}

function Test-PortOpen([int]$Port, [string]$HostIp = '192.168.65.1') {
  try { $c = New-Object System.Net.Sockets.TcpClient; $c.Connect($HostIp, $Port); $c.Close(); return $true }
  catch { return $false }
}

function Get-TimelineResumen([string]$Path) {
  $tl = Get-Content -Raw $Path | ConvertFrom-Json
  $hs = @($tl.TimeLineHandlers)
  $res = foreach ($h in $hs) { "{0} on={1} off={2} loop={3} eventos={4}" -f $h.HandlerType, $h.UtcTimeOn, $h.UtcTimeOff, $h.Loop, @($h.TimeLineEvents).Count }
  return [pscustomobject]@{ Status = $tl.Status; Handlers = $hs.Count; Resumen = ($res -join ' | ') }
}

# Entrega la timeline por el SERVIDOR (vía del plan). El cliente la persiste en
# `config/timeline.json`; si la recarga en caliente, el cliente muere (bug declarado),
# por eso el mecanismo EFECTIVO es `Set-TimelineEnVictima` con el cliente parado.
function Deliver-Timeline([string]$Path) {
  $r = & python $GhostsApiPy send-timeline victima-linux --timeline $Path 2>&1 | Out-String
  Write-Log "send-timeline $(Split-Path $Path -Leaf) -> $($r.Trim().Substring(0, [Math]::Min(180, $r.Trim().Length)))"
}

# Espera a que la timeline quede PERSISTIDA en config/timeline.json de la víctima.
function Wait-TimelineEnVictima([string]$Patron, [int]$TimeoutSec = 120) {
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $deadline) {
    $n = Invoke-OnVm $Vic "grep -c -- '$Patron' $GuestClient/config/timeline.json 2>/dev/null || true" '' -SinLog
    if (([string]$n).Trim() -match '^\s*[1-9]') { return $true }
    Start-Sleep -Seconds 5
  }
  return $false
}

function Wait-ClientRegistrado([int]$TimeoutSec = 180) {
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $deadline) {
    $r = & python $GhostsApiPy wait victima-linux --timeout 10 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { Write-Log "cliente registrado id=$($r.Trim())"; return ($r.Trim()) }
    Start-Sleep -Seconds 5
  }
  Write-Log "cliente NO registrado en ${TimeoutSec}s"; return ''
}

# --- GHOSTS: BD local (host) para purgar actualizaciones pendientes -------------
$Psql = 'D:\TFG-VMs\material-ghosts\pgsql\bin\psql.exe'

function Get-MachineId([string]$Nombre = 'victima-linux') {
  $m = @(Get-GhostsMachines) | Where-Object { $_.name -eq $Nombre } | Select-Object -First 1
  if ($m) { return [string]$m.id }
  return ''
}

# Borra TODAS las machine_updates de la máquina: evita que un update pendiente
# dispare una RECARGA de la timeline (que en GHOSTS v8.3.1 mata al cliente Linux).
function Clear-PendingUpdates([string]$MachineId) {
  if (-not $MachineId) { return }
  $r = & $Psql -h 127.0.0.1 -p 5432 -U ghosts -d ghosts -t -A -c "delete from machine_updates where machineid = '$MachineId';" 2>&1
  Write-Log "machine_updates borradas para $MachineId -> $((([string]$r) -replace '\s+',' ').Trim())"
}

# Coloca la timeline EN EL DISCO del cliente (mecanismo efectivo y determinista).
# Debe hacerse con el cliente PARADO (si recarga en caliente, el cliente muere:
# bug de GHOSTS v8.3.1 — ThreadInterruptedException no capturada).
function Set-TimelineEnVictima([string]$Path) {
  Copy-ToVm $Path $Vic
  Invoke-OnVm $Vic "cp -f /tmp/$(Split-Path $Path -Leaf) $GuestClient/config/timeline.json" '' -SinLog | Out-Null
  $tv = Invoke-OnVm $Vic "grep -m3 -E 'Status|UtcTimeOn' $GuestClient/config/timeline.json" '' -SinLog
  Write-Log "[timeline en la victima] $((([string]$tv) -replace '\s+',' ').Trim())"
}

# ¿Está vivo el cliente? devuelve la línea de pgrep ('' si no).
function Get-ClientEstado {
  $s = Invoke-OnVm $Vic "pgrep -af ghosts.client.linux | grep -v pgrep | head -1" '' -SinLog
  return ([string]$s).Trim()
}

function Ensure-Client([int]$Espera = 8) {
  $st = Get-ClientEstado
  if (-not $st) {
    Invoke-OnVm $Vic "bash $GuestClient/client_ctl.sh start" '' -SinLog | Out-Null
    Start-Sleep -Seconds $Espera
    $st = Get-ClientEstado
  }
  if ($st) { Write-Log "cliente VIVO: $st"; return $true }
  Write-Log "cliente NO está vivo (revisar ghasts.out)"; return $false
}

# ===========================================================================
# Guarda: las fases que usan `sudo` en las VMs necesitan la contraseña.
if (($Phase -in @('prep','arm','drytest','cleanup')) -and (-not $GuestPw)) {
  Write-Log "ERROR: falta la contraseña de las VMs (TFG_GUEST_PW o parámetro -GuestPw). Abortando fase '$Phase'."
  exit 30
}

switch ($Phase) {

  'prep' {
    Write-Log "=== START prep (host UTC $(TsUtc)) t0=$T0 t1=$T1 ==="

    # 0) validación estática de la timeline (falla ruidosamente si está mal)
    $tr = Get-TimelineResumen $Timeline72
    Write-Log ("timeline_72h.json: Status=" + $tr.Status + " handlers=" + $tr.Handlers + " | " + $tr.Resumen)
    if ($tr.Status -ne 'Run' -or $tr.Handlers -lt 1) { Write-Log 'ERROR: timeline inválida'; exit 20 }

    # 1) revert víctima + start víctima + start manager (el manager NO se revierte)
    Invoke-Vmrun @('-T','ws','revertToSnapshot',$Victim,$Snap) | Out-Null
    Invoke-Vmrun @('-T','ws','start',$Victim,'nogui')          | Out-Null
    Invoke-Vmrun @('-T','ws','start',$Manager,'nogui')         | Out-Null
    Wait-VmSsh $Vic 240 | Out-Null
    Wait-VmSsh $Man 240    | Out-Null

    # 2) manager: (re)arranque e higiene + logall_json ON
    Copy-ToVm (Join-Path $Ghosts 'arrancar_manager.sh') $Man
    Copy-ToVm (Join-Path $Ghosts 'logall_json_ctl.sh')  $Man
    Copy-ToVm (Join-Path $Ghosts 'diag_wazuh.sh')       $Man
    Copy-ToVm (Join-Path $Base  'exportar_denominador.sh') $Man
    Invoke-OnVm $Man 'bash /tmp/arrancar_manager.sh' $ManagerPw | Out-Null
    Invoke-OnVm $Man 'bash /tmp/logall_json_ctl.sh on'  $ManagerPw | Out-Null
    Invoke-OnVm $Man 'bash /tmp/logall_json_ctl.sh status' $ManagerPw | Out-Null
    Invoke-OnVm $Man 'bash /tmp/exportar_denominador.sh info' $ManagerPw | Out-Null
    Invoke-OnVm $Man 'bash /tmp/diag_wazuh.sh' $ManagerPw | Out-Null

    # 3) internet local + GHOSTS servidor + firewall
    #    (sin pipe: los procesos lanzados heredan handles y `| Out-String` nunca cierra)
    if ((Test-PortOpen 8080) -and (Test-PortOpen 9090) -and (Test-PortOpen 9092)) {
      Write-Log "internet local: ya está arriba (8080/9090/9092)"
    } else {
      & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Inet 'start_internet_local.ps1')
      Write-Log "internet local lanzada"
    }
    if (Test-PortOpen 5000) {
      Write-Log "GHOSTS API: ya está arriba (5000)"
    } else {
      & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Ghosts 'start_ghosts.ps1')
      Write-Log "servidor GHOSTS lanzado"
    }
    Ensure-FirewallGhosts

    # 4) víctima: verificación de aislamiento (NAT off, servicios locales)
    Copy-ToVm (Join-Path $Inet 'verificar_internet_local.sh') $Vic
    Invoke-OnVm $Vic 'bash /tmp/verificar_internet_local.sh' $GuestPw | Out-Null

    # 5) cliente + timeline
    Invoke-OnVm $Vic "bash $GuestClient/client_ctl.sh stop"  '' -SinLog | Out-Null
    Invoke-OnVm $Vic "bash $GuestClient/client_ctl.sh start" '' | Out-Null
    Wait-ClientRegistrado 180 | Out-Null
    Reconciliar-GhostsMachine 'victima-linux'
    # 5a) vía del PLAN: entrega por el SERVIDOR (best-effort; puede matar al cliente al recargar)
    Deliver-Timeline $Timeline72
    Start-Sleep -Seconds 30
    # 5b) mecanismo EFECTIVO y determinista: cliente PARADO -> purgar updates pendientes
    #     -> colocar el fichero en disco. Evita la recarga en caliente (que mata al cliente).
    Invoke-OnVm $Vic "bash $GuestClient/client_ctl.sh stop" '' -SinLog | Out-Null
    $mid = Get-MachineId 'victima-linux'
    Clear-PendingUpdates $mid
    Set-TimelineEnVictima $Timeline72
    if (-not (Wait-TimelineEnVictima '12:00:00' 30)) { Write-Log 'ERROR: la timeline de régimen NO quedó colocada'; exit 21 }

    # 6) snapshot original intacto
    Invoke-Vmrun @('-T','ws','listSnapshots',$Victim) | Out-Null

    # 7) parar el cliente: la tarea del invitado lo arrancará en arm / t0-5min
    Invoke-OnVm $Vic "bash $GuestClient/client_ctl.sh stop" '' | Out-Null

    Write-Log "=== END prep ==="
  }

  'arm' {
    Write-Log "=== START arm (host UTC $(TsUtc)) ==="
    # 1) tarea del invitado (systemd timer + servicio + keepalive)
    Copy-ToVm (Join-Path $Guest 'tfg_keepalive.sh')             $Vic
    Copy-ToVm (Join-Path $Guest 'tfg-ghosts-legit.service')     $Vic
    Copy-ToVm (Join-Path $Guest 'tfg-ghosts-legit.timer')       $Vic
    Copy-ToVm (Join-Path $Guest 'instalar_tarea_invitado.sh')   $Vic
    Invoke-OnVm $Vic 'bash /tmp/instalar_tarea_invitado.sh' $GuestPw | Out-Null

    # 2) arrancar el cliente (lee config/timeline.json; sin updates pendientes => estable)
    $mid = Get-MachineId 'victima-linux'
    Clear-PendingUpdates $mid
    Ensure-Client 10 | Out-Null

    # 3) checklist previa (§4.1-D)
    Invoke-OnVm $Man 'bash /tmp/diag_wazuh.sh' $ManagerPw | Out-Null
    Invoke-OnVm $Man 'bash /tmp/logall_json_ctl.sh status' $ManagerPw | Out-Null
    $m = Get-GhostsMachines
    $mine = @($m | Where-Object { $_.name -eq 'victima-linux' })
    Write-Log ("GHOSTS: máquinas victima-linux=" + $mine.Count + " | up=" + (($mine | ForEach-Object { $_.statusUp }) -join ',') + " | last=" + (($mine | ForEach-Object { $_.lastReportedUtc }) -join ','))
    Write-Log ("cliente: " + (Get-ClientEstado))
    Invoke-OnVm $Vic "grep -m2 -E 'Status|UtcTimeOn' $GuestClient/config/timeline.json; ip route" '' | Out-Null
    if (Wait-TimelineEnVictima '12:00:00' 60) { Write-Log "arm: timeline de régimen presente en la víctima" }
    else { Write-Log "AVISO arm: la timeline de régimen NO está en la víctima (revisar)" }
    Invoke-OnVm $Vic 'systemctl list-timers tfg-ghosts-legit.timer --all --no-pager; sleep 1' '' | Out-Null
    Write-Log "=== END arm ==="
  }

  'watch' {
    $now = (Get-Date).ToUniversalTime()
    $t0 = [datetime]::Parse($T0).ToUniversalTime()
    $t1 = [datetime]::Parse($T1).ToUniversalTime()
    $line = "[$(TsUtc)] watch "
    if ($now -lt $t0 -or $now -gt $t1) {
      $line += "FUERA de [t0,t1] -> sin vigilancia"
      Add-Content -Path $VigLog -Value $line -Encoding utf8
      Write-Output $line
      break
    }
    $m = Get-GhostsMachines
    $mine = @($m | Where-Object { $_.name -eq 'victima-linux' })
    $up = ($mine | ForEach-Object { "$($_.statusUp)/$($_.lastReportedUtc)" }) -join ';'
    $line += "ghosts=($($mine.Count)) $up "
    if ($ManagerPw) {
      Copy-ToVm (Join-Path $Base 'estado_manager.sh') $Man
      $mg = Invoke-OnVm $Man 'bash /tmp/estado_manager.sh' $ManagerPw -SinLog
      $line += "| " + (([string]$mg) -replace '\s+', ' ').Trim()
    } else {
      # sin credencial: solo lo que no necesita sudo (la vigilancia nunca se rompe)
      $mg = Invoke-OnVm $Man 'echo "manager=$(systemctl is-active wazuh-manager 2>/dev/null)"; echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"' '' -SinLog
      $line += "| (sin credencial manager) " + (([string]$mg) -replace '\s+', ' ').Trim()
    }
    Add-Content -Path $VigLog -Value $line -Encoding utf8
    Add-Content -Path $Log -Value $line -Encoding utf8
    Write-Output $line
  }

  'stop' {
    Write-Log "=== START stop (host UTC $(TsUtc)) ==="
    Invoke-Vmrun @('-T','ws','stop',$Victim,'soft') | Out-Null
    Write-Log "víctima parada (soft). El manager SIGUE encendido para la extracción."
    Write-Log "=== END stop ==="
  }

  'drytest' {
    Write-Log "=== START drytest (host UTC $(TsUtc)) ==="
    # 0) derivar la timeline de prueba: mismas acciones, ventanas abiertas (siempre activa)
    $tl = Get-Content -Raw $Timeline72 | ConvertFrom-Json
    foreach ($h in $tl.TimeLineHandlers) { $h.UtcTimeOn = '00:00:00'; $h.UtcTimeOff = '00:00:00' }
    $dryText = ($tl | ConvertTo-Json -Depth 12)
    # UTF-8 SIN BOM (el BOM rompería el json.load de ghosts_api.py)
    [System.IO.File]::WriteAllText($TimelineDry, $dryText, (New-Object System.Text.UTF8Encoding($false)))
    $td = Get-TimelineResumen $TimelineDry
    Write-Log ("dry timeline: Status=" + $td.Status + " handlers=" + $td.Handlers + " | " + $td.Resumen)

    # 1) cliente PARADO -> purgar updates -> colocar la timeline dry en disco -> arrancar
    #    (determinista; evita la recarga en caliente que mata al cliente GHOSTS v8.3.1)
    Invoke-OnVm $Vic "bash $GuestClient/client_ctl.sh stop" '' -SinLog | Out-Null
    $mid = Get-MachineId 'victima-linux'
    Clear-PendingUpdates $mid
    Set-TimelineEnVictima $TimelineDry
    Ensure-Client 10 | Out-Null
    Wait-ClientRegistrado 120 | Out-Null
    Reconciliar-GhostsMachine 'victima-linux'

    # 2) T0 del ensayo: contar acciones antes
    $psql = $Psql
    $before = & $psql -h 127.0.0.1 -p 5432 -U ghosts -d ghosts -t -A -c 'select count(*) from history_timeline;' 2>&1
    Write-Log "drytest: acciones ANTES = $before"

    # 3) dejar correr N s
    $secs = [int]$DryTestSeconds
    Write-Log "drytest: esperando $secs s de actividad..."
    Start-Sleep -Seconds $secs
    Write-Log ("drytest: cliente durante la actividad -> " + (Get-ClientEstado))

    # 4) acciones durante el ensayo, por handler
    $dur = & $psql -h 127.0.0.1 -p 5432 -U ghosts -d ghosts -t -A -c "select handler, count(*) from history_timeline where createdutc >= (now() at time zone 'utc') - interval '$([int]($secs/60)+1) minutes' group by handler order by 1;" 2>&1
    Write-Log "drytest: acciones por handler (ultimos min) => $((([string]$dur) -replace '\s+',' ').Trim())"
    $after = & $psql -h 127.0.0.1 -p 5432 -U ghosts -d ghosts -t -A -c 'select count(*) from history_timeline;' 2>&1
    Write-Log "drytest: acciones DESPUES = $after"

    # 5) rastro en Wazuh (manager): marcadores de la actividad + agente 001
    Copy-ToVm (Join-Path $Base 'verificar_rastro.sh') $Man
    Invoke-OnVm $Man 'bash /tmp/verificar_rastro.sh' $ManagerPw | Out-Null

    # 6) restaurar la timeline de régimen (cliente parado) y comprobar que arranca estable
    Invoke-OnVm $Vic "bash $GuestClient/client_ctl.sh stop" '' -SinLog | Out-Null
    Clear-PendingUpdates (Get-MachineId 'victima-linux')
    Set-TimelineEnVictima $Timeline72
    Ensure-Client 10 | Out-Null
    Start-Sleep -Seconds 12
    Write-Log ("drytest: cliente con timeline de régimen (fuera de ventana) -> " + (Get-ClientEstado))
    Invoke-OnVm $Vic "bash $GuestClient/client_ctl.sh stop" '' | Out-Null
    Write-Log "=== END drytest ==="
  }

  'cleanup' {
    Write-Log "=== START cleanup (host UTC $(TsUtc)) ==="
    Invoke-OnVm $Vic "bash $GuestClient/client_ctl.sh stop" '' -SinLog | Out-Null
    Invoke-OnVm $Man 'bash /tmp/logall_json_ctl.sh off' $ManagerPw | Out-Null
    Invoke-OnVm $Man 'bash /tmp/logall_json_ctl.sh status' $ManagerPw | Out-Null
    # restauración verificada: diff de ossec.conf contra la copia previa
    # (`sudo -S` lee la contraseña del STDIN que `Invoke-OnVm` ya está enviando)
    Invoke-OnVm $Man 'sudo -S -p "" diff /var/ossec/etc/ossec.conf.tfg-bak /var/ossec/etc/ossec.conf && echo CONFIG_IDENTICA || echo CONFIG_DIFIERE; sudo -S -p "" ls -l /var/ossec/logs/archives/ 2>/dev/null | tail -3' $ManagerPw | Out-Null
    Invoke-Vmrun @('-T','ws','stop',$Victim,'soft')  | Out-Null
    Invoke-Vmrun @('-T','ws','stop',$Manager,'soft') | Out-Null
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Ghosts 'stop_ghosts.ps1')
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Inet 'stop_internet_local.ps1')
    if (Get-NetFirewallRule -DisplayName 'TFG-ghosts-5000' -ErrorAction SilentlyContinue) {
      Remove-NetFirewallRule -DisplayName 'TFG-ghosts-5000'
      Write-Log "firewall: regla TFG-ghosts-5000 retirada"
    }
    Invoke-Vmrun @('-T','ws','list') | Out-Null
    Write-Log "=== END cleanup ==="
  }

  'status' {
    Invoke-Vmrun @('-T','ws','list') | Out-Null
    $m = Get-GhostsMachines
    Write-Log ("status GHOSTS: " + (@($m | ForEach-Object { "$($_.name)=$($_.statusUp)/$($_.lastReportedUtc)" }) -join '; '))
    Invoke-OnVm $Man 'bash /tmp/logall_json_ctl.sh status' $ManagerPw | Out-Null
  }
}

exit 0
