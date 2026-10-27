# ============================================================================
# TFG - HIDS - Control del host para la captura de 72 h de actividad legitima
# Bloque `legitimo-fix` (L1-fix, v3). La ventana la ejecutara `legitimo-72h-v2`.
# ----------------------------------------------------------------------------
# Se invoca desde el Programador de tareas de Windows o a mano.
# NO contiene secretos: las contrasenas de las VMs se leen de VARIABLES DE ENTORNO
#   TFG_GUEST_PW   -> contrasena de `victima-linux` (usuario angel)
#   TFG_MANAGER_PW -> contrasena de `wazuh-server`  (si no esta, se usa TFG_GUEST_PW)
# y se pasan por STDIN a los scripts remotos (nunca a fichero, nunca al log).
#
# Fases:
#   prep     : G-1..G-12 -> revert victima a `lab-listo-legit-v2` + start + deploy del
#              cliente arreglado + manager + internet local + GHOSTS + logall_json ON
#              + verificar_arreglos + receta d1 (cliente PARADO)
#   arm      : instala la tarea del invitado con T0 (timer t0-5min) + arranca el cliente
#              + checklist
#   watch    : vigilancia de 9 senales (7 en vivo + 2 post-hoc: RAM y recovery.log), 3 niveles, SIN tocar
#              la victima (host + manager)             [cada 30 min en la ventana]
#   stop     : stop victima (soft). El manager SIGUE encendido (extraccion)
#   drytest  : ensayo de la receta comprimida en el invitado (fuera de ventana)
#   cleanup  : parada total y restauracion (logall_json OFF, VMs, GHOSTS, internet local)
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
  [string]$T0 = '2026-10-26T00:00:00Z',
  [string]$T1 = '2026-10-29T00:00:00Z',
  [int]$DryTestSeconds = 900,
  # Solo prueba en seco: permite ejecutar `watch` fuera de [t0,t1] y forzar bloque
  [switch]$Test,
  [switch]$ForzarBloque,
  # Solo prueba en seco: umbral de RAM libre de G-12 (MB). Su unico fin es poder
  # ejercitar la NEGATIVA de G-12 (codigo 48) sin tocar la VM; en la ventana se usa
  # el valor del plan (1500 MB) porque es el valor por defecto.
  [int]$RamMinMb = 1500,
  # Via normal: variables de entorno TFG_GUEST_PW / TFG_MANAGER_PW.
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
$Recetas = Join-Path $Base 'recetas'

$Vmrun   = 'C:\Program Files\VMware\VMware Workstation\vmrun.exe'
$Victim  = 'D:\TFG-VMs\victima-linux\victima-linux.vmx'
$Manager = 'D:\TFG-VMs\wazuh-server\wazuh-server.vmx'
$Snap    = 'lab-listo-legit-v2'

$Ssh = 'C:\Program Files\Git\usr\bin\ssh.exe'
$Scp = 'C:\Program Files\Git\usr\bin\scp.exe'
$Key = Join-Path $env:USERPROFILE '.ssh\id_ed25519_tfg_lab'
$Vic = 'angel@192.168.65.129'
$Man = 'angel@192.168.65.128'
$GuestClient = '/home/angel/ghosts-client'

$ApiBase = 'http://192.168.65.1:5000/api'
$Psql    = 'D:\TFG-VMs\material-ghosts\pgsql\bin\psql.exe'

$Log = Join-Path $Base 'legitimo_host_control.log'
$VigLog = Join-Path $Base 'vigilancia_legitimo.log'
$WatchState = Join-Path $env:TEMP 'opencode\tfg_watch_estado.json'

# --- Credenciales SOLO por entorno (nunca del fichero, nunca al log) -------
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

function Wait-VmSsh([string]$Target, [int]$TimeoutSec = 240) {
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $deadline) {
    & $Ssh -i $Key -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=5 $Target 'true' 2>$null
    if ($LASTEXITCODE -eq 0) { Write-Log "SSH OK -> $Target"; return $true }
    Start-Sleep -Seconds 5
  }
  Write-Log "SSH TIMEOUT -> $Target"
  return $false
}

function Copy-ToVm([string]$Local, [string]$Target, [string]$Remoto = '/tmp/') {
  $out = & $Scp -i $Key -o StrictHostKeyChecking=accept-new -o BatchMode=yes $Local "${Target}:$Remoto" 2>&1
  Write-Log "scp $(Split-Path $Local -Leaf) -> $Target rc=$LASTEXITCODE $((($out | Out-String).Trim()))"
}

function Invoke-OnVm([string]$Target, [string]$RemoteCmd, [string]$Pw, [switch]$SinLog) {
  if ($Pw) { $out = ($Pw | & $Ssh -i $Key -o StrictHostKeyChecking=accept-new $Target $RemoteCmd 2>&1 | Out-String) }
  else     { $out = (& $Ssh -i $Key -o StrictHostKeyChecking=accept-new $Target $RemoteCmd 2>&1 | Out-String) }
  if (-not $SinLog) { Write-Log ("[$Target] $RemoteCmd`n" + $out.Trim()) }
  return $out
}

function Get-RepoHash([string]$RelPath) {
  $f = Join-Path $Base 'sha256sums.txt'
  if (-not (Test-Path $f)) { return '' }
  $norm = $RelPath -replace '\\','/'
  foreach ($l in Get-Content $f) {
    if ($l -match '^([0-9a-f]{64})\s+(.+)$' -and $Matches[2].Trim() -eq $norm) { return $Matches[1] }
  }
  return ''
}

function Get-FileHash256([string]$Path) {
  if (-not (Test-Path $Path)) { return '' }
  return (Get-FileHash $Path -Algorithm SHA256).Hash.ToLower()
}

function Get-GhostsMachines {
  try { return Invoke-RestMethod -Uri "$ApiBase/machines?q=" -TimeoutSec 10 }
  catch { Write-Log "AVISO: GHOSTS API no responde: $($_.Exception.Message)"; return @() }
}

function Reconciliar-GhostsMachine([string]$Nombre) {
  $all = @(Get-GhostsMachines)
  $mine = @($all | Where-Object { $_.name -eq $Nombre })
  Write-Log ("reconciliar: maquinas '$Nombre' = " + $mine.Count)
  if ($mine.Count -le 1) { return }
  $idTxt = Invoke-OnVm $Vic "cat $GuestClient/instance/id.json 2>/dev/null" '' -SinLog
  $m = [regex]::Match([string]$idTxt, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
  $keepId = if ($m.Success) { $m.Value } else { '' }
  $keep = $mine | Where-Object { $_.id -eq $keepId } | Select-Object -First 1
  if (-not $keep) { $keep = $mine | Sort-Object { [datetime]$_.lastReportedUtc } -Descending | Select-Object -First 1 }
  Write-Log ("reconciliar: conservo id=" + $keep.id)
  foreach ($mm in $mine) {
    if ($mm.id -ne $keep.id) {
      try { Invoke-RestMethod -Method Delete -Uri "$ApiBase/machines/$($mm.id)" -TimeoutSec 10 | Out-Null; Write-Log ("reconciliar: borrada id=" + $mm.id) }
      catch { Write-Log ("reconciliar: NO se pudo borrar id=" + $mm.id) }
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

function Clear-PendingUpdates([string]$MachineId) {
  if (-not $MachineId) { return }
  $r = & $Psql -h 127.0.0.1 -p 5432 -U ghosts -d ghosts -t -A -c "delete from machine_updates where machineid = '$MachineId';" 2>&1
  Write-Log "machine_updates borradas para $MachineId -> $((([string]$r) -replace '\s+',' ').Trim())"
}

function Get-MachineIds([string]$Nombre = 'victima-linux') {
  $r = & $Psql -h 127.0.0.1 -p 5432 -U ghosts -d ghosts -t -A -c "select id from machines where name = '$Nombre';" 2>&1
  return @(([string]$r) -split "`r?`n" | Where-Object { $_.Trim() -ne '' } | ForEach-Object { $_.Trim() })
}

# Coloca una timeline EN EL DISCO del cliente (cliente PARADO; la recarga en caliente
# mata al cliente v8.3.1 - hallazgo de L1).
function Set-TimelineEnVictima([string]$Path) {
  Copy-ToVm $Path $Vic
  Invoke-OnVm $Vic "cp -f /tmp/$(Split-Path $Path -Leaf) $GuestClient/config/timeline.json" '' -SinLog | Out-Null
  $tv = Invoke-OnVm $Vic "sha256sum $GuestClient/config/timeline.json" '' -SinLog
  Write-Log "[timeline en la victima] $((([string]$tv) -replace '\s+',' ').Trim())"
}

function Get-ClientEstado {
  $s = Invoke-OnVm $Vic "pgrep -af "(^|/)ghosts[.]client[.]linux" | head -1" '' -SinLog
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
  Write-Log "cliente NO esta vivo (revisar client.out)"; return $false
}

function Invoke-WatchManager {
  Copy-ToVm (Join-Path $Base 'watch_manager.py') $Man | Out-Null
  $out = Invoke-OnVm $Man 'python3 /tmp/watch_manager.py' $ManagerPw -SinLog
  $kv = @{}
  foreach ($l in (($out | Out-String) -split "`r?`n")) {
    if ($l -match '^([a-zA-Z0-9_]+)=(.*)$') { $kv[$Matches[1]] = $Matches[2].Trim() }
  }
  return ,$kv
}

# --- calendario (misma fuente que el keepalive) ---------------------------
function Get-Calendario {
  $p = Join-Path $Recetas 'calendario.json'
  if (-not (Test-Path $p)) { return $null }
  return Get-Content -Raw $p | ConvertFrom-Json
}

function Get-BloqueEstado([datetime]$AhoraUtc) {
  $cal = Get-Calendario
  $res = @{ estado = 'fuera'; bloque = '' }
  if (-not $cal) { return $res }
  $hhmm = $AhoraUtc.ToString('HH:mm')
  foreach ($b in $cal.bloques) {
    $on = $b.on.Substring(0,5); $off = $b.off.Substring(0,5)
    if ($hhmm -ge $on -and $hhmm -lt $off) {
      $res.bloque = $b.id
      $res.estado = if ($b.tipo -eq 'trabajo') { 'bloque' } else { 'pausa' }
      return $res
    }
  }
  return $res
}

# ===========================================================================
if (($Phase -in @('prep','arm','drytest','cleanup')) -and (-not $GuestPw)) {
  Write-Log "ERROR: falta la contrasena de las VMs (TFG_GUEST_PW o parametro -GuestPw). Abortando fase '$Phase'."
  exit 30
}

switch ($Phase) {

  # =========================================================================
  'prep' {
    Write-Log "=== START prep (host UTC $(TsUtc)) t0=$T0 t1=$T1 ==="

    # --- G-1: el snapshot v2 existe -------------------------------------
    $snaps = (& $Vmrun -T ws listSnapshots $Victim 2>&1 | Out-String)
    if ($snaps -notmatch [regex]::Escape($Snap)) {
      Write-Log "G-1 FALLO: no existe el snapshot '$Snap'. NO se arma nada."; exit 41
    }
    Write-Log "G-1 OK: snapshot '$Snap' presente | $((($snaps -replace '\s+',' ')).Trim())"

    # --- G-10 (host): D: y Windows Update -------------------------------
    $dFreeGb = [math]::Round((Get-PSDrive D).Free / 1GB, 1)
    $wu = (Get-Service wuauserv -ErrorAction SilentlyContinue).StartType
    Write-Log "G-10: D_libre_gb=$dFreeGb wuauserv_StartType=$wu sesion=$env:USERNAME"
    if ($dFreeGb -lt 60) { Write-Log "G-10 FALLO: D: < 60 GB"; exit 47 }
    if ("$wu" -ne 'Disabled') { Write-Log "G-10 FALLO: Windows Update NO esta pausado (ejecuta pausar_windows_update.ps1 pausar)"; exit 47 }

    # --- G-4: receta valida y mapeo de dias ------------------------------
    $chk = & python (Join-Path $Repo '_artefactos\scripts\construir_receta_legitima.py') --check 2>&1 | Out-String
    Write-Log "G-4 --check:`n$($chk.Trim())"
    if ($chk -notmatch 'RESULT=PASS') { Write-Log "G-4 FALLO: la receta no valida"; exit 20 }
    $sha = @{}
    foreach ($d in 1,2,3) {
      $p = Join-Path $Recetas "d$d.json"
      $sha[$d] = Get-FileHash256 $p
      $exp = Get-RepoHash "Soporte/Laboratorio/legitimo_72h/recetas/d$d.json"
      if ($exp -and $sha[$d] -ne $exp) { Write-Log "G-4 FALLO: d$d.json no coincide con sha256sums.txt"; exit 20 }
    }
    Write-Log ("G-4 OK: d1=$($sha[1].Substring(0,8)) d2=$($sha[2].Substring(0,8)) d3=$($sha[3].Substring(0,8)) mapa 26/27/28 -> d1/d2/d3")

    # --- revert + start --------------------------------------------------
    Invoke-Vmrun @('-T','ws','revertToSnapshot',$Victim,$Snap) | Out-Null
    Invoke-Vmrun @('-T','ws','start',$Victim,'nogui')          | Out-Null
    Invoke-Vmrun @('-T','ws','start',$Manager,'nogui')         | Out-Null
    if (-not (Wait-VmSsh $Vic 300)) { Write-Log 'FALLO: no hay SSH a la victima'; exit 31 }
    if (-not (Wait-VmSsh $Man 300)) { Write-Log 'FALLO: no hay SSH al manager'; exit 31 }

    # --- G-12: RAM de la victima (y swap, que se declara) ----------------
    $mem = Invoke-OnVm $Vic "awk '/^MemAvailable:/{print int(`$2/1024)} /^SwapTotal:/{print int(`$2/1024)}' /proc/meminfo" '' -SinLog
    $nums = @(([string]$mem) -split "`r?`n" | Where-Object { $_.Trim() -match '^\d+$' } | ForEach-Object { [int]$_.Trim() })
    $ramLibre = if ($nums.Count -ge 1) { $nums[0] } else { 0 }
    $swapMb   = if ($nums.Count -ge 2) { $nums[1] } else { 0 }
    Write-Log "G-12: ram_free_mb=$ramLibre swap_mb=$swapMb ram_min_mb=$RamMinMb"
    if ($ramLibre -lt $RamMinMb) { Write-Log "G-12 FALLO: RAM libre < $RamMinMb MB"; exit 48 }
    if ($swapMb -ne 0) { Write-Log "G-12 AVISO (declarado): swap_mb=$swapMb != 0 (el plan asumia 0; no se toca la VM)" }

    # --- deploy del cliente arreglado (nlog Warn + d1/d2/d3 + calendario) -
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Ghosts 'deploy_client.ps1')
    if ($LASTEXITCODE -ne 0) { Write-Log "FALLO: deploy_client.ps1 rc=$LASTEXITCODE"; exit 32 }

    # --- G-2: disco e inodos de la victima -------------------------------
    # Sin comillas dobles dentro del comando remoto: Windows PowerShell las elimina al
    # pasar el argumento a ssh.exe y rompe el `awk` (hallazgo de la ronda 2). `$5+0`
    # convierte "16%" en 16 sin necesidad de `gsub`.
    $df = Invoke-OnVm $Vic "df -Pk / | awk 'NR==2{print int(`$4/1024)}'; df -Pi / | awk 'NR==2{print 100-(`$5+0)}'" '' -SinLog
    $dfn = @(([string]$df) -split "`r?`n" | Where-Object { $_.Trim() -match '^\d+$' } | ForEach-Object { [int]$_.Trim() })
    $dfFreeMb = if ($dfn.Count -ge 1) { $dfn[0] } else { 0 }
    $inodosPct = if ($dfn.Count -ge 2) { $dfn[1] } else { 0 }
    Write-Log "G-2: df_free_mb=$dfFreeMb inodos_libres_pct=$inodosPct"
    if ($dfFreeMb -lt 4096) { Write-Log "G-2 FALLO: menos de 4 GB libres"; exit 42 }
    if ($inodosPct -lt 20) { Write-Log "G-2 FALLO: menos del 20% de inodos libres"; exit 42 }

    # --- G-3: verificar_arreglos.sh --------------------------------------
    Copy-ToVm (Join-Path $Guest 'verificar_arreglos.sh') $Vic
    $nlogSha = Get-RepoHash 'Soporte/Laboratorio/ghosts/client_config/nlog.config'
    $kaSha   = Get-RepoHash 'Soporte/Laboratorio/legitimo_72h/guest/tfg_keepalive.sh'
    $va = Invoke-OnVm $Vic "bash /tmp/verificar_arreglos.sh $nlogSha $($sha[1]) $($sha[2]) $($sha[3]) $kaSha; echo rc=`$?" $GuestPw
    $vaTxt = ([string]$va)
    Write-Log "G-3 verificar_arreglos:`n$($vaTxt.Trim())"
    if ($vaTxt -notmatch 'RESULT=PASS') { Write-Log "G-3 FALLO: los arreglos no estan aplicados en el invitado"; exit 40 }

    # --- manager: arranque, higiene y logall_json ON ---------------------
    Copy-ToVm (Join-Path $Ghosts 'arrancar_manager.sh') $Man
    Copy-ToVm (Join-Path $Ghosts 'logall_json_ctl.sh')  $Man
    Copy-ToVm (Join-Path $Ghosts 'diag_wazuh.sh')       $Man
    Copy-ToVm (Join-Path $Base  'estado_manager.sh')    $Man
    Copy-ToVm (Join-Path $Base  'exportar_denominador.sh') $Man
    Invoke-OnVm $Man 'bash /tmp/arrancar_manager.sh' $ManagerPw | Out-Null
    Invoke-OnVm $Man 'bash /tmp/logall_json_ctl.sh on'  $ManagerPw | Out-Null
    Invoke-OnVm $Man 'bash /tmp/logall_json_ctl.sh status' $ManagerPw | Out-Null

    # --- G-7: logall_json=yes + daemons ---------------------------------
    $st = Invoke-OnVm $Man 'bash /tmp/logall_json_ctl.sh status' $ManagerPw -SinLog
    $stTxt = ([string]$st) -replace '\s+',' '
    Write-Log "G-7: $($stTxt.Trim())"
    if ($stTxt -notmatch '<logall_json>yes</logall_json>' -or $stTxt -notmatch 'manager=active') {
      Write-Log "G-7 FALLO: logall_json no esta en yes o el manager no esta active"; exit 44
    }
    $dae = Invoke-OnVm $Man "pgrep -c -f 'wazuh-remoted|wazuh-analysisd'" '' -SinLog
    if ([int](([string]$dae).Trim()) -lt 2) { Write-Log "G-7 FALLO: faltan daemons (remoted/analysisd)"; exit 44 }

    # --- internet local + GHOSTS ----------------------------------------
    if ((Test-PortOpen 8080) -and (Test-PortOpen 9090) -and (Test-PortOpen 9092)) {
      Write-Log "internet local: ya esta arriba (8080/9090/9092)"
    } else {
      & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Inet 'start_internet_local.ps1')
      Write-Log "internet local lanzada"
    }
    if (Test-PortOpen 5000) {
      Write-Log "GHOSTS API: ya esta arriba (5000)"
    } else {
      & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Ghosts 'start_ghosts.ps1')
      Write-Log "servidor GHOSTS lanzado"
    }
    Ensure-FirewallGhosts

    # --- G-8: aislamiento de la victima + internet local ----------------
    Copy-ToVm (Join-Path $Inet 'verificar_internet_local.sh') $Vic
    $net = Invoke-OnVm $Vic 'bash /tmp/verificar_internet_local.sh' $GuestPw
    $netTxt = ([string]$net)
    Write-Log "G-8:`n$($netTxt.Trim())"
    if ($netTxt -match 'default via') { Write-Log "G-8 FALLO: la victima tiene ruta por defecto (NAT conectado)"; exit 45 }

    # --- G-5: agente dentro ---------------------------------------------
    $ag = Invoke-OnVm $Vic "pgrep -c -f wazuh-agentd" '' -SinLog
    $ac = Invoke-OnVm $Man 'bash /tmp/estado_manager.sh' $ManagerPw -SinLog
    Write-Log "G-5: agentd_procs=$(([string]$ag).Trim()) | $((([string]$ac) -replace '\s+',' ').Trim())"
    if ((([string]$ac) -match 'Status:\s*Active') -eq $false) { Write-Log "G-5 FALLO: el agente 001 no esta Active"; exit 43 }

    # --- G-11: machineids ------------------------------------------------
    $ids = Get-MachineIds 'victima-linux'
    Write-Log ("G-11: machineids de victima-linux = " + ($ids -join ','))

    # --- cliente + timeline d1 (queda PARADO con d1 colocada) ------------
    Invoke-OnVm $Vic "bash $GuestClient/client_ctl.sh stop" '' -SinLog | Out-Null
    Set-TimelineEnVictima (Join-Path $Recetas 'd1.json')
    $act = Invoke-OnVm $Vic "sha256sum $GuestClient/config/timeline.json | cut -c1-8" '' -SinLog
    Write-Log "prep: timeline activa = $(([string]$act).Trim()) (esperado d1=$($sha[1].Substring(0,8)))"
    # Día 1 YA colocado: se marca en `rotacion.estado` para que el keepalive NO rote a las
    # 07:45 del día 1 (el cliente reescribe el fichero al arrancar y el sha cambia; el
    # estado es determinista y evita gastar una de las 2 rotaciones declaradas).
    $fechaT0 = ([datetime]::Parse($T0).ToUniversalTime()).ToString('yyyy-MM-dd')
    Invoke-OnVm $Vic "echo $fechaT0 > $GuestClient/rotacion.estado; cat $GuestClient/rotacion.estado" '' -SinLog | Out-Null
    Write-Log "prep: rotacion.estado = $fechaT0 (día 1 ya colocado; no se rota el día 1)"

    # --- G-9: sonda de rotacion (aviso) ---------------------------------
    $rot = Invoke-OnVm $Man 'sudo -S -p '''' ls -la --time-style=+%H:%M /var/ossec/logs/archives/*/*/ossec-archive-*.json.gz 2>/dev/null | tail -2' $ManagerPw -SinLog
    Write-Log "G-9 (informativo) ultimo .gz: $((([string]$rot) -replace '\s+',' ').Trim())"

    # --- G-6: el `df -P` del agente llega al manager --------------------
    $ok6 = $false
    for ($i = 1; $i -le 14; $i++) {
      $n = Invoke-OnVm $Man 'sudo -S -p '''' grep -c -E df[[:space:]]-P /var/ossec/logs/archives/archives.json 2>/dev/null || echo 0' $ManagerPw -SinLog
      if ([int](([string]$n).Trim()) -ge 7) { $ok6 = $true; break }
      Start-Sleep -Seconds 30
    }
    if (-not $ok6) { Write-Log "G-6 FALLO: no llega ninguna muestra 'df -P' del agente 001 en 7 min"; exit 46 }
    Write-Log "G-6 OK: muestras 'df -P' del agente 001 en archives.json"

    Invoke-Vmrun @('-T','ws','listSnapshots',$Victim) | Out-Null
    Write-Log "=== END prep (laboratorio LISTO, cliente PARADO) ==="
  }

  # =========================================================================
  'arm' {
    Write-Log "=== START arm (host UTC $(TsUtc)) t0=$T0 ==="
    $sha1 = Get-FileHash256 (Join-Path $Recetas 'd1.json')
    $sha2 = Get-FileHash256 (Join-Path $Recetas 'd2.json')
    $sha3 = Get-FileHash256 (Join-Path $Recetas 'd3.json')

    Copy-ToVm (Join-Path $Guest 'tfg_keepalive.sh')           $Vic
    Copy-ToVm (Join-Path $Guest 'tfg-ghosts-legit.service')   $Vic
    Copy-ToVm (Join-Path $Guest 'tfg-ghosts-legit.timer')     $Vic
    Copy-ToVm (Join-Path $Guest 'instalar_tarea_invitado.sh') $Vic
    $inst = Invoke-OnVm $Vic "bash /tmp/instalar_tarea_invitado.sh $T0 $sha1 $sha2 $sha3; echo rc=`$?" $GuestPw
    $instTxt = ([string]$inst)
    Write-Log "arm instalar:`n$($instTxt.Trim())"
    if ($instTxt -notmatch 'rc=0') { Write-Log "FALLO arm: instalador rc != 0"; exit 33 }

    $mid = (Get-MachineIds 'victima-linux' | Select-Object -First 1)
    Clear-PendingUpdates $mid
    Ensure-Client 10 | Out-Null

    Invoke-OnVm $Man 'bash /tmp/diag_wazuh.sh' $ManagerPw | Out-Null
    Invoke-OnVm $Man 'bash /tmp/logall_json_ctl.sh status' $ManagerPw | Out-Null
    $m = Get-GhostsMachines
    $mine = @($m | Where-Object { $_.name -eq 'victima-linux' })
    Write-Log ("GHOSTS: maquinas victima-linux=" + $mine.Count + " | up=" + (($mine | ForEach-Object { $_.statusUp }) -join ',') + " | last=" + (($mine | ForEach-Object { $_.lastReportedUtc }) -join ','))
    Write-Log ("cliente: " + (Get-ClientEstado))
    $tl = Invoke-OnVm $Vic "grep -m2 -E 'Status|UtcTimeOn' $GuestClient/config/timeline.json; sha256sum $GuestClient/config/timeline.json; ip route" '' -SinLog
    Write-Log "arm timeline:`n$((([string]$tl) -replace '\s+',' ').Trim())"
    Invoke-OnVm $Vic 'systemctl list-timers tfg-ghosts-legit.timer --all --no-pager; sleep 1' '' | Out-Null
    Write-Log "=== END arm ==="
  }

  # =========================================================================
  'watch' {
    $now = (Get-Date).ToUniversalTime()
    $t0 = [datetime]::Parse($T0).ToUniversalTime()
    $t1 = [datetime]::Parse($T1).ToUniversalTime()
    if (($now -lt $t0 -or $now -gt $t1) -and -not $Test) {
      $line = "[$(TsUtc)] watch FUERA de [t0,t1] -> sin vigilancia"
      Add-Content -Path $VigLog -Value $line -Encoding utf8
      Write-Output $line
      break
    }

    # --- estado previo (persistencia de ALARMA y de <<2 chequeos>>) --------
    $prev = @{ ts = ''; archives = -1; alerts = -1; alarma_sig = ''; alarma_n = 0; cero_n = 0 }
    if (Test-Path $WatchState) {
      try { $j = Get-Content -Raw $WatchState | ConvertFrom-Json; foreach ($k in @($prev.Keys)) { if ($null -ne $j.$k) { $prev[$k] = $j.$k } } } catch { }
    }

    $cal = Get-BloqueEstado $now
    if ($ForzarBloque) { $cal = @{ estado = 'bloque'; bloque = 'TEST' } }
    $nivel = 0   # 0 OK, 1 AVISO, 2 ALARMA
    $notas = New-Object System.Collections.Generic.List[string]

    # --- senal 1: ?esta haciendo? (GHOSTS, host) ------------------------
    $ids = Get-MachineIds 'victima-linux'
    $doingAgeMin = -1
    if ($ids.Count -gt 0) {
      $inIds = ($ids | ForEach-Object { "'$_'" }) -join ','
      $q = & $Psql -h 127.0.0.1 -p 5432 -U ghosts -d ghosts -t -A -c "select coalesce(extract(epoch from (now() at time zone 'utc' - max(createdutc)))/60, -1)::int from history_timeline where machineid in ($inIds);" 2>&1
      $doingAgeMin = [int]((([string]$q).Trim() -split "`r?`n")[0])
    }
    if ($cal.estado -eq 'bloque' -and $doingAgeMin -ge 0) {
      # Umbrales CA-30 del plan v5: AVISO > 25 min, ALARMA > 35 min (los huecos de la receta
      # v2 llegan a 20,8 min y el keepalive usa STALE=30; con 15 min habia AVISO espurios).
      if ($doingAgeMin -gt 35) { $nivel = 2; $notas.Add('doing>35m') }
      elseif ($doingAgeMin -gt 25) { if ($nivel -lt 1) { $nivel = 1 }; $notas.Add('doing>25m') }
    } elseif ($cal.estado -eq 'bloque' -and $doingAgeMin -lt 0) {
      $nivel = 2; $notas.Add('sin_acciones_nunca')
    }

    # --- senales 2,3,4,5: manager ---------------------------------------
    $wm = Invoke-WatchManager
    $kaEdad = if ($wm['agente_ka_edad_s']) { [int]$wm['agente_ka_edad_s'] } else { -1 }
    if ($kaEdad -lt 0 -or $kaEdad -gt 600) { $nivel = 2; $notas.Add('agente>10m') }
    elseif ($kaEdad -gt 60) { if ($nivel -lt 1) { $nivel = 1 }; $notas.Add('agente>60s') }

    $mgrOk = ($wm['manager'] -eq 'active') -and ([int]$wm['daemons'] -ge 2)
    if (-not $mgrOk) { $nivel = 2; $notas.Add('daemons') }

    $archDelta = [int]$wm['archives_delta']
    $alertDelta = [int]$wm['alerts_delta']
    if ($archDelta -le 0 -and $alertDelta -le 0) { $prev.cero_n = [int]$prev.cero_n + 1 } else { $prev.cero_n = 0 }
    if ($prev.cero_n -ge 2 -and $cal.estado -eq 'bloque') { $nivel = 2; $notas.Add('sin_eventos') }

    $dfAvailKb = [int]$wm['df_avail_kb']
    $dfGb = if ($dfAvailKb -ge 0) { [math]::Round($dfAvailKb / 1MB, 1) } else { -1 }
    $dfTasa = $wm['df_tasa_mb_h']
    $dfEdad = [int]$wm['df_muestras_edad_min']
    if ($dfAvailKb -lt 0) { if ($nivel -lt 1) { $nivel = 1 }; $notas.Add('sin_df') }
    elseif ($dfAvailKb -lt 2097152) { $nivel = 2; $notas.Add('df<2G') }
    elseif ($dfAvailKb -lt 3145728) { if ($nivel -lt 1) { $nivel = 1 }; $notas.Add('df<3G') }
    if ($dfTasa -ne 'none' -and $dfTasa -ne $null -and $dfTasa -ne '') {
      $t = [double]$dfTasa
      if ($t -lt -1024) { $nivel = 2; $notas.Add('tasa<-1G/h') }
      elseif ($t -lt -500) { if ($nivel -lt 1) { $nivel = 1 }; $notas.Add('tasa<-500M/h') }
    }
    if ($dfEdad -gt 20 -and $dfAvailKb -ge 0) { if ($nivel -lt 1) { $nivel = 1 }; $notas.Add('df_viejo') }

    # --- senal 6: disco del host ----------------------------------------
    $hostGb = [math]::Round((Get-PSDrive D).Free / 1GB, 1)
    if ($hostGb -lt 20) { $nivel = 2; $notas.Add('host<20G') }
    elseif ($hostGb -lt 60) { if ($nivel -lt 1) { $nivel = 1 }; $notas.Add('host<60G') }

    # --- senal 7: BD de GHOSTS ------------------------------------------
    $dbMb = -1
    $q = & $Psql -h 127.0.0.1 -p 5432 -U ghosts -d ghosts -t -A -c "select (pg_database_size('ghosts')/1048576)::int;" 2>&1
    try { $dbMb = [int]((([string]$q).Trim() -split "`r?`n")[0]) } catch { }
    if ($dbMb -gt 10240) { $nivel = 2; $notas.Add('db>10G') }
    elseif ($dbMb -gt 4096) { if ($nivel -lt 1) { $nivel = 1 }; $notas.Add('db>4G') }

    # --- senal 8: recuperaciones/rotaciones (informativo) ----------------
    # La vigilancia NO toca la victima (S7.1): `recovery.log` se lee AL CERRAR (post-hoc).
    $recN = 'post-hoc'; $rotN = 'post-hoc'

    # --- senal 9: RAM (post-hoc) ----------------------------------------
    $estadoTxt = @('OK','AVISO','ALARMA')[$nivel]
    $bloqueTxt = if ($cal.estado -eq 'bloque') { 'si' } else { $cal.estado }
    $doingTxt = if ($doingAgeMin -ge 0) { "$($doingAgeMin)m" } else { 'n/a' }
    $hbTxt = if ($kaEdad -ge 0) { "$($kaEdad)s" } else { 'n/a' }
    $line = "[$(TsUtc)] [watch] estado=$estadoTxt doing_age=$doingTxt bloque=$bloqueTxt hb=$hbTxt ag=$($wm['agente_status']) mgr=$($wm['manager'])/$($wm['daemons']) arch=$($archDelta)B dia=$($alertDelta)B df=$(if($dfGb -ge 0){"${dfGb}G"}else{'n/a'}) tasa=$($dfTasa)MB/h db=${dbMb}MB host=${hostGb}G ram=post-hoc rec=post-hoc rot=post-hoc notas=$($notas -join ',')"

    Add-Content -Path $VigLog -Value $line -Encoding utf8
    Add-Content -Path $Log -Value $line -Encoding utf8
    Write-Output $line

    # --- alarma visible --------------------------------------------------
    if ($nivel -eq 2) {
      $sig = ($notas -join ',')
      if ($prev.alarma_sig -eq $sig) { $prev.alarma_n = [int]$prev.alarma_n + 1 } else { $prev.alarma_n = 1 }
      $sufijo = if ([int]$prev.alarma_n -ge 2) { 'PERSISTENTE' } else { 'NUEVA' }
      $tsSafe = (TsUtc) -replace ':',''
      $af = Join-Path $Base "ALARMA_$tsSafe.txt"
      @(
        "ALARMA ($sufijo) $((TsUtc))",
        "senales: $sig",
        $line,
        "recuperaciones=$recN rotaciones=$rotN",
        "La vigilancia NO actua: solo avisa. Revisa disco/agente/GHOSTS."
      ) | Set-Content -Path $af -Encoding utf8
      try { & msg.exe $env:USERNAME "TFG-Legit ALARMA ($sufijo): $sig" 2>$null } catch { }
      $prev.alarma_sig = $sig
    } else {
      $prev.alarma_sig = ''
      $prev.alarma_n = 0
    }

    $prev.ts = TsUtc
    $prev.archives = [int]$wm['archives_bytes']
    $prev.alerts = [int]$wm['alerts_bytes']
    $prev | ConvertTo-Json | Set-Content -Path $WatchState -Encoding utf8
  }

  # =========================================================================
  'stop' {
    Write-Log "=== START stop (host UTC $(TsUtc)) ==="
    Invoke-Vmrun @('-T','ws','stop',$Victim,'soft') | Out-Null
    Write-Log "victima parada (soft). El manager SIGUE encendido para la extraccion."
    Write-Log "=== END stop ==="
  }

  # =========================================================================
  'drytest' {
    Write-Log "=== START drytest (host UTC $(TsUtc)) ==="
    $base = (Get-Date).ToUniversalTime().AddMinutes(2).ToString('HH:mm') + 'Z'
    $dry = Join-Path $env:TEMP 'opencode\d1.dry.json'
    & python (Join-Path $Repo '_artefactos\scripts\construir_receta_legitima.py') --dry --base $base --out $dry
    Write-Log "drytest: timeline comprimida en $dry (base $base)"

    Invoke-OnVm $Vic "bash $GuestClient/client_ctl.sh stop" '' -SinLog | Out-Null
    $mid = (Get-MachineIds 'victima-linux' | Select-Object -First 1)
    Clear-PendingUpdates $mid
    Set-TimelineEnVictima $dry
    $before = & $Psql -h 127.0.0.1 -p 5432 -U ghosts -d ghosts -t -A -c 'select count(*) from history_timeline;' 2>&1
    Ensure-Client 10 | Out-Null
    Write-Log "drytest: esperando $DryTestSeconds s..."
    Start-Sleep -Seconds $DryTestSeconds
    $dur = & $Psql -h 127.0.0.1 -p 5432 -U ghosts -d ghosts -t -A -F',' -c "select handler, count(*) from history_timeline where createdutc >= (now() at time zone 'utc') - interval '$([int]($DryTestSeconds/60)+2) minutes' group by handler;" 2>&1
    $after = & $Psql -h 127.0.0.1 -p 5432 -U ghosts -d ghosts -t -A -c 'select count(*) from history_timeline;' 2>&1
    Write-Log "drytest: antes=$(([string]$before).Trim()) despues=$(([string]$after).Trim()) por_handler=$((([string]$dur) -replace '\s+',' ').Trim())"
    Invoke-OnVm $Vic "bash $GuestClient/client_ctl.sh stop" '' -SinLog | Out-Null
    Set-TimelineEnVictima (Join-Path $Recetas 'd1.json')
    Write-Log "=== END drytest (d1 restaurada; cliente PARADO) ==="
  }

  # =========================================================================
  'cleanup' {
    Write-Log "=== START cleanup (host UTC $(TsUtc)) ==="
    Invoke-OnVm $Vic "bash $GuestClient/client_ctl.sh stop" '' -SinLog | Out-Null
    Invoke-OnVm $Man 'bash /tmp/logall_json_ctl.sh off' $ManagerPw | Out-Null
    Invoke-OnVm $Man 'bash /tmp/logall_json_ctl.sh status' $ManagerPw | Out-Null
    Invoke-OnVm $Man 'sudo -S -p '''' diff /var/ossec/etc/ossec.conf.tfg-bak /var/ossec/etc/ossec.conf && echo CONFIG_IDENTICA || echo CONFIG_DIFIERE; sudo -S -p '''' ls -l /var/ossec/logs/archives/ 2>/dev/null | tail -3' $ManagerPw | Out-Null
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

  # =========================================================================
  'status' {
    Invoke-Vmrun @('-T','ws','list') | Out-Null
    $m = Get-GhostsMachines
    Write-Log ("status GHOSTS: " + (@($m | ForEach-Object { "$($_.name)=$($_.statusUp)/$($_.lastReportedUtc)" }) -join '; '))
    Invoke-OnVm $Man 'bash /tmp/logall_json_ctl.sh status' $ManagerPw | Out-Null
    Write-Log ("status tareas host: " + ((Get-ScheduledTask -TaskName 'TFG-Legit-*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty TaskName) -join ','))
  }
}

exit 0
