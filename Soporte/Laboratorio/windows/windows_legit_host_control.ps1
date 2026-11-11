# ============================================================================
# windows_legit_host_control.ps1 v4 - control del HOST para la ventana legitima Windows
# Bloque `windows-legit-prep` (W3-bis). Espejo de `legitimo_72h/legitimo_host_control.ps1`.
# ----------------------------------------------------------------------------
# Fases:
#   prep    : G-W1..G-W12 -> revert a `lab-listo-windows-legit` + arranque + deploy
#             idempotente + verificacion del invitado + SINK 9095 arriba y POST de
#             prueba (si no, exit 48) + manifiesto si esta sellado (si DIFIERE, exit 46).
#             Puerta G-1: `DEFENDER_OFF=1` y `SESION_ANGEL=1` o exit 47. Lista negra
#             7.3 completa (G-2): si hay residuos, exit 46. NO arma.
#             F-1.2: al empezar ventana nueva ARCHIVA `heartbeat.jsonl` (host) y
#             `heartbeat.seq` (invitado) y reinicia el sink (un solo emisor: `-Loop`).
#   arm     : fija el mapa de dias (--t0), re-despliega recetas, crea `armado.flag`,
#             arranca la actividad y enciende `logall_json` (manager) DE FORMA
#             IDEMPOTENTE: si ya esta `yes`, NO ejecuta `on` (no borra archives.json).
#             G-8: si el payload ya esta desplegado con el MISMO `MANIFEST_SHA256`,
#             NO re-sube el payload ni re-registra tareas (solo aplica lo que falte).
#             Escribe `ventana_actual.json` (t0/t1/fecha) para `crudo`/`cleanup`.
#   watch   : vigilancia READ-ONLY **SIN SSH AL INVITADO**: lee `heartbeat.jsonl` en el
#             host (chivato por red). G-W13 (nuevo): frescura <= 12 min, `seq` monotono
#             y `ka_instancias=1`. G-W5/G-W8/G-W9/G-W10/G-W11 salen del latido.
#   crudo   : copia `archives` + `alerts` del manager a
#             `D:\TFG-VMs\legitimo-windows-<fecha>\crudo\`, sella sha256 + MANIFEST.tsv,
#             calcula `M` de la copia y escribe `crudo.done`.
#   stop    : parada suave: crea `stop.flag`, espera a que el bucle salga, borra el flag,
#             para el sink. SOLO si existe `cosecha.done` (orden critico).
#   cleanup : BLOQUEADO sin `crudo.done` (exit 84). Despues: stop.flag + bucle + sink,
#             desregistra tareas, para la VM, `logall_json off` + CONFIG_IDENTICA,
#             para GHOSTS; deja 0 VMs de medida.
#   status  : imprime el estado (incluye HB_EDAD_MIN, KA_PID, CLIENTE_*, DEFENDER_*,
#             SESION_ANGEL).
#   drytest : evalua los guardarrailes de CADA fase en seco (sin ventana, sin acciones).
#             `-DryPhase <fase>` limita la prueba a una fase.
#
# Guardarrailes (definidos aqui porque el plan los nombra sin enumerarlos; cada uno cita
# su criterio del plan):
#   G-W1  tareas `TFG-Baseline-*` del host desactivadas o ausentes        (R-W1/CA-W19)
#   G-W2  snapshot `lab-listo-windows-legit` presente + los 6 previos     (CA-W11)
#   G-W3  disco del host D: >= 60 GB libres                               (R-W3)
#   G-W4  receta `--check` PASS + sha256 + espejo 504=504                 (CA-W1/CA-W2)
#   G-W5  Sysmon64/WazuhSvc Running y agente 002 Active                   (WE0-1)
#   G-W6  aislamiento: sin ruta por defecto (cualquiera) + hosts + victima-linux off (W-V5)
#   G-W7  `logall_json` segun [t0,t1]: `yes` dentro, `no` fuera; sin t0/t1 -> SKIP (CA-W16)
#   G-W8  0 procesos con padre `vmtoolsd.exe` (sin acceso del operador)   (W-V4/CA-W13)
#   G-W9  sin suspension (STANDBYIDLE/HIBERNATEIDLE/HYBRIDSLEEP = 0)      (R-W4)
#   G-W10 disco del invitado >= 4 GB + guarda 500 MB del keepalive        (R-W15)
#   G-W11 un solo cliente vivo (1 `ghosts.exe`, 1 machineid)              (CA-W6)
#   G-W12 host: RAM libre >= 1500 MB y Windows Update pausado             (R-W4)
#   G-W13 latido fresco (<= 12 min) + `seq` monotono + `ka_instancias=1`   (CA-W3b-12b)
#   G-W14 campo `defender` del latido en `off` (si `on` => ALARMA; R4)      (T2b-1b)
#
# Sin secretos. Uso (HOST):
#   powershell -NoProfile -ExecutionPolicy Bypass -File windows_legit_host_control.ps1 -Phase drytest
#   ... -Phase prep | arm -T0 2026-11-16T00:00:00Z -T1 2026-11-19T00:00:00Z | watch | crudo | stop | cleanup | status
#   `G-W7` decide por la ventana: con `-T0/-T1` exige `yes` dentro y `no` fuera; sin
#   ellos usa `ventana_actual.json` (lo escribe `arm`); si tampoco existe, SKIP declarado.
#   `watch`/`crudo`/`cleanup` aceptan `-Heartbeat` (ruta del JSONL del chivato).
#   `prep -SoloListaNegra` y `prep -SimularVerificador <fichero>` son SOLO PRUEBAS
#   (lista negra read-only / puerta G-1 sin tocar la VM).
# ============================================================================
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('prep', 'arm', 'watch', 'crudo', 'stop', 'cleanup', 'status', 'drytest')]
  [string]$Phase,
  [string]$T0 = '',
  [string]$T1 = '',
  # drytest: limita la prueba a una fase (por defecto, todas).
  [ValidateSet('', 'prep', 'arm', 'watch', 'crudo', 'stop', 'cleanup', 'status')]
  [string]$DryPhase = '',
  # drytest: log alternativo (la prueba negativa de G-W11 no ensucia `drytest.log`).
  [string]$DryLogPath = '',
  # `prep -SoloListaNegra`: comprobacion READ-ONLY de la lista negra 7.3 (G-2) sin
  # revertir ni desplegar. Sirve para la prueba negativa reproducible (exit 46).
  [switch]$SoloListaNegra,
  # SOLO PRUEBAS (T2b-1b): inyecta la salida de `verificar_windows.ps1` desde un fichero
  # en lugar de pedirla por SSH. Sirve para probar la puerta `exit 47` (G-1) sin tocar
  # Defender ni la VM. En operacion normal NO se usa (vacio).
  [string]$SimularVerificador = '',
  # Chivato por red: JSONL que escribe `heartbeat_sink.py` en el HOST.
  [string]$Heartbeat = '',
  [int]$HbMaxMin = 12,
  [string]$SinkBind = '192.168.65.1',
  [int]$SinkPort = 9095,
  # Donde vive el pid/log del sink (debe coincidir con el `-OutDir` del ctl).
  [string]$SinkOutDir = '',
  # Raiz del crudo (fuera del repo).
  [string]$CrudoBase = 'D:\TFG-VMs',
  [int]$RamMinMb = 1500,
  [int]$DiskHostMinGb = 60,
  [int]$DiskGuestMinMb = 4096
)

$ErrorActionPreference = 'Continue'

$Repo    = 'D:\TFG\HIDS-Analisis_Capacidad_deteccion_Ataques_locales_MITRE'
$Win     = Join-Path $Repo 'Soporte\Laboratorio\windows'
$Recetas = Join-Path $Win 'recetas'
$Campana = Join-Path $Win 'campana'
$Deploy  = Join-Path $Win 'deploy_windows.ps1'
$Ghosts  = Join-Path $Repo 'Soporte\Laboratorio\ghosts'
$Evid    = Join-Path $Win 'legit\evidencia'
# D1/D3: los logs de control viven en `legit/evidencia/` (versionable: excepcion
# explicita en `.gitignore`). Antes estaban en la raiz del bloque y `*.log` los ignoraba.
$Log     = Join-Path $Evid 'windows_legit_host_control.log'
$VigLog  = Join-Path $Evid 'vigilancia_windows.log'
$DryLog  = Join-Path $Evid 'drytest.log'
$Cosecha = Join-Path $Win 'cosecha.done'
New-Item -ItemType Directory -Force -Path $Evid | Out-Null
if (-not $DryLogPath) { $DryLogPath = $DryLog }
if (-not $Heartbeat) { $Heartbeat = Join-Path $Evid 'heartbeat.jsonl' }
if (-not $SinkOutDir) { $SinkOutDir = $Evid }
$VentanaFile = Join-Path $Evid 'ventana_actual.json'
$ManEsp      = Join-Path $Evid 'manifiesto_esperado.json'
$SinkCtl     = Join-Path $Win 'legit\heartbeat_sink_ctl.ps1'
$SinkUrl     = "http://${SinkBind}:${SinkPort}"

# `watch` lee el latido en LOCAL; este flag hace que G-W5/G-W8/G-W9/G-W10/G-W11 no
# abran NINGUNA sesion SSH contra el invitado. `$script:SshInvitado` cuenta las que
# se abren (para demostrar el 0 del `watch`).
$script:UsarLatido = $false
$script:SshInvitado = 0

$Vmrun   = 'C:\Program Files\VMware\VMware Workstation\vmrun.exe'
$Vmx     = 'D:\TFG-VMs\victima-windows\victima-windows.vmx'
$VmxLinux = 'D:\TFG-VMs\victima-linux\victima-linux.vmx'
$VmxMgr  = 'D:\TFG-VMs\wazuh-server\wazuh-server.vmx'
$Snap    = 'lab-listo-windows-legit'
$SnapsPrevios = @('base-limpia', 'lab-listo-windows', 'lab-listo-windows-baseline',
                  'lab-listo-windows-ataques', 'lab-listo-windows-ataques-ssh',
                  'lab-listo-windows-ataques-gui')

$Ssh = 'C:\Program Files\Git\usr\bin\ssh.exe'
$Scp = 'C:\Program Files\Git\usr\bin\scp.exe'
$Key = Join-Path $env:USERPROFILE '.ssh\id_ed25519_tfg_win'
$Target = 'angel@192.168.65.130'
$RVerif = 'C:/Users/angel/ghosts-client/verificar_windows.ps1'
# El manager es Linux: el script NO puede ejecutarse con la ruta de Windows del repo.
$MgrScriptLocal = Join-Path $Repo 'Soporte\Laboratorio\ghosts\logall_json_ctl.sh'
$MgrScript      = '/tmp/logall_json_ctl.sh'

$Py = 'python'

function Ts { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
function Log([string]$m) {
  $linea = "[$(Ts)] [$Phase] $m"
  Add-Content -Path $Log -Value $linea -Encoding utf8
  Write-Output $linea
}

function Invoke-Remote([string]$Cmd, [switch]$PermitirFallo) {
  # Cuenta las sesiones SSH abiertas contra el INVITADO (demostracion de que el
  # `watch` v4 no abre ninguna: sale `SSH_INVITADO=0`).
  $script:SshInvitado++
  $eap = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  $out = & $Ssh -i $Key -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR $Target $Cmd 2>&1
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $eap
  if (-not $PermitirFallo -and $rc -ne 0) { return $null }
  return (($out | Out-String).Trim())
}

function Get-VmEnMarcha([string]$VmxPath) {
  $l = (& $Vmrun -T ws list 2>&1 | Out-String)
  return ($l -match [regex]::Escape($VmxPath))
}

function Get-Snapshots([string]$VmxPath) {
  $out = (& $Vmrun -T ws listSnapshots $VmxPath 2>&1 | Out-String)
  return @($out -split "`r?`n" | Where-Object { $_ -and $_ -notmatch '^Total snapshots' } | ForEach-Object { $_.Trim() })
}

function Get-ManagerPw {
  # D6 (declarado): el manager usa una contrasena PROPIA. En WE0 hay que definir
  # `TFG_MANAGER_PW` de forma explicita. El antiguo fallback a `TFG_GUEST_PW` se ha
  # RETIRADO: no servia para el manager (contrasena distinta) y convertia un fallo de
  # credencial en un error opaco. Sin `TFG_MANAGER_PW` las fases que lo necesitan
  # (arm/cleanup/status) dicen `manager=SKIP` con el motivo.
  return $env:TFG_MANAGER_PW
}

function Get-ManagerKey {
  # El manager es la VM Linux: SIEMPRE `id_ed25519_tfg_lab`.
  # `id_ed25519_tfg_win` es la clave del invitado Windows y NO sirve aqui (defecto F3).
  return (Join-Path $env:USERPROFILE '.ssh\id_ed25519_tfg_lab')
}

function Push-ManagerScript {
  # Copia `logall_json_ctl.sh` al manager (`/tmp`). Necesario porque la ruta del repo
  # es de Windows y el manager es Linux.
  if (-not (Test-Path $MgrScriptLocal)) { return $false }
  $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  & $Scp -i (Get-ManagerKey) -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR $MgrScriptLocal "angel@192.168.65.128:$MgrScript" 2>&1 | Out-Null
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $eap
  return ($rc -eq 0)
}

function Invoke-Manager([string]$Cmd) {
  # Una sola credencial (clave + contrasena por STDIN) para status/on/off/diff.
  $pw = Get-ManagerPw
  if ([string]::IsNullOrEmpty($pw)) { return $null }
  $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  $out = ($pw | & $Ssh -i (Get-ManagerKey) -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR angel@192.168.65.128 $Cmd 2>&1 | Out-String)
  $ErrorActionPreference = $eap
  if ($LASTEXITCODE -ne 0) { return $null }
  return $out
}

function Get-ManagerEstado {
  # Read-only: logall_json y daemons del manager. Sin manager -> SKIP.
  if (-not (Test-Path $MgrScriptLocal)) { return @{ ok = $false; skip = $true; detalle = 'sin logall_json_ctl.sh' } }
  if ([string]::IsNullOrEmpty($env:TFG_MANAGER_PW)) {
    return @{ ok = $false; skip = $true; detalle = 'sin TFG_MANAGER_PW (D6: el fallback a TFG_GUEST_PW no sirve para el manager)' }
  }  $out = Invoke-Manager "bash $MgrScript status"
  if (-not $out -or $out -match 'No such file|not found') {
    if (Push-ManagerScript) { $out = Invoke-Manager "bash $MgrScript status" }
  }
  if (-not $out -or $out -match 'Connection refused|No route|timed out|denied|Permission denied') {
    return @{ ok = $false; skip = $true; detalle = 'manager apagado o inaccesible' }
  }
  $logall = if ($out -match '<logall_json>\s*(\w+)\s*</logall_json>') { $Matches[1] } else { '' }
  $activo = ($out -match 'manager=active')
  $daemons = if ($out -match 'daemons_remoted_analysisd=(\d+)') { [int]$Matches[1] } else { 0 }
  return @{ ok = $true; skip = $false; logall = $logall; activo = $activo; daemons = $daemons; detalle = (($out -replace '\s+', ' ').Trim()) }
}

function Get-Agente002 {
  # F7 / WE0-1: estado REAL del agente 002 en el manager (`agent_control -l`).
  # Se consulta en el manager (no en el invitado) para no depender de un binario del
  # agente y para que el dato sea el que ve Wazuh. Solo tiene sentido con el manager
  # accesible: si esta apagado, G-W5 ya sale SKIP por la parte del manager.
  $out = Invoke-Manager 'sudo -S -p '''' /var/ossec/bin/agent_control -l'
  if (-not $out) { return @{ ok = $false; estado = ''; detalle = 'agent_control sin salida' } }
  $m = [regex]::Match($out, 'ID:\s*002,[^\r\n]*')
  if (-not $m.Success) { return @{ ok = $false; estado = 'AUSENTE'; detalle = 'agente 002 no listado' } }
  $linea = ($m.Value -replace '\s+', ' ').Trim()
  $estado = 'desconocido'
  if ($linea -match '(?i)\bActive\b') { $estado = 'Active' }
  elseif ($linea -match '(?i)Never connected') { $estado = 'Never connected' }
  elseif ($linea -match '(?i)Disconnected') { $estado = 'Disconnected' }
  elseif ($linea -match '(?i)Pending') { $estado = 'Pending' }
  return @{ ok = ($estado -eq 'Active'); estado = $estado; detalle = $linea }
}

function Get-Invitado {
  if (-not (Get-VmEnMarcha $Vmx)) { return @{ ok = $false; skip = $true; detalle = 'VM apagada (no evaluable)' } }
  $txt = Invoke-Remote "powershell -NoProfile -ExecutionPolicy Bypass -File `"$RVerif`" -SinCampana" -PermitirFallo
  if (-not $txt) { return @{ ok = $false; detalle = 'sin respuesta por SSH' } }
  $kv = @{}
  foreach ($l in ($txt -split "`r?`n")) {
    if ($l -match '^([A-Z_]+)=(.*)$') { $kv[$Matches[1]] = $Matches[2].Trim() }
  }
  $kv['raw'] = $txt
  return @{ ok = $true; kv = $kv; detalle = 'verificar_windows ejecutado' }
}

# --- chivato por red (watch SIN SSH) ---------------------------------------
function Get-Heartbeat {
  # Lee las ultimas lineas del JSONL del sink y devuelve la ultima valida. Tolera una
  # escritura parcial (si la ultima linea no parsea, usa la anterior y lo anota).
  if (-not (Test-Path $Heartbeat)) { return @{ ok = $false; motivo = "sin $Heartbeat" } }
  $lineas = @()
  try { $lineas = @(Get-Content -LiteralPath $Heartbeat -Tail 40 -ErrorAction Stop) }
  catch { return @{ ok = $false; motivo = 'lectura fallida' } }
  $objs = @()
  $parcial = $false
  foreach ($l in $lineas) {
    if ([string]::IsNullOrWhiteSpace($l)) { continue }
    try { $o = $l | ConvertFrom-Json -ErrorAction Stop } catch { $parcial = $true; continue }
    if ($null -ne $o.seq) { $objs += $o }
  }
  if ($objs.Count -eq 0) { return @{ ok = $false; motivo = 'sin lineas validas' } }
  $last = $objs[-1]
  # `seq` monotono en la ventana leida (una edicion o un duplicado lo rompe).
  $seqOk = $true
  for ($i = 1; $i -lt $objs.Count; $i++) {
    try { if ([int]$objs[$i].seq -le [int]$objs[$i - 1].seq) { $seqOk = $false } }
    catch { $seqOk = $false }
  }
  $ref = $last.recv_utc
  if (-not $ref) { $ref = $last.ts_envio }
  if (-not $ref) { $ref = $last.ts_utc }
  $edad = -1
  try {
    $t = [datetime]::Parse([string]$ref).ToUniversalTime()
    $edad = [math]::Round(((Get-Date).ToUniversalTime() - $t).TotalMinutes, 1)
  } catch { }
  return @{ ok = $true; last = $last; seq_ok = $seqOk; edad_min = $edad; n = $objs.Count; parcial = $parcial; motivo = '' }
}

function Get-Ventana {
  # G-3 (T2b-1b): `-T0/-T1` MANDAN si llegan; si no, se lee `ventana_actual.json`
  # (lo escribe `arm`). Antes el fichero pisaba a los parametros y un `watch` con
  # `-T0/-T1` nuevos seguia evaluando la ventana vieja.
  $r = @{ fecha = ''; t0 = ''; t1 = ''; fuente = 'sin ventana' }
  if (Test-Path $VentanaFile) {
    try {
      $j = Get-Content -Raw $VentanaFile | ConvertFrom-Json
      $r.fecha = [string]$j.fecha; $r.t0 = [string]$j.t0; $r.t1 = [string]$j.t1
      $r.fuente = 'ventana_actual.json'
    } catch { }
  }
  if ($T0) {
    $r.t0 = $T0
    $r.fecha = ([datetime]$T0).ToUniversalTime().ToString('yyyy-MM-dd')
    $r.fuente = if ($r.fuente -eq 'ventana_actual.json') { 'parametros + ventana_actual.json' } else { 'parametros' }
  }
  if ($T1) { $r.t1 = $T1 }
  return $r
}

function Test-Sink {
  Log 'test-sink: inicio' | Out-Null
  # Puerto 9095 abierto + POST de prueba a `/test` (no contamina `heartbeat.jsonl`).
  # T2b-1b: POST con socket crudo y deadline propio. `Invoke-RestMethod` se colgo en
  # una prueba (posible resolucion de proxy) y bloqueaba `prep`; aqui no hay sorpresas.
  $c = New-Object System.Net.Sockets.TcpClient
  try {
    $iar = $c.BeginConnect($SinkBind, $SinkPort, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne(1500)) { return @{ ok = $false; motivo = "puerto $SinkPort cerrado" } }
    $c.EndConnect($iar)
    Log 'test-sink: conectado' | Out-Null
    $c.ReceiveTimeout = 4000
    $body = '{"prueba":"prep","ts_envio":"' + (Ts) + '"}'
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
    $head = "POST /test HTTP/1.1`r`nHost: ${SinkBind}:${SinkPort}`r`nContent-Type: application/json`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n"
    $hb = [System.Text.Encoding]::ASCII.GetBytes($head)
    $st = $c.GetStream()
    $st.Write($hb, 0, $hb.Length)
    $st.Write($bytes, 0, $bytes.Length)
    $st.Flush()
    Log 'test-sink: escrito' | Out-Null
    $buf = New-Object byte[] 4096
    $sb = New-Object System.Text.StringBuilder
    $deadline = (Get-Date).AddSeconds(5)
    while ((Get-Date) -lt $deadline) {
      if ($c.Available -le 0) { Start-Sleep -Milliseconds 50; continue }
      $n = $st.Read($buf, 0, $buf.Length)
      if ($n -le 0) { break }
      [void]$sb.Append([System.Text.Encoding]::UTF8.GetString($buf, 0, $n))
      if ($sb.ToString() -match '"ok"\s*:\s*true') { break }
    }
    $txt = $sb.ToString()
    Log ('test-sink: leido len=' + $txt.Length) | Out-Null
    if ($txt -match '\b200\b' -and $txt -match '"ok"\s*:\s*true') {
      return @{ ok = $true; motivo = ("POST /test ok len=" + $bytes.Length) }
    }
    $primera = (($txt -split "`r?`n") | Select-Object -First 1)
    return @{ ok = $false; motivo = ("POST /test sin ok (resp=" + $primera + ")") }
  } catch { return @{ ok = $false; motivo = ("POST /test: " + $_.Exception.Message) } } finally { $c.Close() }
}

function Invoke-SinkCtl([string]$Action) {
  # OJO (medido en T2b-1b): NO se captura la salida con `|` ni con `*>`: el sink
  # (`Start-Process` del ctl) hereda el handle y el padre esperaria para siempre.
  # El ctl ya escribe su propio log (`heartbeat_sink_ctl.log`); aqui solo importa el rc.
  if (-not (Test-Path $SinkCtl)) { return @{ rc = 2; out = "FALTA $SinkCtl" } }
  & powershell -NoProfile -ExecutionPolicy Bypass -File $SinkCtl -Action $Action -OutDir $SinkOutDir
  return @{ rc = $LASTEXITCODE; out = "(ver heartbeat_sink_ctl.log)" }
}

function Stop-Sink {
  $r = Invoke-SinkCtl 'stop'
  Log ("sink: " + $r.out)
}

function Test-PuertoSink {
  # Puerto TCP del sink (sin POST). Distingue "cerrado" de "ocupado por otro".
  $c = New-Object System.Net.Sockets.TcpClient
  try {
    $iar = $c.BeginConnect($SinkBind, $SinkPort, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne(1200)) { return $false }
    $c.EndConnect($iar)
    return $true
  } catch { return $false } finally { $c.Close() }
}

function Start-Sink {
  # G-4: MISMO `-OutDir` que el controlador (por defecto `legit/evidencia`).
  # T2b-1b: se arranca el sink DIRECTAMENTE (sin un powershell ctl intermedio). El ctl
  # lanzaba python con `Start-Process` y, al invocarlo desde el controlador, el `&`
  # esperaba a que python cerrase el stdout heredado (colgon medido). Aqui `Start-Process`
  # devuelve y el controlador sigue.
  $sinkPy = Join-Path $Win 'legit\heartbeat_sink.py'
  if (-not (Test-Path $sinkPy)) { Log "sink: FALTA $sinkPy" | Out-Null; return $false }
  New-Item -ItemType Directory -Force -Path $SinkOutDir | Out-Null
  $out = Join-Path $SinkOutDir 'heartbeat.jsonl'
  $log = Join-Path $SinkOutDir 'heartbeat_sink.log'
  $stdout = Join-Path $SinkOutDir 'heartbeat_sink.stdout.log'
  $stderr = Join-Path $SinkOutDir 'heartbeat_sink.stderr.log'
  $stdin = Join-Path $SinkOutDir 'heartbeat_sink.stdin.log'
  if (-not (Test-Path $stdin)) { New-Item -ItemType File -Force -Path $stdin | Out-Null }
  $arg = @($sinkPy, '--bind', $SinkBind, '--port', [string]$SinkPort, '--out', $out, '--log', $log)
  $p = Start-Process -FilePath $Py -ArgumentList $arg -PassThru -WindowStyle Hidden `
    -RedirectStandardInput $stdin -RedirectStandardOutput $stdout -RedirectStandardError $stderr
  Set-Content -Path (Join-Path $SinkOutDir 'heartbeat_sink.pid') -Value ([string]$p.Id) -Encoding ascii
  Start-Sleep -Milliseconds 1500
  if ($p.HasExited) { Log "sink: FALLO rc=$($p.ExitCode) (ver $stderr)" | Out-Null; return $false }
  if (-not (Test-PuertoSink)) { Log "sink: FALLO no responde en $SinkBind`:$SinkPort" | Out-Null; return $false }
  Log "sink: SINK_ARRANCADO pid=$($p.Id) out=$out" | Out-Null
  return $true
}

function Reset-Heartbeat {
  # F-1.2: una ventana nueva NO puede heredar el `seq` de la anterior (una bajada
  # legitima de `seq` se veria como `ROTA_SEQ`). Se archiva el JSONL del host y el
  # `heartbeat.seq` del invitado; el sink se reinicia para re-sembrar la cadena.
  # T2b-1b: tambien se archiva `ventana_actual.json` de la ventana ANTERIOR. Si no, el
  # `G-W7` de este `prep` se evaluaria contra una ventana caducada (y `arm` la reescribe
  # de inmediato). `crudo`/`stop`/`cleanup` sin ventana se declaran (no se inventan).
  $hist = Join-Path (Split-Path -Parent $Heartbeat) 'historico'
  New-Item -ItemType Directory -Force -Path $hist | Out-Null
  $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
  if (Test-Path $Heartbeat) {
    $dst = Join-Path $hist ("heartbeat_" + $stamp + ".jsonl")
    try {
      Move-Item -LiteralPath $Heartbeat -Destination $dst -Force
      Log "prep: heartbeat.jsonl anterior archivado -> $dst"
    } catch { Log "prep AVISO: no se pudo archivar $Heartbeat ($($_.Exception.Message))" }
  }
  if (Test-Path ($Heartbeat + '.1')) {
    Move-Item -LiteralPath ($Heartbeat + '.1') -Destination (Join-Path $hist ("heartbeat_" + $stamp + ".1.jsonl")) -Force -ErrorAction SilentlyContinue
  }
  if (Test-Path $VentanaFile) {
    $dstV = Join-Path $hist ("ventana_actual_" + $stamp + ".json")
    try {
      Move-Item -LiteralPath $VentanaFile -Destination $dstV -Force
      Log "prep: ventana_actual.json anterior archivado -> $dstV"
    } catch { Log "prep AVISO: no se pudo archivar $VentanaFile ($($_.Exception.Message))" }
  }
}

function Test-GateDefensorSesion([string]$texto, [string]$cuando) {
  # G-1: `prep` debe exigir `DEFENDER_OFF=1` y `SESION_ANGEL=1`. Devuelve $null si el
  # script desplegado aun no publica esas lineas (snapshot v1 con el verificador
  # antiguo): en ese caso la puerta se evalua DESPUES del deploy (script nuevo).
  if (-not $texto) {
    Log "prep: gate Defender/sesion NO EVALUABLE en $cuando (sin salida de verificar_windows.ps1)" | Out-Null
    return $null
  }
  $def = if ($texto -match 'DEFENDER_OFF=(\d)') { $Matches[1] } else { '' }
  $ses = if ($texto -match 'SESION_ANGEL=(\d)') { $Matches[1] } else { '' }
  if ($def -eq '' -or $ses -eq '') {
    Log "prep: gate Defender/sesion NO EVALUABLE en $cuando (DEFENDER_OFF='$def' SESION_ANGEL='$ses'; verificador sin esas lineas)" | Out-Null
    return $null
  }
  return @{ def = $def; ses = $ses; ok = ($def -eq '1' -and $ses -eq '1') }
}

function Get-CrudoDest {
  # G-5: ruta alineada con el plan (7.2 C-4): `D:\TFG-VMs\legitimo-windows-<fecha>\crudo\`.
  $vent = Get-Ventana
  if (-not $vent.fecha) { return '' }
  return (Join-Path $CrudoBase ("legitimo-windows-" + $vent.fecha + "\crudo"))
}

function Wait-KeepaliveSalida([int]$MaxSeg = 360) {
  # Espera a que el bucle `-Loop` desaparezca del invitado (parada ordenada <= 5 min).
  # Se usa el estado de la TAREA (`Running` -> `Ready`): `schtasks` no necesita comillas
  # anidadas (la consulta por `CommandLine` por SSH es fragil en cmd).
  $t = 0
  while ($t -lt $MaxSeg) {
    $q = Invoke-Remote 'schtasks /query /tn TFG-WinLegit-Keepalive /fo LIST' -PermitirFallo
    if ($q -match '(?i)Status:\s*Ready') { return $true }
    Start-Sleep -Seconds 15
    $t += 15
  }
  return $false
}

function Set-StopFlag([bool]$Crear) {
  if ($Crear) {
    Invoke-Remote 'type nul > C:\Users\angel\ghosts-client\stop.flag' -PermitirFallo | Out-Null
  } else {
    Invoke-Remote 'del /f /q C:\Users\angel\ghosts-client\stop.flag' -PermitirFallo | Out-Null
  }
}

# --- guardarrailes ----------------------------------------------------------
function Test-GW1 {
  $t = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like 'TFG-Baseline-*' })
  $malas = @($t | Where-Object { $_.State -ne 'Disabled' })
  if ($malas.Count -eq 0) { return @{ ok = $true; detalle = "TFG-Baseline-* activas=0 (total=$($t.Count))" } }
  return @{ ok = $false; detalle = ("activas: " + (($malas | ForEach-Object { $_.TaskName }) -join ',')) }
}

function Test-GW2 {
  $s = Get-Snapshots $Vmx
  $tiene = $s -contains $Snap
  $faltan = @($SnapsPrevios | Where-Object { $s -notcontains $_ })
  if ($tiene -and $faltan.Count -eq 0) { return @{ ok = $true; detalle = "snapshots=$($s.Count) (incluye $Snap)" } }
  $msg = "snapshot=$Snap presente=$tiene"
  if ($faltan.Count -gt 0) { $msg += "; faltan=" + ($faltan -join ',') }
  return @{ ok = $false; detalle = $msg }
}

function Test-GW3 {
  $gb = 0
  try { $gb = [math]::Round((Get-PSDrive D).Free / 1GB, 1) } catch { }
  return @{ ok = ($gb -ge $DiskHostMinGb); detalle = "D_libre_gb=$gb min=$DiskHostMinGb" }
}

function Test-GW4 {
  $chk = (& $Py (Join-Path $Repo '_artefactos\scripts\construir_receta_legitima_windows.py') --check 2>&1 | Out-String)
  $esp = (& $Py (Join-Path $Repo '_artefactos\scripts\verificar_espejo.py') 2>&1 | Out-String)
  $okChk = ($chk -match 'PASA|RESULT=PASS')
  $okEsp = ($esp -match 'PASA|504\s*=\s*504')
  $sha = @{}
  foreach ($d in 1..3) {
    $sha[$d] = (Get-FileHash (Join-Path $Recetas "w$d.json") -Algorithm SHA256).Hash.ToLower().Substring(0, 12)
  }
  return @{ ok = ($okChk -and $okEsp); detalle = "check=$okChk espejo=$okEsp sha=$($sha[1])/$($sha[2])/$($sha[3])" }
}

function Test-GW5 {
  if ($script:UsarLatido) {
    # v4: servicios del invitado desde el LATIDO (el watch no abre SSH).
    $hb = Get-Heartbeat
    if (-not $hb.ok) {
      return @{ ok = $false; skip = (-not (Get-VmEnMarcha $Vmx)); detalle = "latido: $($hb.motivo)" }
    }
    $svc = (([string]$hb.last.sysmon) -eq 'Running') -and (([string]$hb.last.wazuh) -eq 'Running')
    if (-not $svc) {
      return @{ ok = $false; detalle = "servicios_latido=False (sysmon=$($hb.last.sysmon) wazuh=$($hb.last.wazuh))" }
    }
    $mgr = Get-ManagerEstado
    if ($mgr.skip) {
      return @{ ok = $true; skip = $true; detalle = "servicios_latido=True; manager=SKIP ($($mgr.detalle))" }
    }
    $ag = Get-Agente002
    if (-not $ag.ok) {
      return @{ ok = $false; detalle = "servicios_latido=True manager_active=$($mgr.activo) daemons=$($mgr.daemons) agente_002=$($ag.estado) [$($ag.detalle)]" }
    }
    return @{ ok = ($mgr.activo -and $mgr.daemons -ge 2 -and $ag.ok); detalle = "servicios_latido=True manager_active=$($mgr.activo) daemons=$($mgr.daemons) agente_002=$($ag.estado)" }
  }
  $g = Get-Invitado
  if (-not $g.ok) { return @{ ok = $false; skip = $g.skip; detalle = $g.detalle } }
  $svc = ($g.kv['raw'] -match 'CHECK svc_Sysmon64\s+OK') -and ($g.kv['raw'] -match 'CHECK svc_WazuhSvc\s+OK')
  # F2: un fallo de servicios del invitado NUNCA puede salir SKIP. El SKIP es SOLO
  # por la parte del manager (apagado a proposito fuera de WE0).
  if (-not $svc) {
    return @{ ok = $false; detalle = 'servicios_invitado=False (Sysmon64/WazuhSvc)' }
  }
  $mgr = Get-ManagerEstado
  if ($mgr.skip) {
    return @{ ok = $true; skip = $true; detalle = "servicios_invitado=True; manager=SKIP ($($mgr.detalle))" }
  }
  # F7 (WE0-1): el agente 002 tiene que estar `Active`. Un fallo del agente NUNCA es SKIP:
  # el SKIP queda reservado al manager apagado (linea anterior).
  $ag = Get-Agente002
  if (-not $ag.ok) {
    return @{ ok = $false; detalle = "servicios_invitado=True manager_active=$($mgr.activo) daemons=$($mgr.daemons) agente_002=$($ag.estado) [$($ag.detalle)]" }
  }
  return @{ ok = ($mgr.activo -and $mgr.daemons -ge 2 -and $ag.ok); detalle = "servicios_invitado=True manager_active=$($mgr.activo) daemons=$($mgr.daemons) agente_002=$($ag.estado)" }
}

function Test-GW6 {
  $g = Get-Invitado
  if (-not $g.ok) { return @{ ok = $false; skip = $g.skip; detalle = $g.detalle } }
  $hostsOk = ($g.kv['raw'] -match 'CHECK hosts_intranet\s+OK')
  # F5: no se asume `192.168.65.x`. Vale CUALQUIER ruta por defecto. Se pregunta a
  # `Get-NetRoute` (vacio = sin ruta) y, si no esta disponible, se cae al texto de
  # `route print` con la regex generica `0.0.0.0 0.0.0.0 <gateway>`.
  $nRutas = -1
  $cnt = Invoke-Remote 'powershell -NoProfile -Command "@(Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue).Count"' -PermitirFallo
  if ($cnt -match '^\s*(\d+)\s*$') { $nRutas = [int]$Matches[1] }
  if ($nRutas -ge 0) {
    $sinDefecto = ($nRutas -eq 0)
    $fuente = "Get-NetRoute=$nRutas"
  } else {
    $ruta = Invoke-Remote 'route print 0.0.0.0' -PermitirFallo
    $sinDefecto = -not ($ruta -match '0\.0\.0\.0\s+0\.0\.0\.0\s+\S+')
    $fuente = 'route_print'
  }
  $linuxOff = -not (Get-VmEnMarcha $VmxLinux)
  return @{ ok = ($hostsOk -and $sinDefecto -and $linuxOff); detalle = "hosts=$hostsOk sin_ruta_defecto=$sinDefecto ($fuente) victima_linux_off=$linuxOff" }
}

function Test-GW7 {
  $mgr = Get-ManagerEstado
  if ($mgr.skip) { return @{ ok = $true; skip = $true; detalle = $mgr.detalle } }
  $logall = $mgr.logall
  # F6: manda la VENTANA, no la fase. Espejo de `legitimo_host_control.ps1:510-518`.
  #   now dentro de [t0,t1] -> `yes`; now fuera -> `no`; sin t0/t1 -> SKIP declarado.
  # G-3 (T2b-1b): si no llegan `-T0/-T1`, se lee `ventana_actual.json` (lo escribe
  # `arm`). Asi el `watch`/`cleanup` de la ventana real no se queda en SKIP.
  $vent = Get-Ventana
  $t0s = $vent.t0
  $t1s = $vent.t1
  if ([string]::IsNullOrWhiteSpace($t0s) -or [string]::IsNullOrWhiteSpace($t1s)) {
    return @{ ok = $true; skip = $true; detalle = "sin -T0/-T1 ni ventana_actual.json (no evaluable); logall_json=$logall" }
  }
  try {
    $t0 = [datetime]::Parse($t0s).ToUniversalTime()
    $t1 = [datetime]::Parse($t1s).ToUniversalTime()
  } catch {
    return @{ ok = $false; detalle = "t0/t1 no parseables ('$t0s' / '$t1s'; fuente=$($vent.fuente))" }
  }
  $now = (Get-Date).ToUniversalTime()
  if ($now -ge $t0 -and $now -le $t1) {
    return @{ ok = ($logall -eq 'yes'); detalle = "logall_json=$logall (now dentro de [t0,t1] exige yes; fuente=$($vent.fuente))" }
  }
  return @{ ok = ($logall -eq 'no'); detalle = "logall_json=$logall (now fuera de [t0,t1] exige no; fuente=$($vent.fuente))" }
}

function Test-GW8 {
  if ($script:UsarLatido) {
    $hb = Get-Heartbeat
    if (-not $hb.ok) {
      return @{ ok = $false; skip = (-not (Get-VmEnMarcha $Vmx)); detalle = "latido: $($hb.motivo)" }
    }
    $n = -1
    if ($null -ne $hb.last.hijos_vmtoolsd) { $n = [int]$hb.last.hijos_vmtoolsd }
    return @{ ok = ($n -eq 0); detalle = "hijos_vmtoolsd=$n (latido)" }
  }
  $g = Get-Invitado
  if (-not $g.ok) { return @{ ok = $false; skip = $g.skip; detalle = $g.detalle } }
  $m = [regex]::Match($g.kv['raw'], 'HIJOS_VMTOOLSD=(\d+)')
  $n = if ($m.Success) { [int]$m.Groups[1].Value } else { -1 }
  return @{ ok = ($n -eq 0); detalle = "hijos_vmtoolsd=$n (0 = sin acceso del operador)" }
}

function Test-GW9 {
  if ($script:UsarLatido) {
    $hb = Get-Heartbeat
    if (-not $hb.ok) {
      return @{ ok = $false; skip = (-not (Get-VmEnMarcha $Vmx)); detalle = "latido: $($hb.motivo)" }
    }
    $ok = ([string]$hb.last.powercfg_ok -eq 'True')
    return @{ ok = $ok; detalle = "powercfg_ok=$($hb.last.powercfg_ok) (latido)" }
  }
  $g = Get-Invitado
  if (-not $g.ok) { return @{ ok = $false; skip = $g.skip; detalle = $g.detalle } }
  $ok = ($g.kv['raw'] -match 'CHECK powercfg_STANDBYIDLE\s+OK') -and
        ($g.kv['raw'] -match 'CHECK powercfg_HIBERNATEIDLE\s+OK') -and
        ($g.kv['raw'] -match 'CHECK powercfg_HYBRIDSLEEP\s+OK')
  return @{ ok = $ok; detalle = "powercfg 3/3 = $ok" }
}

function Test-GW10 {
  if ($script:UsarLatido) {
    $hb = Get-Heartbeat
    if (-not $hb.ok) {
      return @{ ok = $false; skip = (-not (Get-VmEnMarcha $Vmx)); detalle = "latido: $($hb.motivo)" }
    }
    $mb = -1
    if ($null -ne $hb.last.disco_mb) { $mb = [int]$hb.last.disco_mb }
    return @{ ok = ($mb -ge $DiskGuestMinMb); detalle = "disco_invitado_mb=$mb min=$DiskGuestMinMb (latido; keepalive exige 500)" }
  }
  $g = Get-Invitado
  if (-not $g.ok) { return @{ ok = $false; skip = $g.skip; detalle = $g.detalle } }
  $m = [regex]::Match($g.kv['raw'], 'CHECK disco_libre_mb\s+OK\s+(\d+) MB')
  $mb = if ($m.Success) { [int]$m.Groups[1].Value } else { -1 }
  return @{ ok = ($mb -ge $DiskGuestMinMb); detalle = "disco_invitado_mb=$mb min=$DiskGuestMinMb (keepalive exige 500)" }
}

function Get-FlagArmado {
  # `armado.flag` es la marca de ventana armada. Sin ella (prep/drytest) G-W11 no
  # es evaluable: fuera de ventana el cliente NO debe estar corriendo.
  $out = Invoke-Remote 'if exist C:\Users\angel\ghosts-client\armado.flag (echo FLAG_SI) else (echo FLAG_NO)' -PermitirFallo
  if ($out -match 'FLAG_SI') { return $true }
  if ($out -match 'FLAG_NO') { return $false }
  return $null
}

function Test-GW11 {
  if ($script:UsarLatido) {
    $hb = Get-Heartbeat
    if (-not $hb.ok) {
      return @{ ok = $false; skip = (-not (Get-VmEnMarcha $Vmx)); detalle = "latido: $($hb.motivo)" }
    }
    if (-not [bool]$hb.last.armado) {
      return @{ ok = $true; skip = $true; detalle = 'sin armado (latido)' }
    }
    $n = -1
    if ($null -ne $hb.last.n_ghosts) { $n = [int]$hb.last.n_ghosts }
    $usr = [string]$hb.last.win_user
    $usrOk = ($usr -match '(?i)(^|\\)angel$')
    return @{ ok = ($n -eq 1 -and $usrOk); detalle = "n_ghosts=$n (latido) win_user=$usr dueno_angel=$usrOk" }
  }
  $g = Get-Invitado
  if (-not $g.ok) { return @{ ok = $false; skip = $g.skip; detalle = $g.detalle } }
  $flag = Get-FlagArmado
  if ($flag -ne $true) {
    if ($flag -eq $false) { return @{ ok = $true; skip = $true; detalle = 'sin armado.flag (fuera de ventana)' } }
    return @{ ok = $false; detalle = 'no se pudo leer armado.flag' }
  }
  $m = [regex]::Match($g.kv['raw'], 'CLIENTE_VIVO=(\w+) PID=(\d+) WIN_USER=(\S*)')
  $vivo = $m.Success -and ($m.Groups[1].Value -eq 'True')
  $usr = if ($m.Success) { $m.Groups[3].Value } else { '' }
  $usrOk = ($usr -match '(?i)(^|\\)angel$')
  # `tasklist` devuelve una linea por proceso; se cuenta por lineas no vacias.
  $lineas = @((Invoke-Remote 'tasklist /nh | findstr /i ghosts.exe' -PermitirFallo) -split "`r?`n" | Where-Object { $_.Trim() })
  # CA-W6: EXACTAMENTE 1 cliente vivo y su dueno real es `angel`.
  return @{ ok = ($vivo -and $lineas.Count -eq 1 -and $usrOk); detalle = "procesos_ghosts=$($lineas.Count) vivo=$vivo win_user=$usr dueno_angel=$usrOk" }
}

function Test-GW12 {
  $libre = 0
  try {
    $os = Get-CimInstance Win32_OperatingSystem
    $libre = [math]::Round($os.FreePhysicalMemory / 1024)
  } catch { }
  $wu = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
  $wuTxt = 'AUSENTE'
  if ($wu) { $wuTxt = "$($wu.Status)/$($wu.StartType)" }
  $wuOk = (-not $wu) -or ($wu.Status -ne 'Running')
  return @{ ok = ($libre -ge $RamMinMb -and $wuOk); detalle = "ram_libre_mb=$libre min=$RamMinMb wu=$wuTxt" }
}

function Test-GW13 {
  # CA-W3b-12b: el latido es la senal de vida. Frescura <= 12 min, `seq` monotono y
  # exactamente 1 instancia del bucle. Sin VM encendida no es evaluable (drytest VM off).
  if (-not (Get-VmEnMarcha $Vmx)) {
    return @{ ok = $true; skip = $true; detalle = 'VM apagada (no evaluable)' }
  }
  $hb = Get-Heartbeat
  if (-not $hb.ok) {
    return @{ ok = $false; detalle = "sin latido ($($hb.motivo))" }
  }
  $edad = $hb.edad_min
  $inst = -1
  if ($null -ne $hb.last.ka_instancias) { $inst = [int]$hb.last.ka_instancias }
  $fresco = ($edad -ge 0 -and $edad -le $HbMaxMin)
  $ok = ($fresco -and $hb.seq_ok -and ($inst -eq 1))
  return @{ ok = $ok; detalle = "HB_EDAD_MIN=$edad max=$HbMaxMin seq_monotono=$($hb.seq_ok) ka_instancias=$inst seq=$($hb.last.seq) ka_pid=$($hb.last.ka_pid) parcial=$($hb.parcial)" }
}

function Test-GW14 {
  # NUEVO (T2b-1b): el `watch` MIRA el campo `defender` del latido y ALARMA si esta ON.
  # Solo lee el JSONL del host: no entra en la VM. `off` = control ambiental OK,
  # `on` = FALLO (Defender reactivado, R4), `?` = no evaluable (SKIP declarado).
  $hb = Get-Heartbeat
  if (-not $hb.ok) { return @{ ok = $false; skip = $true; detalle = "sin latido ($($hb.motivo))" } }
  $def = ([string]$hb.last.defender).Trim().ToLower()
  if ($def -eq 'on') {
    return @{ ok = $false; detalle = 'DEFENDER=ON en el latido (control ambiental roto: R4)' }
  }
  if ($def -eq 'off') { return @{ ok = $true; detalle = 'defender=off (latido)' } }
  return @{ ok = $true; skip = $true; detalle = "defender='$def' no evaluable (latido)" }
}

$Guardarrailes = [ordered]@{
  'G-W1'  = 'Test-GW1'
  'G-W2'  = 'Test-GW2'
  'G-W3'  = 'Test-GW3'
  'G-W4'  = 'Test-GW4'
  'G-W5'  = 'Test-GW5'
  'G-W6'  = 'Test-GW6'
  'G-W7'  = 'Test-GW7'
  'G-W8'  = 'Test-GW8'
  'G-W9'  = 'Test-GW9'
  'G-W10' = 'Test-GW10'
  'G-W11' = 'Test-GW11'
  'G-W12' = 'Test-GW12'
  'G-W13' = 'Test-GW13'
  'G-W14' = 'Test-GW14'
}

# Que guardarrailes aplican a cada fase (los demas no se evaluan en esa fase).
# `arm` NO evalua G-W7: es la TRANSICION (antes `no`, despues `yes`). Con G-W7 dentro,
# un 2.o `arm` (reintento idempotente, C-3) se abortaria por exigir `no` fuera de la
# ventana aunque el 1.o acabe de poner `yes`. `arm` verifica el estado antes y despues
# de forma explicita (logall_json=yes) y NO ejecuta `on` si ya estaba.
$Aplican = @{
  prep    = @('G-W1', 'G-W2', 'G-W3', 'G-W4', 'G-W5', 'G-W6', 'G-W7', 'G-W9', 'G-W10', 'G-W12')
  arm     = @('G-W1', 'G-W2', 'G-W4', 'G-W5', 'G-W6', 'G-W9', 'G-W10', 'G-W11', 'G-W12')
  watch   = @('G-W5', 'G-W7', 'G-W8', 'G-W9', 'G-W10', 'G-W11', 'G-W12', 'G-W13', 'G-W14')
  stop    = @('G-W5', 'G-W10')
  cleanup = @('G-W1', 'G-W2', 'G-W3', 'G-W7', 'G-W12')
  status  = @('G-W1', 'G-W2', 'G-W3', 'G-W4', 'G-W5', 'G-W6', 'G-W7', 'G-W8', 'G-W9', 'G-W10', 'G-W11', 'G-W12', 'G-W13', 'G-W14')
}

function Invoke-Guardarrailes([string]$Fase) {
  $res = @()
  foreach ($g in $Aplican[$Fase]) {
    $fn = $Guardarrailes[$g]
    $r = & $fn
    $estado = if ($r.skip) { 'SKIP' } elseif ($r.ok) { 'OK' } else { 'FALLO' }
    $res += @{ id = $g; estado = $estado; detalle = $r.detalle }
  }
  $fallos = @($res | Where-Object { $_.estado -eq 'FALLO' })
  $skips = @($res | Where-Object { $_.estado -eq 'SKIP' })
  return @{ res = $res; fallos = $fallos; skips = $skips }
}

function Write-Guardarrailes($r) {
  foreach ($x in $r.res) { Write-Output ("  {0} {1} {2}" -f $x.id, $x.estado, $x.detalle) }
}

function Stop-Actividad {
  Invoke-Remote 'schtasks /end /tn TFG-WinLegit-Actividad' -PermitirFallo | Out-Null
  Invoke-Remote 'taskkill /f /im ghosts.exe' -PermitirFallo | Out-Null
  Invoke-Remote 'del /f /q C:\Users\angel\ghosts-client\armado.flag' -PermitirFallo | Out-Null
}

# --- fases -----------------------------------------------------------------
switch ($Phase) {

  'drytest' {
    $fases = if ($DryPhase) { @($DryPhase) } else { @('prep', 'arm', 'watch', 'stop', 'cleanup', 'status') }
    $vm = if (Get-VmEnMarcha $Vmx) { 'on' } else { 'off' }
    # D1: la salida del drytest se REGISTRA en `legit/evidencia/drytest.log` (versionable).
    # Antes solo iba a stdout y el log de control nunca se creaba.
    $salida = New-Object System.Collections.Generic.List[string]
    $salida.Add("=== DRYTEST $(Ts) host=$env:COMPUTERNAME vm_windows=$vm fases=$($fases -join ',') ===")
    $totalFallos = 0
    foreach ($f in $fases) {
      # v4: la fase `watch` se evalua con el LATIDO (0 sesiones SSH al invitado).
      $script:UsarLatido = ($f -eq 'watch')
      $script:SshInvitado = 0
      $salida.Add("DRYTEST FASE=$f")
      $r = Invoke-Guardarrailes $f
      foreach ($x in $r.res) { $salida.Add(("  {0} {1} {2}" -f $x.id, $x.estado, $x.detalle)) }
      if ($f -eq 'watch') { $salida.Add("  SSH_INVITADO=$($script:SshInvitado)") }
      $veredicto = if ($r.fallos.Count -gt 0) { 'FAIL' } elseif ($r.skips.Count -gt 0) { 'PASS_CON_SKIP' } else { 'PASS' }
      $salida.Add(("DRYTEST {0} {1} (ok={2} fallos={3} skip={4})" -f $f, $veredicto, ($r.res.Count - $r.fallos.Count - $r.skips.Count), $r.fallos.Count, $r.skips.Count))
      $totalFallos += $r.fallos.Count
    }
    $script:UsarLatido = $false
    $resultado = if ($totalFallos -eq 0) { 'DRYTEST_RESULT=PASS' } else { 'DRYTEST_RESULT=FAIL' }
    $salida.Add($resultado)
    foreach ($l in $salida) { Write-Output $l }
    Add-Content -Path $DryLogPath -Value ($salida -join [Environment]::NewLine) -Encoding utf8
    if ($totalFallos -eq 0) { exit 0 }
    exit 1
  }

  'prep' {
    # --- G-2 read-only: `prep -SoloListaNegra` (prueba negativa reproducible) ---
    if ($SoloListaNegra) {
      $verBl = Invoke-Remote "powershell -NoProfile -ExecutionPolicy Bypass -File `"$RVerif`" -SinCampana" -PermitirFallo
      Write-Output $verBl
      if ($verBl -notmatch 'LISTA_NEGRA_OK=1') {
        $malos = if ($verBl -match 'CHECK lista_negra\s+FALLO\s+(.+)') { $Matches[1].Trim() } else { 'no evaluable' }
        Log "prep -SoloListaNegra FALLO: lista negra 7.3 con residuos ($malos) -> exit 46"; exit 46
      }
      Log 'prep -SoloListaNegra OK: lista negra 7.3 sin residuos'
      exit 0
    }
    # --- G-1 (entrada): si la VM ya esta encendida, Defender y sesion se exigen YA ---
    # Permite abortar ANTES del revert (y hace testeable la puerta forzando Defender ON
    # o cerrando la sesion de `angel` en la VM viva).
    # T2b-1b: `-SimularVerificador <fichero>` inyecta la salida sin tocar la VM (solo
    # pruebas de la puerta `exit 47`; nunca se activa Defender para probar).
    $vEnt = ''
    if ($SimularVerificador) {
      if (Test-Path $SimularVerificador) { $vEnt = (Get-Content -Raw -LiteralPath $SimularVerificador) }
      if (-not $vEnt) { Log "prep FALLO: -SimularVerificador ilegible ($SimularVerificador)"; exit 49 }
      Log "prep: verificador SIMULADO desde $SimularVerificador (prueba G-1; NO se toca la VM)"
    } elseif (Get-VmEnMarcha $Vmx) {
      $vEnt = Invoke-Remote "powershell -NoProfile -ExecutionPolicy Bypass -File `"$RVerif`" -SinCampana" -PermitirFallo
    }
    $gateEnt = Test-GateDefensorSesion $vEnt 'entrada'
    if ($gateEnt -and -not $gateEnt.ok) {
      Log "prep FALLO: gate Defender/sesion en entrada (DEFENDER_OFF=$($gateEnt.def) SESION_ANGEL=$($gateEnt.ses)) -> exit 47"
      exit 47
    }
    # --- sink 9095: si esta ocupado por un proceso ajeno, exit 48 (sin fallback) ---
    if (Test-PuertoSink) {
      $s = Test-Sink
      if (-not $s.ok) {
        Log "prep FALLO: $SinkBind`:$SinkPort ocupado y /test no responde ($($s.motivo)) -> exit 48"
        exit 48
      }
      Stop-Sink
      if (Test-PuertoSink) { Log 'prep FALLO: no se pudo parar el sink -> exit 48'; exit 48 }
    }
    # F-1.2: ventana nueva => archivar latido anterior y re-sembrar el sink.
    Reset-Heartbeat
    if (-not (Start-Sink)) { Log 'prep FALLO: no se pudo arrancar el sink -> exit 48'; exit 48 }
    $sink = Test-Sink
    if (-not $sink.ok) {
      Log "prep FALLO: sink $SinkBind`:$SinkPort no operativo ($($sink.motivo)) -> exit 48 (sin fallback silencioso)"
      exit 48
    }
    Log "prep: sink OK ($($sink.motivo))"
    $r = Invoke-Guardarrailes 'prep'
    if ($r.fallos.Count -gt 0) { Log "prep ABORTADO por guardarrailes: $(($r.fallos | ForEach-Object { $_.id }) -join ',')"; exit 41 }
    Log 'prep: revert a snapshot y arranque'
    & $Vmrun -T ws revertToSnapshot $Vmx $Snap | Out-Null
    if ($LASTEXITCODE -ne 0) { Log 'prep FALLO: revertToSnapshot'; exit 42 }
    & $Vmrun -T ws start $Vmx nogui | Out-Null
    $ok = $false
    for ($i = 0; $i -lt 40; $i++) {
      $w = Invoke-Remote 'whoami' -PermitirFallo
      if ($w -match 'angel') { $ok = $true; break }
      Start-Sleep -Seconds 10
    }
    if (-not $ok) { Log 'prep FALLO: el invitado no responde por SSH'; exit 43 }
    # F-1.2: el `heartbeat.seq` del invitado tambien es de la ventana anterior.
    $seqArc = Invoke-Remote 'if exist C:\Users\angel\ghosts-client\heartbeat.seq (move /y C:\Users\angel\ghosts-client\heartbeat.seq C:\Users\angel\ghosts-client\heartbeat.seq.prev >nul 2>&1 & echo SEQ_ARCHIVADO) else (echo SEQ_AUSENTE)' -PermitirFallo
    Log ("prep: heartbeat.seq " + (($seqArc -replace '\s+', ' ').Trim()))
    Log 'prep: deploy idempotente'
    & powershell -NoProfile -ExecutionPolicy Bypass -File $Deploy -Phase apply
    if ($LASTEXITCODE -ne 0) { Log 'prep FALLO: deploy'; exit 44 }
    $r2 = Invoke-Guardarrailes 'prep'
    if ($r2.fallos.Count -gt 0) { Log "prep FALLO tras deploy: $(($r2.fallos | ForEach-Object { $_.id }) -join ',')"; exit 45 }
    # --- G-1 (post-deploy) + G-2 (lista negra) --------------------------------
    $ver = Invoke-Remote "powershell -NoProfile -ExecutionPolicy Bypass -File `"$RVerif`" -SinCampana" -PermitirFallo
    Write-Output $ver
    $gate = Test-GateDefensorSesion $ver 'post-deploy'
    if (-not $gate -or -not $gate.ok) {
      $d = if ($gate) { "DEFENDER_OFF=$($gate.def) SESION_ANGEL=$($gate.ses)" } else { 'no evaluable' }
      Log "prep FALLO: gate Defender/sesion ($d) -> exit 47"; exit 47
    }
    Log "prep: gate Defender/sesion OK (DEFENDER_OFF=$($gate.def) SESION_ANGEL=$($gate.ses))"
    if ($ver -notmatch 'LISTA_NEGRA_OK=1') {
      $malos = if ($ver -match 'CHECK lista_negra\s+FALLO\s+(.+)') { $Matches[1].Trim() } else { 'no evaluable' }
      Log "prep FALLO: lista negra 7.3 con residuos ($malos) -> exit 46"; exit 46
    }
    Log 'prep: lista negra 7.3 OK (0 residuos)'
    # Manifiesto esperado: T2b-2 lo sella con el deploy 8.3.1 (`manifiesto_esperado.json`).
    # Si existe, `prep` aborta con 46 cuando DIFIERE; si no, se declara SKIP (no se inventa).
    if (Test-Path $ManEsp) {
      $esp = (Get-Content -Raw $ManEsp | ConvertFrom-Json).MANIFEST_SHA256
      $man = Invoke-Remote "powershell -NoProfile -ExecutionPolicy Bypass -File `"$RVerif`" -Manifiesto" -PermitirFallo
      $act = if ($man -match 'MANIFEST_SHA256=([0-9a-f]+)') { $Matches[1] } else { '' }
      if (-not $esp -or $act -ne $esp) {
        Log "prep FALLO: manifiesto DIFIERE (esperado=$esp actual=$act) -> exit 46"; exit 46
      }
      Log "prep: manifiesto OK ($act)"
    } else {
      Log "prep: manifiesto SKIP (sin $ManEsp; se sella en T2b-2 con el deploy 8.3.1)"
    }
    Log 'prep OK (NO armado)'
  }

  'arm' {
    if (-not $T0) { Log 'arm FALLO: falta -T0 (AAAA-MM-DDThh:mm:ssZ)'; exit 50 }
    if (-not $T1) { Log 'arm AVISO: sin -T1; G-W7 no es evaluable (SKIP). Pasa -T0 y -T1 para verificar la ventana.' }
    $r = Invoke-Guardarrailes 'arm'
    if ($r.fallos.Count -gt 0) { Log "arm ABORTADO: $(($r.fallos | ForEach-Object { $_.id }) -join ',')"; exit 51 }
    $fecha = ([datetime]$T0).ToUniversalTime().ToString('yyyy-MM-dd')
    Log "arm: fijando mapa de dias con --t0 $fecha"
    & $Py (Join-Path $Repo '_artefactos\scripts\construir_receta_legitima_windows.py') --t0 $fecha | Out-Null
    if ($LASTEXITCODE -ne 0) { Log 'arm FALLO: generador --t0'; exit 52 }
    # G-8: `deploy` es idempotente y, con el MISMO `MANIFEST_SHA256`, NO re-sube el
    # payload ni re-registra tareas (solo aplica lo que falte). Se captura la salida
    # para saber si hubo despliegue real.
    $dep = & powershell -NoProfile -ExecutionPolicy Bypass -File $Deploy -Phase apply 2>&1 | Out-String
    Write-Output $dep
    if ($LASTEXITCODE -ne 0) { Log 'arm FALLO: re-deploy con mapa'; exit 53 }
    $deploySkip = ($dep -match 'DEPLOY_SKIP=1')
    if ($deploySkip) {
      # F-1/G-8: mismo payload y mismo `MANIFEST_SHA256` => NO se ha re-subido el
      # payload ni se han re-registrado tareas. Solo se asegura de que el bucle vive.
      Log 'arm: G-8 deploy SKIP (payload y MANIFEST_SHA256 ya coinciden; no se re-sube ni se re-registran tareas)'
      $kaQ = Invoke-Remote 'schtasks /query /tn TFG-WinLegit-Keepalive /fo LIST' -PermitirFallo
      if ($kaQ -notmatch '(?i)Status:\s*Running') {
        Invoke-Remote 'schtasks /run /tn TFG-WinLegit-Keepalive' -PermitirFallo | Out-Null
        Log 'arm: bucle keepalive no estaba Running -> relanzado (sin re-desplegar)'
      }
    }
    Invoke-Remote 'type nul > C:\Users\angel\ghosts-client\armado.flag' | Out-Null
    if ($deploySkip) {
      # 2.o `arm`: no se relanza el cliente si ya esta vivo (no se duplica actividad).
      $vivo = Invoke-Remote 'tasklist /nh | findstr /i ghosts.exe' -PermitirFallo
      if ($vivo -match 'ghosts\.exe') {
        Log 'arm: deploy SKIP y cliente ya vivo -> NO se relanza la actividad'
      } else {
        Invoke-Remote 'schtasks /run /tn TFG-WinLegit-Actividad' | Out-Null
        Log 'arm: deploy SKIP y cliente parado -> actividad arrancada'
      }
    } else {
      Invoke-Remote 'schtasks /run /tn TFG-WinLegit-Actividad' | Out-Null
    }
    # F3: MISMA credencial que `Get-ManagerEstado` (clave del laboratorio Linux, no la
    # del invitado Windows) y verificacion REAL: no se registra "ON" sin comprobarlo.
    # C-3 (v4): `arm` es IDEMPOTENTE. `logall_json_ctl.sh on` hace `rm -f archives.json`
    # ANTES de reiniciar: un 2.o `arm` destruiria el archivo del dia. Si ya esta `yes`,
    # NO se ejecuta `on`; se verifica el estado antes y despues.
    $mgrAntes = Get-ManagerEstado
    if ($mgrAntes.skip) {
      Log "arm FALLO: manager inaccesible o sin TFG_MANAGER_PW (R21): $($mgrAntes.detalle)"; exit 54
    }
    $yaOn = ($mgrAntes.logall -eq 'yes')
    if ($yaOn) {
      Log 'arm: logall_json ya estaba yes -> NO se ejecuta on (archives.json intacto)'
    } else {
      Push-ManagerScript | Out-Null
      $on = Invoke-Manager "bash $MgrScript on"
      if (-not $on) { Log 'arm FALLO: no se pudo ejecutar logall_json on (manager inaccesible o sin credencial)'; exit 54 }
    }
    $mgr = Get-ManagerEstado
    if ($mgr.skip -or $mgr.logall -ne 'yes') {
      Log "arm FALLO: logall_json NO verificado tras arm (logall=$($mgr.logall); $($mgr.detalle))"
      exit 55
    }
    $vent = [ordered]@{
      t0          = ([datetime]$T0).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
      t1          = $(if ($T1) { ([datetime]$T1).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
      fecha       = $fecha
      armado_utc  = (Ts)
      logall_antes = [string]$mgrAntes.logall
      on_ejecutado = (-not $yaOn)
    }
    ($vent | ConvertTo-Json) | Set-Content -Path $VentanaFile -Encoding utf8
    Log "arm: logall_json ON verificado (antes=$($mgrAntes.logall) on_ejecutado=$(-not $yaOn) manager_active=$($mgr.activo) daemons=$($mgr.daemons))"
    Log "arm: ventana_actual.json escrito ($VentanaFile)"
    Log 'arm OK'
  }

  'watch' {
    # v4 / C-1: el watch NO abre SSH contra el invitado. Todo lo del invitado sale del
    # `heartbeat.jsonl` que escribe el sink en el host (G-W5/G-W8/G-W9/G-W10/G-W11/G-W13).
    $script:UsarLatido = $true
    $script:SshInvitado = 0
    $r = Invoke-Guardarrailes 'watch'
    $linea = "chequeo ok=$($r.res.Count - $r.fallos.Count - $r.skips.Count) fallos=$($r.fallos.Count) skip=$($r.skips.Count)"
    if ($r.fallos.Count -gt 0) {
      $linea = "ALARMA $linea :: " + (($r.fallos | ForEach-Object { "$($_.id)=$($_.detalle)" }) -join ' | ')
    }
    $hb = Get-Heartbeat
    if ($hb.ok) {
      $linea += " :: HB_EDAD_MIN=$($hb.edad_min) SEQ=$($hb.last.seq) KA_PID=$($hb.last.ka_pid) KA_INSTANCIAS=$($hb.last.ka_instancias)"
    } else {
      $linea += " :: HB_EDAD_MIN=n/a ($($hb.motivo))"
    }
    $linea += " SSH_INVITADO=$($script:SshInvitado)"
    Add-Content -Path $VigLog -Value "[$(Ts)] $linea" -Encoding utf8
    Write-Output $linea
    Write-Output ("SSH_INVITADO=" + $script:SshInvitado)
    if ($r.fallos.Count -gt 0) { exit 60 }
  }

  'crudo' {
    # C-4: copia el crudo del manager ANTES de apagar `logall_json`. Es la regla dura
    # de `state.md:8-18`: sin `archives` no se puede re-puntuar con reglas nuevas.
    $vent = Get-Ventana
    if (-not $vent.fecha) { Log 'crudo FALLO: sin ventana_actual.json ni -T0 (no se sabe la fecha)'; exit 85 }
    if ([string]::IsNullOrEmpty($env:TFG_MANAGER_PW)) { Log 'crudo FALLO: sin TFG_MANAGER_PW (R21)'; exit 85 }
    $dest = Get-CrudoDest
    if (-not $dest) { Log 'crudo FALLO: sin fecha de ventana'; exit 85 }
    $dirA = Join-Path $dest 'archives'
    $dirL = Join-Path $dest 'alerts'
    New-Item -ItemType Directory -Force -Path $dirA, $dirL | Out-Null
    Log "crudo: copiando archives+alerts del manager a $dest"

    # 1) lista de ficheros (actuales + rotaciones dentro de la ventana)
    $desde = if ($vent.t0) { ([datetime]$vent.t0).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
    $filtro = if ($desde) { "-newermt '$desde'" } else { '' }
    $listaCmd = "sudo -S -p '' find /var/ossec/logs/archives /var/ossec/logs/alerts -type f \( -name 'archives.json' -o -name 'alerts.json' -o -name 'ossec-archive-*.json.gz' -o -name 'ossec-alert-*.json.gz' \) $filtro 2>/dev/null"
    $lista = Invoke-Manager $listaCmd
    if (-not $lista) { Log 'crudo FALLO: el manager no devolvio ficheros (inaccesible o sin sudo)'; exit 85 }
    $archivos = @(($lista -split "`r?`n") | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() })

    # 2) staging legible por `angel` y scp (binario-safe; no se re-codifica por stdout)
    $stage = "/tmp/tfg-crudo-" + $vent.fecha
    Invoke-Manager "sudo -S -p '' rm -rf $stage && sudo -S -p '' mkdir -p $stage/archives $stage/alerts" | Out-Null
    foreach ($p in $archivos) {
      $sub = if ($p -like '*/archives/*') { 'archives' } else { 'alerts' }
      Invoke-Manager "sudo -S -p '' cp '$p' '$stage/$sub/'" | Out-Null
    }
    Invoke-Manager "sudo -S -p '' chmod -R a+rX $stage" | Out-Null
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & $Scp -i (Get-ManagerKey) -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR -r "angel@192.168.65.128:$stage/archives" $dest 2>&1 | Out-Null
    $rc1 = $LASTEXITCODE
    & $Scp -i (Get-ManagerKey) -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR -r "angel@192.168.65.128:$stage/alerts" $dest 2>&1 | Out-Null
    $rc2 = $LASTEXITCODE
    $ErrorActionPreference = $eap
    Invoke-Manager "sudo -S -p '' rm -rf $stage" | Out-Null
    if ($rc1 -ne 0 -or $rc2 -ne 0) { Log "crudo FALLO: scp rc=$rc1/$rc2"; exit 85 }

    # 3) sha256 + MANIFEST.tsv de la COPIA
    $man = Join-Path $dest 'MANIFEST.tsv'
    $lineas = @("fichero`tbytes`tsha256")
    foreach ($f in @(Get-ChildItem -Path $dest -Recurse -File | Where-Object { $_.FullName -ne $man })) {
      $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLower()
      $lineas += ("{0}`t{1}`t{2}" -f $f.FullName, $f.Length, $h)
    }
    $lineas | Set-Content -Path $man -Encoding utf8
    $shaMan = (Get-FileHash -LiteralPath $man -Algorithm SHA256).Hash.ToLower()

    # 4) `M` de la COPIA (unidad = linea de `archives`, agente 002; CA-W3b-23)
    $archLocales = @(Get-ChildItem -Path $dirA -File | ForEach-Object { $_.FullName })
    $mCsv = Join-Path $dest 'denominador_M.csv'
    $mMan = Join-Path $dest 'denominador_manifest.tsv'
    $argsM = @($archLocales) + @('--agent-id', '002', '--agent-name', 'victima-windows', '--estricto', '--out', $mCsv, '--manifest', $mMan)
    if ($vent.t0) { $argsM += @('--desde', ([datetime]$vent.t0).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) }
    if ($vent.t1) { $argsM += @('--hasta', ([datetime]$vent.t1).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) }
    & $Py (Join-Path $Repo '_artefactos\scripts\contar_denominador.py') @argsM | Out-Null
    $rcM = $LASTEXITCODE
    if ($rcM -ne 0) { Log "crudo FALLO: contar_denominador rc=$rcM (no se escribe crudo.done)"; exit 85 }

    # 5) crudo.done (es la puerta de `cleanup`)
    $done = Join-Path $dest 'crudo.done'
    @(
      "crudo_utc=$(Ts)",
      "fecha=$($vent.fecha)",
      "t0=$($vent.t0)",
      "t1=$($vent.t1)",
      "ficheros=$($archivos.Count)",
      "manifest_sha256=$shaMan",
      "M_rc=$rcM",
      "M_csv=$mCsv"
    ) | Set-Content -Path $done -Encoding utf8
    Log "crudo OK: $dest (ficheros=$($archivos.Count) manifest=$shaMan M_rc=$rcM)"
  }

  'stop' {
    # Orden critico: no se para la ventana sin el crudo copiado. Se acepta el
    # `crudo.done` nuevo (fase `crudo`) o el `cosecha.done` heredado de W3.
    $vent = Get-Ventana
    $crudoDone = ''
    if ($vent.fecha) { $crudoDone = Join-Path (Get-CrudoDest) 'crudo.done' }
    $tieneCrudo = ($vent.fecha -and (Test-Path $crudoDone))
    if (-not $tieneCrudo -and -not (Test-Path $Cosecha)) {
      Log "stop BLOQUEADO: no existe crudo.done ($crudoDone) ni cosecha.done (orden critico)"; exit 70
    }
    Log ("stop: crudo=" + $(if ($tieneCrudo) { 'crudo.done' } else { 'cosecha.done' }))
    # C-8: parada ordenada del bucle (`stop.flag`), retirada del flag y parada del sink.
    if (Get-VmEnMarcha $Vmx) {
      Log 'stop: creando stop.flag'
      Set-StopFlag $true
      $salio = Wait-KeepaliveSalida 360
      Log "stop: bucle_salio=$salio (espera <= 6 min)"
      Set-StopFlag $false
    } else {
      Log 'stop: VM apagada (sin bucle que esperar)'
    }
    Stop-Sink
    Stop-Actividad
    & $Vmrun -T ws stop $Vmx soft | Out-Null
    Log "stop OK (vmrun rc=$LASTEXITCODE)"
  }

  'cleanup' {
    # C-5: BLOQUEADO sin `crudo.done` (regla dura del crudo, `state.md:8-18`).
    $vent = Get-Ventana
    $crudoDone = ''
    if ($vent.fecha) { $crudoDone = Join-Path (Get-CrudoDest) 'crudo.done' }
    if (-not $vent.fecha -or -not (Test-Path $crudoDone)) {
      Log "cleanup BLOQUEADO: no existe crudo.done ($crudoDone) -> exit 84 (no se apaga logall_json sin copia)"
      exit 84
    }
    Log "cleanup: crudo.done presente ($crudoDone)"
    # C-8: parada ordenada del bucle + parada del sink ANTES de tocar el manager.
    if (Get-VmEnMarcha $Vmx) {
      Set-StopFlag $true
      $salio = Wait-KeepaliveSalida 360
      Log "cleanup: bucle_salio=$salio"
      Set-StopFlag $false
    }
    Stop-Sink
    Stop-Actividad
    Invoke-Remote 'schtasks /delete /tn TFG-WinLegit-Actividad /f' -PermitirFallo | Out-Null
    Invoke-Remote 'schtasks /delete /tn TFG-WinLegit-Keepalive /f' -PermitirFallo | Out-Null
    if (Get-VmEnMarcha $Vmx) { & $Vmrun -T ws stop $Vmx soft | Out-Null }
    # D5: parar GHOSTS API + PostgreSQL del host (espejo del cleanup Linux). No borra datos.
    $stopGhosts = Join-Path $Ghosts 'stop_ghosts.ps1'
    if (Test-Path $stopGhosts) {
      & powershell -NoProfile -ExecutionPolicy Bypass -File $stopGhosts | Out-Null
      $apiViva = @(Get-CimInstance Win32_Process -Filter "Name='dotnet.exe'" -ErrorAction SilentlyContinue |
                   Where-Object { $_.CommandLine -like '*ghosts.api.dll*' }).Count
      $pgReady = & (Join-Path 'D:\TFG-VMs\material-ghosts\pgsql\bin' 'pg_isready.exe') -h 127.0.0.1 -p 5432 2>&1
      $pgParado = ($LASTEXITCODE -ne 0)
      Log "cleanup: GHOSTS/PostgreSQL parados (api_procesos=$apiViva postgres_parado=$pgParado)"
      if ($apiViva -gt 0) { Log 'cleanup FALLO: la GHOSTS API sigue viva'; exit 83 }
    } else {
      Log "cleanup AVISO: no existe stop_ghosts.ps1 ($stopGhosts)"
    }
    # F4: restaurar la telemetria (CA-W16 / WE0-12). `logall_json off` + CONFIG_IDENTICA.
    # Si el manager no es accesible se AVISA (no se puede verificar); si responde y no
    # cuadra, se ABORTA.
    $mgr = Get-ManagerEstado
    if ($mgr.skip) {
      Log "cleanup AVISO: manager inaccesible; logall_json y CONFIG_IDENTICA NO verificados ($($mgr.detalle))"
    } else {
      Push-ManagerScript | Out-Null
      $off = Invoke-Manager "bash $MgrScript off"
      if (-not $off) { Log 'cleanup FALLO: no se pudo ejecutar logall_json off'; exit 81 }
      $st = Get-ManagerEstado
      if ($st.skip -or $st.logall -ne 'no') { Log "cleanup FALLO: logall_json=$($st.logall) tras off"; exit 81 }
      Log 'cleanup: logall_json=no verificado'
      $diff = Invoke-Manager 'sudo -S -p '''' diff /var/ossec/etc/ossec.conf.tfg-bak /var/ossec/etc/ossec.conf && echo CONFIG_IDENTICA || echo CONFIG_DIFIERE'
      if ($diff -match 'CONFIG_IDENTICA') {
        Log 'cleanup: CONFIG_IDENTICA'
      } else {
        Log "cleanup FALLO: CONFIG_DIFIERE ($(($diff -replace '\s+', ' ').Trim()))"; exit 82
      }
    }
    $r = Invoke-Guardarrailes 'cleanup'
    # El manager SIGUE ENCENDIDO a proposito: `logall_json off` y `CONFIG_IDENTICA` se
    # verifican contra el. El "0 VMs" (CA-W21) es del CIERRE del laboratorio (paso
    # posterior, humano/orquestador), no de `cleanup`. Aqui se exige que las VMs de
    # MEDIDA (Windows y Linux) esten apagadas.
    $winOff = -not (Get-VmEnMarcha $Vmx)
    $linuxOff = -not (Get-VmEnMarcha $VmxLinux)
    $mgrOn = Get-VmEnMarcha $VmxMgr
    Log "cleanup: guardarrailes fallos=$($r.fallos.Count) victima_windows_off=$winOff victima_linux_off=$linuxOff manager_on=$mgrOn"
    if (-not ($winOff -and $linuxOff)) { Log 'cleanup FALLO: quedan VMs de medida encendidas'; exit 80 }
  }

  'status' {
    $r = Invoke-Guardarrailes 'status'
    Write-Output ("STATUS fallos=" + $r.fallos.Count + " skip=" + $r.skips.Count)
    Write-Output ("VMS=" + ((& $Vmrun -T ws list 2>&1 | Out-String) -replace '\s+', ' ').Trim())
    Write-Output ("SNAPSHOTS=" + ((Get-Snapshots $Vmx) -join ','))
    $hb = Get-Heartbeat
    if ($hb.ok) {
      Write-Output ("HB_EDAD_MIN=" + $hb.edad_min + " SEQ=" + $hb.last.seq + " KA_PID=" + $hb.last.ka_pid + " KA_INSTANCIAS=" + $hb.last.ka_instancias)
      Write-Output ("CLIENTE_VIVO=" + ([bool]$hb.last.n_ghosts) + " CLIENTE_PID=" + $hb.last.cliente_pid + " WIN_USER=" + $hb.last.win_user)
      Write-Output ("DEFENDER=" + $hb.last.defender + " SESION_ANGEL=" + $hb.last.sesion + " IL=" + $hb.last.il + " ARMADO=" + $hb.last.armado)
    } else {
      Write-Output ("HB_EDAD_MIN=n/a (" + $hb.motivo + ")")
    }
    $vent = Get-Ventana
    Write-Output ("VENTANA fecha=" + $vent.fecha + " t0=" + $vent.t0 + " t1=" + $vent.t1 + " fuente=" + $vent.fuente)
  }
}
