# ============================================================================
# windows_legit_host_control.ps1 - control del HOST para la ventana legitima Windows
# Bloque `windows-legit-prep` (W3). Espejo de `legitimo_72h/legitimo_host_control.ps1`.
# ----------------------------------------------------------------------------
# Fases:
#   prep    : G-W1..G-W12 -> revert a `lab-listo-windows-legit` + arranque + deploy
#             idempotente + verificacion del invitado. NO arma.
#   arm     : fija el mapa de dias (--t0), re-despliega recetas, crea `armado.flag`,
#             arranca la actividad y enciende `logall_json` (manager).
#   watch   : vigilancia READ-ONLY (host + manager + invitado). No arranca ni para nada.
#   stop    : parada suave del invitado SOLO si existe `cosecha.done` (orden critico).
#   cleanup : desregistra tareas, para la VM, `logall_json off` + CONFIG_IDENTICA,
#             para GHOSTS; deja 0 VMs.
#   status  : imprime el estado.
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
#   G-W7  `logall_json` segun [t0,t1]: `yes` dentro, `no` fuera; sin t0/t1 ⇒ SKIP (CA-W16)
#   G-W8  0 procesos con padre `vmtoolsd.exe` (sin acceso del operador)   (W-V4/CA-W13)
#   G-W9  sin suspension (STANDBYIDLE/HIBERNATEIDLE/HYBRIDSLEEP = 0)      (R-W4)
#   G-W10 disco del invitado >= 4 GB + guarda 500 MB del keepalive        (R-W15)
#   G-W11 un solo cliente vivo (1 `ghosts.exe`, 1 machineid)              (CA-W6)
#   G-W12 host: RAM libre >= 1500 MB y Windows Update pausado             (R-W4)
#
# Sin secretos. Uso (HOST):
#   powershell -NoProfile -ExecutionPolicy Bypass -File windows_legit_host_control.ps1 -Phase drytest
#   ... -Phase prep | arm -T0 2026-11-16T00:00:00Z -T1 2026-11-19T00:00:00Z | watch | stop | cleanup | status
#   `G-W7` decide por la ventana: con `-T0/-T1` exige `yes` dentro y `no` fuera; sin
#   ellos sale SKIP declarado. `watch`/`status` deben recibir ambos para evaluarlo.
# ============================================================================
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('prep', 'arm', 'watch', 'stop', 'cleanup', 'status', 'drytest')]
  [string]$Phase,
  [string]$T0 = '',
  [string]$T1 = '',
  # drytest: limita la prueba a una fase (por defecto, todas).
  [ValidateSet('', 'prep', 'arm', 'watch', 'stop', 'cleanup', 'status')]
  [string]$DryPhase = '',
  # drytest: log alternativo (la prueba negativa de G-W11 no ensucia `drytest.log`).
  [string]$DryLogPath = '',
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
  if ([string]::IsNullOrWhiteSpace($T0) -or [string]::IsNullOrWhiteSpace($T1)) {
    return @{ ok = $true; skip = $true; detalle = "sin -T0/-T1 (no evaluable); logall_json=$logall" }
  }
  try {
    $t0 = [datetime]::Parse($T0).ToUniversalTime()
    $t1 = [datetime]::Parse($T1).ToUniversalTime()
  } catch {
    return @{ ok = $false; detalle = "t0/t1 no parseables ('$T0' / '$T1')" }
  }
  $now = (Get-Date).ToUniversalTime()
  if ($now -ge $t0 -and $now -le $t1) {
    return @{ ok = ($logall -eq 'yes'); detalle = "logall_json=$logall (now dentro de [t0,t1] exige yes)" }
  }
  return @{ ok = ($logall -eq 'no'); detalle = "logall_json=$logall (now fuera de [t0,t1] exige no)" }
}

function Test-GW8 {
  $g = Get-Invitado
  if (-not $g.ok) { return @{ ok = $false; skip = $g.skip; detalle = $g.detalle } }
  $m = [regex]::Match($g.kv['raw'], 'HIJOS_VMTOOLSD=(\d+)')
  $n = if ($m.Success) { [int]$m.Groups[1].Value } else { -1 }
  return @{ ok = ($n -eq 0); detalle = "hijos_vmtoolsd=$n (0 = sin acceso del operador)" }
}

function Test-GW9 {
  $g = Get-Invitado
  if (-not $g.ok) { return @{ ok = $false; skip = $g.skip; detalle = $g.detalle } }
  $ok = ($g.kv['raw'] -match 'CHECK powercfg_STANDBYIDLE\s+OK') -and
        ($g.kv['raw'] -match 'CHECK powercfg_HIBERNATEIDLE\s+OK') -and
        ($g.kv['raw'] -match 'CHECK powercfg_HYBRIDSLEEP\s+OK')
  return @{ ok = $ok; detalle = "powercfg 3/3 = $ok" }
}

function Test-GW10 {
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
}

# Que guardarrailes aplican a cada fase (los demas no se evaluan en esa fase).
$Aplican = @{
  prep    = @('G-W1', 'G-W2', 'G-W3', 'G-W4', 'G-W5', 'G-W6', 'G-W7', 'G-W9', 'G-W10', 'G-W12')
  arm     = @('G-W1', 'G-W2', 'G-W4', 'G-W5', 'G-W6', 'G-W7', 'G-W9', 'G-W10', 'G-W11', 'G-W12')
  watch   = @('G-W5', 'G-W7', 'G-W8', 'G-W9', 'G-W10', 'G-W11', 'G-W12')
  stop    = @('G-W5', 'G-W10')
  cleanup = @('G-W1', 'G-W2', 'G-W3', 'G-W7', 'G-W12')
  status  = @('G-W1', 'G-W2', 'G-W3', 'G-W4', 'G-W5', 'G-W6', 'G-W7', 'G-W8', 'G-W9', 'G-W10', 'G-W11', 'G-W12')
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
      $salida.Add("DRYTEST FASE=$f")
      $r = Invoke-Guardarrailes $f
      foreach ($x in $r.res) { $salida.Add(("  {0} {1} {2}" -f $x.id, $x.estado, $x.detalle)) }
      $veredicto = if ($r.fallos.Count -gt 0) { 'FAIL' } elseif ($r.skips.Count -gt 0) { 'PASS_CON_SKIP' } else { 'PASS' }
      $salida.Add(("DRYTEST {0} {1} (ok={2} fallos={3} skip={4})" -f $f, $veredicto, ($r.res.Count - $r.fallos.Count - $r.skips.Count), $r.fallos.Count, $r.skips.Count))
      $totalFallos += $r.fallos.Count
    }
    $resultado = if ($totalFallos -eq 0) { 'DRYTEST_RESULT=PASS' } else { 'DRYTEST_RESULT=FAIL' }
    $salida.Add($resultado)
    foreach ($l in $salida) { Write-Output $l }
    Add-Content -Path $DryLogPath -Value ($salida -join [Environment]::NewLine) -Encoding utf8
    if ($totalFallos -eq 0) { exit 0 }
    exit 1
  }

  'prep' {
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
    Log 'prep: deploy idempotente'
    & powershell -NoProfile -ExecutionPolicy Bypass -File $Deploy -Phase apply
    if ($LASTEXITCODE -ne 0) { Log 'prep FALLO: deploy'; exit 44 }
    $r2 = Invoke-Guardarrailes 'prep'
    if ($r2.fallos.Count -gt 0) { Log "prep FALLO tras deploy: $(($r2.fallos | ForEach-Object { $_.id }) -join ',')"; exit 45 }
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
    & powershell -NoProfile -ExecutionPolicy Bypass -File $Deploy -Phase apply | Out-Null
    if ($LASTEXITCODE -ne 0) { Log 'arm FALLO: re-deploy con mapa'; exit 53 }
    Invoke-Remote 'type nul > C:\Users\angel\ghosts-client\armado.flag' | Out-Null
    Invoke-Remote 'schtasks /run /tn TFG-WinLegit-Actividad' | Out-Null
    # F3: MISMA credencial que `Get-ManagerEstado` (clave del laboratorio Linux, no la
    # del invitado Windows) y verificacion REAL: no se registra "ON" sin comprobarlo.
    Push-ManagerScript | Out-Null
    $on = Invoke-Manager "bash $MgrScript on"
    if (-not $on) { Log 'arm FALLO: no se pudo ejecutar logall_json on (manager inaccesible o sin credencial)'; exit 54 }
    $mgr = Get-ManagerEstado
    if ($mgr.skip -or $mgr.logall -ne 'yes') {
      Log "arm FALLO: logall_json NO verificado tras on (logall=$($mgr.logall); $($mgr.detalle))"
      exit 55
    }
    Log "arm: logall_json ON verificado (manager_active=$($mgr.activo) daemons=$($mgr.daemons))"
    Log 'arm OK'
  }

  'watch' {
    $r = Invoke-Guardarrailes 'watch'
    $linea = "chequeo ok=$($r.res.Count - $r.fallos.Count - $r.skips.Count) fallos=$($r.fallos.Count) skip=$($r.skips.Count)"
    if ($r.fallos.Count -gt 0) {
      $linea = "ALARMA $linea :: " + (($r.fallos | ForEach-Object { "$($_.id)=$($_.detalle)" }) -join ' | ')
    }
    Add-Content -Path $VigLog -Value "[$(Ts)] $linea" -Encoding utf8
    Write-Output $linea
    if ($r.fallos.Count -gt 0) { exit 60 }
  }

  'stop' {
    if (-not (Test-Path $Cosecha)) { Log 'stop BLOQUEADO: no existe cosecha.done (orden critico del plan §10)'; exit 70 }
    Stop-Actividad
    & $Vmrun -T ws stop $Vmx soft | Out-Null
    Log "stop OK (vmrun rc=$LASTEXITCODE)"
  }

  'cleanup' {
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
    # verifican contra el. El «0 VMs» (CA-W21) es del CIERRE del laboratorio (paso
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
  }
}
