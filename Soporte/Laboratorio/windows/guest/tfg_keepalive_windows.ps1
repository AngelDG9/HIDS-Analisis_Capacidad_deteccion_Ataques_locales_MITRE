# ============================================================================
# tfg_keepalive_windows.ps1 - guardian del INVITADO, UN SOLO PROCESO (W3-bis v2)
# Bloque `windows-legit-prep` (W3-bis, T2a). Espejo de `legitimo_72h/guest/tfg_keepalive.sh`.
# ----------------------------------------------------------------------------
# Modos:
#   -Loop (principal) : 1 proceso persistente. Mutex global, ciclo cada 5 min
#                       ALINEADO al reloj, try/catch POR ciclo, `stop.flag` para
#                       parada ordenada, `estado.json` cada 60 min, log append y
#                       latido POST al sink del host (http://192.168.65.1:9095/heartbeat).
#   -Once (diagnostico): un solo ciclo y exit 0. **NO emite latido, NO toca
#                       `heartbeat.seq` y NO recrea `estado.json`** (F-1, T2b-1b):
#                       el UNICO emisor del latido es `-Loop`. Un `-Once` lanzado por
#                       `deploy`/`arm` no puede inyectar un segundo escritor en el
#                       JSONL (era la causa de `ROTA_SEQ`). Sin bucle y sin mutex.
#
# Lo que hace CADA ciclo:
#   1) disco C: (guardas 500/300 MB) y topes de `client.out`/logs (rotacion).
#   2) Windows Update: re-aplica `NoAutoUpdate=1`; si `wuauserv` esta Running, lo para
#      y lo deja Disabled (el servicio se auto-repara: control efectivo = politica + red).
#   3) actividad: si `armado.flag` y no hay `ghosts.exe`, recupera con
#      `schtasks /run /tn TFG-WinLegit-Actividad` (NUNCA lanza el cliente como SYSTEM).
#   4) rotacion de receta d1->d2->d3 SOLO con `TFG_MAPA_DIAS` (lo fija `arm`).
#   5) latido: una linea TSV en `keepalive.log` + POST JSON al sink + `estado.json`
#      cada 60 min (no cada 5: evita recreaciones de fichero).
#
# CERO procesos externos por ciclo [D]:
#   - solo cmdlets en proceso (Get-Service/Get-Process/Get-PSDrive/Get-CimInstance/
#     Get-NetRoute/Get-MpComputerStatus/registro);
#   - `powercfg` se ejecuta UNA vez al arrancar (1 proceso) y su valor viaja en el latido;
#   - `schtasks` solo se invoca en una recuperacion (0-2 veces en 72 h).
#
# LATIDO (JSON <= 1 KB, lo firma el sink):
#   ts_ciclo, ts_utc, ts_envio, seq, ka_pid, ka_instancias, n_ghosts, cliente_pid,
#   win_user, il, sesion, disco_mb, sysmon, wazuh, wu, defender, powercfg_ok,
#   ruta_defecto, hosts_ok, armado, dia_k, client_out_mb, hijos_vmtoolsd, sha256_prev
#   `ts_ciclo`/`ts_utc` = inicio del ciclo (alineacion a :00/:05). `ts_envio` se sella
#   JUSTO antes del POST: el sink calcula `delta_s` con el (CA-W3b-21) y no con el
#   inicio del ciclo (que incluye el trabajo del ciclo).
#   `seq` es monotono (persiste en `heartbeat.seq`). `sha256_prev` = sha256 del cuerpo
#   del latido ANTERIOR aceptado por el sink; un proceso nuevo manda cadena vacia y el
#   sink lo registra como `REINICIO_BUCLE` (declarado, no manipulacion).
#   Si el POST falla: `hb=FAIL` en el log, el bucle SIGUE, `estado.json` intacto.
#
# `il` se deriva del RunLevel de la tarea de actividad (Limited => Medium). La medida
# real del IL del cliente se hace en la evidencia con Sysmon EID 1 (CA-W3b-02).
#
# NO contiene secretos. NO escribe fuera de C:\Users\angel\ghosts-client.
# Uso (SYSTEM o a mano):
#   powershell -NoProfile -ExecutionPolicy Bypass -File tfg_keepalive_windows.ps1 -Loop
#   powershell -NoProfile -ExecutionPolicy Bypass -File tfg_keepalive_windows.ps1 -Once
# ============================================================================
[CmdletBinding()]
param(
  [switch]$Loop,
  [switch]$Once,
  # Solo prueba en seco: ignora `armado.flag` (no viaja a la ventana).
  [switch]$Force,
  [int]$DiskMinMb = 500,
  [int]$DiskHardMinMb = 300,
  [int]$ClientOutMaxMb = 20,
  [int]$LogMaxMb = 2,
  # Solo prueba en seco: no toca Windows Update (para poder ensayar sin cambiar el host).
  [switch]$SinWu,
  # Intervalo del bucle (min). La ventana usa 5; se deja parametrizable para pruebas.
  [int]$IntervaloMin = 5,
  [string]$SinkUrl = 'http://192.168.65.1:9095/heartbeat',
  [int]$EstadoCadaMin = 60
)

$ErrorActionPreference = 'Continue'
if ($Loop -and $Once) { throw 'Usa -Loop o -Once, no ambos.' }
$Modo = if ($Loop) { 'Loop' } else { 'Once' }
if ($IntervaloMin -lt 1 -or $IntervaloMin -gt 60) { throw 'IntervaloMin fuera de [1,60].' }

$Dir        = 'C:\Users\angel\ghosts-client'
$CwdBase    = 'C:\Users\angel'
$Log        = Join-Path $Dir 'keepalive.log'
$RecLog     = Join-Path $Dir 'recovery.log'
$Estado     = Join-Path $Dir 'estado.json'
$SeqFile    = Join-Path $Dir 'heartbeat.seq'
$FlagArmado = Join-Path $Dir 'armado.flag'
$StopFlag   = Join-Path $Dir 'stop.flag'
$ClientOut  = Join-Path $Dir 'client.out'
$Bloques    = Join-Path $Dir 'recetas\bloques_windows.env'
$TareaAct   = 'TFG-WinLegit-Actividad'

$script:Seq        = 0
$script:ShaPrev    = ''
$script:PowercfgOk = $false
# F-1: SOLO el bucle persistente es emisor del latido. `-Once` es diagnostico.
$script:EmiteLatido = ($Modo -eq 'Loop')
$script:UltimoEstado = [datetime]::MinValue
$script:Sha256     = [System.Security.Cryptography.SHA256]::Create()

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

function Get-SvcEstado([string]$Nombre) {
  try {
    $s = Get-Service -Name $Nombre -ErrorAction SilentlyContinue
    if ($s) { return [string]$s.Status }
  } catch { }
  return 'AUSENTE'
}

function Get-PowercfgOk {
  # UNA sola invocacion de powercfg (al arrancar). STANDBYIDLE/HIBERNATEIDLE/HYBRIDSLEEP
  # con AC=0 => sin suspension. Devuelve $true/$false.
  $guids = @{
    '29f6c1db-86da-48c5-9fdb-f2b67b1f44da' = 'STANDBYIDLE'
    '9d7815a6-7ee4-497e-8888-515a05f02364' = 'HIBERNATEIDLE'
    '94ac6d29-73ce-41a6-809f-6363ba21b47e' = 'HYBRIDSLEEP'
  }
  try {
    $txt = (& powercfg /query SCHEME_CURRENT SUB_SLEEP 2>&1 | Out-String)
    $ok = $true
    $vistos = 0
    foreach ($bloque in ($txt -split 'Power Setting GUID:')) {
      $m = [regex]::Match($bloque, '^\s*([0-9a-fA-F-]{36})')
      if (-not $m.Success) { continue }
      $g = $m.Groups[1].Value.ToLower()
      if (-not $guids.ContainsKey($g)) { continue }
      $vistos++
      $ac = [regex]::Match($bloque, 'Current AC Power Setting Index:\s*(0x[0-9A-Fa-f]+)')
      $val = if ($ac.Success) { [Convert]::ToInt32($ac.Groups[1].Value, 16) } else { -1 }
      if ($val -ne 0) { $ok = $false }
    }
    if ($vistos -lt 3) { return $false }
    return $ok
  } catch { return $false }
}

function Get-MsHastaSiguiente([int]$Min) {
  $a = Get-Date
  $seg = $Min * 60
  $trans = ($a.Minute % $Min) * 60 + $a.Second + ($a.Millisecond / 1000.0)
  $falta = $seg - $trans
  if ($falta -le 0) { $falta += $seg }
  return [int]([math]::Ceiling($falta * 1000))
}

# ---------------------------------------------------------------------------
# Invoke-Ciclo: un ciclo completo. Devuelve @{ escribir_estado; hb_ok }
# ---------------------------------------------------------------------------
function Invoke-Ciclo {
  $ts = TsUtc

  # --- 1) disco -------------------------------------------------------------
  $freeMb = 0
  try { $freeMb = [math]::Round((Get-PSDrive C).Free / 1MB) } catch { $freeMb = -1 }
  $puedeArrancar = $true
  if ($freeMb -ge 0 -and $freeMb -lt $DiskMinMb) {
    RLog 'alarma_disco' "free_mb=$freeMb min_mb=$DiskMinMb"
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

  # --- 2) Windows Update ----------------------------------------------------
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
    } catch { RLog 'alarma_wu' "servicio: $($_.Exception.Message)" }
  }
  $wuSvc = Get-SvcEstado 'wuauserv'

  # --- 3) actividad ---------------------------------------------------------
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
    RLog 'alarma' "tarea_principal_no_angel=$tareaUser (no se relanza)"
  }

  $proc = @(Get-Process -Name ghosts -ErrorAction SilentlyContinue)
  $pid1 = if ($proc.Count -gt 0) { $proc[0].Id } else { 0 }
  $dueno = if ($proc.Count -gt 0) { Get-DuenoProceso 'ghosts.exe' } else { '' }

  # Sesion de la consola de `angel` SIN `query.exe` (proceso externo): el cliente, si
  # vive, ya dice su sesion; si no, `explorer.exe` de la sesion interactiva.
  $sesionAngel = 0
  if ($proc.Count -gt 0) {
    try { $sesionAngel = [int]$proc[0].SessionId } catch { }
  }
  if ($sesionAngel -le 0) {
    try {
      $exp = @(Get-Process -Name explorer -ErrorAction SilentlyContinue | Select-Object -First 1)
      if ($exp.Count -gt 0) { $sesionAngel = [int]$exp[0].SessionId }
    } catch { }
  }
  $haySesion = ($sesionAngel -gt 0)
  if ($armado -and -not $haySesion) {
    RLog 'alarma' 'sin_sesion_angel (la tarea Interactive no puede arrancar)'
    $puedeArrancar = $false
  }

  if ($armado -and $userOk -and $puedeArrancar) {
    if ($proc.Count -eq 0) {
      if ($tareaEstado -eq 'Running') {
        & schtasks /end /tn $TareaAct 2>&1 | Out-Null
        RLog 'end' 'tarea_huerfana state=Running pid=0'
        Start-Sleep -Seconds 2
      }
      & schtasks /run /tn $TareaAct 2>&1 | Out-Null
      $rcRun = $LASTEXITCODE
      Start-Sleep -Seconds 8
      $proc = @(Get-Process -Name ghosts -ErrorAction SilentlyContinue)
      if ($proc.Count -gt 0) {
        $pid1 = $proc[0].Id
        $dueno = Get-DuenoProceso 'ghosts.exe'
        $sesionAngel = [int]$proc[0].SessionId
        RLog 'recuperacion' "pid=$pid1 user=$dueno rc_run=$rcRun"
      } else {
        RLog 'alarma' "no_arranca rc_run=$rcRun state=$tareaEstado"
      }
    }
  } elseif (-not $armado) {
    if ($proc.Count -gt 0) { KLog "desarmado_pero_vivo pid=$pid1 user=$dueno" }
  }

  # --- 4) tope de client.out ------------------------------------------------
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

  # --- 5) rotacion de receta (solo con mapa de dias) ------------------------
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

  # --- 6) metricas del latido ----------------------------------------------
  $t = $null
  try { $t = Get-ScheduledTask -TaskName $TareaAct -ErrorAction SilentlyContinue } catch { }
  if ($t) {
    $tareaEstado = [string]$t.State
    $tareaUser = [string]$t.Principal.UserId
    $tareaLogon = [string]$t.Principal.LogonType
  }

  $nGhosts = $proc.Count
  $clientePid = if ($nGhosts -gt 0) { $proc[0].Id } else { 0 }
  $winUser = if ($nGhosts -gt 0) { Get-DuenoProceso 'ghosts.exe' } else { '' }

  $il = '?'
  if ($t) { $il = if ([string]$t.Principal.RunLevel -eq 'Limited') { 'Medium' } else { 'High' } }

  $sysmon = Get-SvcEstado 'Sysmon64'
  $wazuh  = Get-SvcEstado 'WazuhSvc'

  $defender = '?'
  $wd = Get-SvcEstado 'WinDefend'
  if ($wd -ne 'Running') {
    # Defender parado => proteccion en tiempo real fuera (control ambiental declarado).
    $defender = 'off'
  } else {
    try {
      $mp = Get-MpComputerStatus -ErrorAction Stop
      $defender = if (-not $mp.RealTimeProtectionEnabled) { 'off' } else { 'on' }
    } catch { $defender = '?' }
  }

  $rutaDef = 0
  try { $rutaDef = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue).Count } catch { }

  $hostsOk = $false
  try {
    $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $hostsOk = ((Get-Content -LiteralPath $hosts -ErrorAction Stop) -join "`n") -match '192\.168\.65\.1\s+.*intranet\.local'
  } catch { }

  # Instancias del bucle (-Loop) vivas: la nuestra + cualquier duplicado que hubiera.
  $kaInst = 0
  try {
    $kaInst = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
      Where-Object { $_.CommandLine -and $_.CommandLine -match 'tfg_keepalive_windows\.ps1' -and $_.CommandLine -match '(?i)-Loop\b' }).Count
  } catch { }

  # Hijos del propio proceso (para evidencia de "0 procesos externos por ciclo").
  $hijos = 0
  try {
    $hijos = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
      Where-Object { $_.ParentProcessId -eq $PID }).Count
  } catch { }

  # Hijos de `vmtoolsd.exe` (senal W-V4 / G-W8): viaja en el latido para que el
  # `watch` del host NO tenga que entrar por SSH en el invitado.
  $hijosVt = 0
  try {
    $vt = Get-CimInstance Win32_Process -Filter "Name='vmtoolsd.exe'" -ErrorAction SilentlyContinue |
      Select-Object -First 1
    if ($vt) {
      $hijosVt = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ParentProcessId -eq $vt.ProcessId }).Count
    }
  } catch { $hijosVt = -1 }

  # --- 7) latido POST (SOLO -Loop; F-1) ------------------------------------
  $hbEstado = 'SKIP'
  $hbMotivo = ''
  $body = ''
  if ($script:EmiteLatido) {
    $script:Seq++
    try { Set-Content -Path $SeqFile -Value ([string]$script:Seq) -Encoding ascii } catch { }

    $hb = [ordered]@{
      ts_ciclo      = $ts
      ts_utc        = $ts
      seq           = $script:Seq
      ka_pid        = $PID
      ka_instancias = $kaInst
      n_ghosts      = $nGhosts
      cliente_pid   = $clientePid
      win_user      = $winUser
      il            = $il
      sesion        = $sesionAngel
      disco_mb      = $freeMb
      sysmon        = $sysmon
      wazuh         = $wazuh
      wu            = "$wuSvc/NoAutoUpdate=$wuPol"
      defender      = $defender
      powercfg_ok   = [bool]$script:PowercfgOk
      ruta_defecto  = $rutaDef
      hosts_ok      = [bool]$hostsOk
      armado        = [bool]$armado
      dia_k         = $diaK
      client_out_mb = $outMb
      hijos_vmtoolsd = $hijosVt
      sha256_prev   = $script:ShaPrev
    }

    $hbEstado = 'FAIL'
    try {
      # `ts_envio` JUSTO antes del POST (correccion T2b-1 / CA-W3b-21).
      $hb['ts_envio'] = (TsUtc)
      $body = ($hb | ConvertTo-Json -Compress -Depth 3)
      if ($body.Length -gt 1024) { throw "latido de $($body.Length) bytes (> 1 KB)" }
      Invoke-RestMethod -Uri $SinkUrl -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 3 | Out-Null
      $hbEstado = 'OK'
      $script:ShaPrev = [System.BitConverter]::ToString(
        $script:Sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($body))).Replace('-', '').ToLower()
    } catch {
      $hbMotivo = $_.Exception.Message
    }
  }

  if ($script:EmiteLatido) {
    KLog ("latido seq=$($script:Seq) hb=$hbEstado ka_inst=$kaInst n_ghosts=$nGhosts pid=$clientePid " +
      "user=$winUser il=$il ses=$sesionAngel disco_mb=$freeMb sysmon=$sysmon wazuh=$wazuh wu=$wuSvc " +
      "def=$defender pc=$($script:PowercfgOk) rd=$rutaDef hosts=$hostsOk armado=$armado dia=$diaK " +
      "out_mb=$outMb hijos=$hijos" + $(if ($hbMotivo) { " motivo=$hbMotivo" } else { '' }))
  } else {
    KLog ("diagnostico modo=Once sin_latido sin_seq sin_estado n_ghosts=$nGhosts pid=$clientePid " +
      "user=$winUser ses=$sesionAngel disco_mb=$freeMb sysmon=$sysmon wazuh=$wazuh def=$defender " +
      "armado=$armado dia=$diaK out_mb=$outMb")
  }

  # --- 8) estado.json cada N minutos (SOLO -Loop; F-1) ---------------------
  $escribir = $false
  if ($script:EmiteLatido) {
    $escribir = ((Get-Date) - $script:UltimoEstado).TotalMinutes -ge $EstadoCadaMin
  }
  if ($escribir) {
    $est = [ordered]@{
      ts_utc          = $ts
      seq             = $script:Seq
      armado          = $armado
      dia_k           = $diaK
      disco_libre_mb  = $freeMb
      wuauserv        = $wuSvc
      wu_noautoupdate = $wuPol
      tarea           = $TareaAct
      tarea_estado    = $tareaEstado
      tarea_user      = $tareaUser
      tarea_logon     = $tareaLogon
      cliente_vivo    = ($nGhosts -gt 0)
      cliente_pid     = $clientePid
      win_user        = $winUser
      il              = $il
      sesion          = $sesionAngel
      sysmon          = $sysmon
      wazuh           = $wazuh
      defender        = $defender
      powercfg_ok     = [bool]$script:PowercfgOk
      ruta_defecto    = $rutaDef
      hosts_ok        = [bool]$hostsOk
      client_out_mb   = $outMb
      hb              = $hbEstado
      hb_motivo       = $hbMotivo
      sha256_prev     = $script:ShaPrev
    }
    try { ($est | ConvertTo-Json -Compress) | Set-Content -Path $Estado -Encoding utf8 } catch { }
    $script:UltimoEstado = Get-Date
  }

  return @{ escribir_estado = $escribir; hb_ok = ($hbEstado -eq 'OK') }
}

# ---------------------------------------------------------------------------
# Arranque
# ---------------------------------------------------------------------------
if (-not (Test-Path $Dir)) {
  # Sin cliente desplegado no hay nada que guardar (y no se crea nada).
  exit 0
}
New-Item -ItemType Directory -Force -Path (Join-Path $Dir 'logs') | Out-Null
if (-not (Test-Path $Log)) { New-Item -ItemType File -Force -Path $Log | Out-Null }
if (-not (Test-Path $RecLog)) { New-Item -ItemType File -Force -Path $RecLog | Out-Null }
try { Set-Location $CwdBase } catch { Set-Location $Dir }

# ---------------------------------------------------------------------------
# -Loop: MUTEX ANTES DE TODO (correccion T2b-1)
# La 2.a instancia debe salir SIN rotar logs, SIN ejecutar `powercfg` y SIN escribir
# la linea `arranque`: solo `segunda_instancia` + exit 0. (Antes el bloque de mutex
# estaba despues del arranque y el duplicado gastaba un `powercfg.exe` por nada.)
# ---------------------------------------------------------------------------
$mutex = $null
if ($Modo -eq 'Loop') {
  $tengoMutex = $false
  $mutexDenegado = $false
  try {
    # ACL explicita: `Everyone` puede ABRIR el mutex. Sin esto, el mutex creado por
    # SYSTEM en `Global\` da ACCESS_DENIED a un duplicado lanzado como `angel`, y ese
    # duplicado arrancaria (bug medido en T2a). Con la ACL, WaitOne(0)=false y sale.
    $sec = $null
    try {
      $sec = New-Object System.Security.AccessControl.MutexSecurity
      $everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
      $regla = New-Object System.Security.AccessControl.MutexAccessRule($everyone,
        [System.Security.AccessControl.MutexRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow)
      $sec.AddAccessRule($regla)
    } catch { $sec = $null }

    if ($sec) {
      $creado = $false
      $mutex = [System.Threading.Mutex]::new($false, 'Global\TFG-WinLegit-Keepalive', [ref]$creado, $sec)
    } else {
      $mutex = [System.Threading.Mutex]::new($false, 'Global\TFG-WinLegit-Keepalive')
    }
    try { $tengoMutex = $mutex.WaitOne(0) }
    catch [System.Threading.AbandonedMutexException] { $tengoMutex = $true }
  } catch [System.UnauthorizedAccessException] {
    $mutexDenegado = $true
  } catch {
    KLog "mutex_error $($_.Exception.Message)"
    $mutexDenegado = $true
  }
  if ($mutexDenegado -or -not $tengoMutex) {
    # Cualquier fallo del mutex se trata como "ya hay instancia": NUNCA se arranca un
    # segundo bucle (conservador; el plan exige que el duplicado no haga nada).
    KLog "segunda_instancia pid=$PID (mutex Global\TFG-WinLegit-Keepalive ocupado o inaccesible; no se hace nada)"
    exit 0
  }
}

$rotKa = Rotar $Log $LogMaxMb
$rotRec = Rotar $RecLog $LogMaxMb
if ($rotKa -or $rotRec) { KLog "rotacion_logs ka=$rotKa rec=$rotRec" }

# `seq` persistente (monotono entre reinicios del proceso).
if (Test-Path $SeqFile) {
  try { $script:Seq = [int]((Get-Content -LiteralPath $SeqFile -Raw).Trim()) } catch { $script:Seq = 0 }
}

# `powercfg`: UNA vez al arrancar (no por ciclo).
$script:PowercfgOk = Get-PowercfgOk

KLog "arranque modo=$Modo pid=$PID intervalo_min=$IntervaloMin sink=$SinkUrl powercfg_ok=$($script:PowercfgOk) seq=$($script:Seq)"

# ---------------------------------------------------------------------------
# -Once: un ciclo y salir (comportamiento historico de W3)
# ---------------------------------------------------------------------------
if ($Modo -eq 'Once') {
  $script:UltimoEstado = [datetime]::MinValue
  Invoke-Ciclo | Out-Null
  exit 0
}

$script:UltimoEstado = [datetime]::MinValue
while ($true) {
  if (Test-Path $StopFlag) {
    KLog 'parada_ordenada stop.flag'
    break
  }
  try {
    Invoke-Ciclo | Out-Null
  } catch {
    KLog "ciclo_error $($_.Exception.Message)"
  }
  if (Test-Path $StopFlag) {
    KLog 'parada_ordenada stop.flag'
    break
  }
  $ms = Get-MsHastaSiguiente $IntervaloMin
  try { Start-Sleep -Milliseconds $ms } catch { Start-Sleep -Seconds 30 }
}

# Parada ordenada: se retira el `stop.flag` para que un reinicio del proceso (o el
# arranque del snapshot) no salga inmediatamente. Tambien lo borra el controlador.
try { if (Test-Path $StopFlag) { Remove-Item -LiteralPath $StopFlag -Force -ErrorAction SilentlyContinue } } catch { }
try { if ($mutex) { $mutex.ReleaseMutex(); $mutex.Dispose() } } catch { }
exit 0
