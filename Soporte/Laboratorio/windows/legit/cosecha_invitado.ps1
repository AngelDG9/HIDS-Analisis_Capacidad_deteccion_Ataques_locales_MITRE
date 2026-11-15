# ============================================================================
# cosecha_invitado.ps1 - COSECHA del invitado Windows tras `t1` (bloque windows-legit)
# ----------------------------------------------------------------------------
# Lo copia al invitado y lo lanza el controlador (`windows_legit_host_control.ps1
# -Phase cosecha`). Se ejecuta DENTRO del invitado, SOLO LECTURA sobre la evidencia:
# copia a un directorio de trabajo (`-Stage`) todo lo que se pierde al apagar/revertir la
# VM y calcula `sha256` de cada fichero (`MANIFEST_INVITADO.tsv`). El controlador lo trae
# al host (`scp -r`) y vuelve a calcular los hashes para comprobar la copia.
#
# Que se recoge (R-02 de la auditoria de plan.md):
#   - estado del operador: keepalive.log, recovery.log, estado.json, client.out(.1),
#     heartbeat.seq(.prev), dia_aplicado.txt, logs del cliente GHOSTS
#   - errores.log de la receta y las 22 marcas de la campana (+ export*.csv)
#   - ossec.log del AGENTE (prueba de si hubo perdidas: buffer lleno, desconexiones)
#   - EVTX completos: Security, Sysmon, PowerShell/Operational, System, Application
#     (verdad de terreno para comparar con `archives` del manager) + `wevtutil gl` (tamanos)
#   - reinicios/suspensiones desde `t0` (W-V8) y reloj del invitado (W-V9)
#   - reg query / schtasks / ipconfig / systeminfo / servicios / powercfg
#
# NO modifica nada de la ventana: la ventana ya termino (se lanza tras `t1`).
# ASCII puro (PowerShell 5.1 sin BOM). Sin secretos.
# ============================================================================
[CmdletBinding()]
param(
  [string]$Stage = 'C:\Users\angel\cosecha_stage',
  # `t0` y `t1` en UTC (ISO8601): filtran reinicios y el CONTEO de eventos por tipo.
  # Vacio = ultimos 7 dias / hasta ahora.
  [string]$Desde = '',
  [string]$Hasta = ''
)

$ErrorActionPreference = 'Continue'
$Dir = 'C:\Users\angel\ghosts-client'
$Agente = 'C:\Program Files (x86)\ossec-agent'

$Stage = [IO.Path]::GetFullPath($Stage)   # acepta `/` (el controlador las pasa asi por SSH)
if (Test-Path $Stage) { Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force -Path $Stage | Out-Null
$aviso = New-Object System.Collections.Generic.List[string]

function Copiar([string]$Src, [string]$RelDst) {
  if (-not (Test-Path -LiteralPath $Src)) { $script:aviso.Add("AUSENTE $Src"); return }
  $dst = Join-Path $Stage $RelDst
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
  try { Copy-Item -LiteralPath $Src -Destination $dst -Force -ErrorAction Stop }
  catch { $script:aviso.Add("ERROR_COPIA $Src : $($_.Exception.Message)") }
}

function Salida([string]$Nombre, [scriptblock]$Bloque) {
  $dst = Join-Path $Stage $Nombre
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
  try { (& $Bloque 2>&1 | Out-String) | Set-Content -LiteralPath $dst -Encoding UTF8 }
  catch { "ERROR: $($_.Exception.Message)" | Set-Content -LiteralPath $dst -Encoding UTF8 }
}

# --- 0) reloj (W-V9) --------------------------------------------------------
$utc = (Get-Date).ToUniversalTime()
Salida 'reloj.txt' { "guest_utc=" + $utc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'); "guest_local=" + (Get-Date -Format o); "tz=" + (Get-TimeZone).Id }

# --- 1) estado del operador y del cliente -----------------------------------
foreach ($f in @('keepalive.log', 'keepalive.log.1', 'recovery.log', 'recovery.log.1', 'estado.json',
                 'client.out', 'client.out.1', 'heartbeat.seq', 'heartbeat.seq.prev',
                 'dia_aplicado.txt', 'armado.flag', 'stop.flag')) {
  Copiar (Join-Path $Dir $f) ("cliente\" + $f)
}
if (Test-Path (Join-Path $Dir 'logs')) {
  Get-ChildItem -LiteralPath (Join-Path $Dir 'logs') -File -ErrorAction SilentlyContinue |
    ForEach-Object { Copiar $_.FullName ("cliente\logs\" + $_.Name) }
}
Copiar 'C:\Users\angel\Documentos\errores.log' 'receta\errores.log'

# --- 2) campana (22 marcas + exports) ---------------------------------------
if (Test-Path 'C:\lab-legit\campana') {
  Get-ChildItem -LiteralPath 'C:\lab-legit\campana' -Recurse -File -ErrorAction SilentlyContinue |
    ForEach-Object {
      $rel = $_.FullName.Substring('C:\lab-legit\campana'.Length).TrimStart('\')
      Copiar $_.FullName ("campana\" + $rel)
    }
} else { $aviso.Add('AUSENTE C:\lab-legit\campana') }

# --- 3) ossec.log del agente (prueba de perdidas) ---------------------------
Copiar (Join-Path $Agente 'ossec.log') 'agente\ossec.log'
if (Test-Path (Join-Path $Agente 'logs')) {
  Get-ChildItem -LiteralPath (Join-Path $Agente 'logs') -Recurse -File -ErrorAction SilentlyContinue |
    ForEach-Object {
      $rel = $_.FullName.Substring((Join-Path $Agente 'logs').Length).TrimStart('\')
      Copiar $_.FullName ("agente\logs\" + $rel)
    }
}
Copiar (Join-Path $Agente 'ossec.conf') 'agente\ossec.conf'

# --- 4) EVTX completos + configuracion de los logs --------------------------
$logs = [ordered]@{
  'Security'                                 = 'Security.evtx'
  'Microsoft-Windows-Sysmon/Operational'     = 'Sysmon.evtx'
  'Microsoft-Windows-PowerShell/Operational' = 'PowerShell-Operational.evtx'
  'System'                                   = 'System.evtx'
  'Application'                              = 'Application.evtx'
}
New-Item -ItemType Directory -Force -Path (Join-Path $Stage 'evtx') | Out-Null
foreach ($n in $logs.Keys) {
  $dst = Join-Path $Stage ('evtx\' + $logs[$n])
  & wevtutil epl $n $dst /ow:true 2>&1 | Out-Null
  if (-not (Test-Path -LiteralPath $dst)) { $aviso.Add("EVTX_NO_EXPORTADO $n") }
}
Salida 'evtx\config_logs.txt' {
  foreach ($n in $logs.Keys) {
    "=== $n"
    & wevtutil gl $n
    try { $l = Get-WinEvent -ListLog $n -ErrorAction Stop; "RecordCount=$($l.RecordCount) FileSize=$($l.FileSize) LogMode=$($l.LogMode)" } catch { "ListLog ERROR $($_.Exception.Message)" }
  }
}

# --- 4b) CONTEO de eventos por (log, EventID) dentro de [t0, t1] ----------------
# Verdad de terreno del invitado para comparar con `archives` del manager: si el agente
# hubiese perdido eventos (buffer lleno, desconexion), aqui habria MAS que en `archives`.
# Lo calcula el propio invitado (Get-WinEvent con filtro de fechas) para no parsear EVTX
# en el host. Salida: evtx\conteo_por_evento.csv  (log,eventid,count,primero_utc,ultimo_utc)
$ini = (Get-Date).AddDays(-7).ToUniversalTime()
$fin = (Get-Date).ToUniversalTime()
if ($Desde) { try { $ini = [datetime]::Parse($Desde, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { } }
if ($Hasta) { try { $fin = [datetime]::Parse($Hasta, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { } }
$conteo = New-Object System.Collections.Generic.List[string]
$conteo.Add('log,eventid,count,primero_utc,ultimo_utc')
foreach ($n in $logs.Keys) {
  try {
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $n; StartTime = $ini.ToLocalTime(); EndTime = $fin.ToLocalTime() } -ErrorAction Stop)
    foreach ($g in ($ev | Group-Object -Property Id | Sort-Object { [int]$_.Name })) {
      $ts = @($g.Group | ForEach-Object { $_.TimeCreated.ToUniversalTime() } | Sort-Object)
      $conteo.Add(('{0},{1},{2},{3},{4}' -f $n, $g.Name, $g.Count, $ts[0].ToString('yyyy-MM-ddTHH:mm:ss.fffZ'), $ts[$ts.Count - 1].ToString('yyyy-MM-ddTHH:mm:ss.fffZ')))
    }
  } catch {
    if ($_.Exception.Message -match 'No events were found|No se encontraron') { continue }
    $aviso.Add("CONTEO_ERROR $n : $($_.Exception.Message)")
  }
}
$conteo | Set-Content -LiteralPath (Join-Path $Stage 'evtx\conteo_por_evento.csv') -Encoding ASCII
Salida 'evtx\conteo_ventana.txt' { 'desde_utc=' + $ini.ToString('o'); 'hasta_utc=' + $fin.ToString('o') }

# --- 5) reinicios / suspensiones desde t0 (W-V8) ----------------------------
$t0 = (Get-Date).AddDays(-7)
if ($Desde) { try { $t0 = [datetime]::Parse($Desde, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { } }
Salida 'sistema\reinicios.txt' {
  "desde_utc=" + $t0.ToUniversalTime().ToString('o')
  $ev = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1074, 6005, 6006, 6008, 41, 42, 107, 109; StartTime = $t0 } -ErrorAction SilentlyContinue
  "reinicios_o_suspensiones=" + @($ev).Count
  $ev | Select-Object TimeCreated, Id, ProviderName | Format-Table -AutoSize | Out-String -Width 200
  $wu = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WindowsUpdateClient'; StartTime = $t0 } -ErrorAction SilentlyContinue
  "eventos_windowsupdateclient=" + @($wu).Count
}

# --- 6) configuracion / estado (equivale al `reg query`+`schtasks` de WE0-10) ---
Salida 'sistema\schtasks.txt'   { schtasks /query /fo LIST /v }
Salida 'sistema\ipconfig.txt'   { ipconfig /all; route print }
Salida 'sistema\systeminfo.txt' { systeminfo }
Salida 'sistema\servicios.txt'  { Get-Service Sysmon64, WazuhSvc, WinDefend, wuauserv, UsoSvc, sshd -ErrorAction SilentlyContinue | Format-Table Name, Status, StartType -AutoSize | Out-String -Width 200 }
Salida 'sistema\powercfg.txt'   { powercfg /query SCHEME_CURRENT SUB_SLEEP }
Salida 'sistema\procesos.txt'   { tasklist /v }
Salida 'sistema\defender.txt'   { try { Get-MpComputerStatus -ErrorAction Stop | Format-List | Out-String } catch { 'Get-MpComputerStatus: ' + $_.Exception.Message } }
Salida 'sistema\reg_windowsupdate.txt' { reg query 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /s }
Salida 'sistema\reg_run.txt' {
  reg query 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' /s
  reg query 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' /s
}
Salida 'sistema\whoami.txt'     { whoami /all }

# --- 7) MANIFEST del invitado (sha256 de cada fichero recogido) -------------
$man = New-Object System.Collections.Generic.List[string]
$man.Add("fichero`tbytes`tsha256")
Get-ChildItem -LiteralPath $Stage -Recurse -File | Sort-Object FullName | ForEach-Object {
  if ($_.Name -eq 'MANIFEST_INVITADO.tsv' -or $_.Name -eq 'AVISOS.txt') { return }
  $rel = $_.FullName.Substring($Stage.Length).TrimStart('\')
  $h = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower()
  $man.Add(("{0}`t{1}`t{2}" -f $rel, $_.Length, $h))
}
$aviso | Set-Content -LiteralPath (Join-Path $Stage 'AVISOS.txt') -Encoding UTF8
$man | Set-Content -LiteralPath (Join-Path $Stage 'MANIFEST_INVITADO.tsv') -Encoding UTF8

Write-Output ("COSECHA_INVITADO_FICHEROS=" + ($man.Count - 1))
Write-Output ("COSECHA_INVITADO_AVISOS=" + $aviso.Count)
foreach ($a in $aviso) { Write-Output ("AVISO " + $a) }
Write-Output 'COSECHA_INVITADO_OK'
