# ============================================================================
# watch_loop.ps1 - VIGILANTE del HOST durante la ventana legitima Windows (72 h)
# Bloque `windows-legit` (R-01 de la auditoria de plan.md). Espejo de
# `legitimo_72h/registrar_tareas.ps1` (watch cada 30 min) pero como UN solo bucle.
# ----------------------------------------------------------------------------
# Antes NO existia ninguna tarea que ejecutase la fase `watch` cada 30 min: el controlador
# tenia la fase pero nadie la llamaba (la prueba de 2 h hizo 5 chequeos A MANO).
#
# Que hace:
#   - Un chequeo `windows_legit_host_control.ps1 -Phase watch` por tick, en
#     t0 + k*IntervaloSeg (k = 0..N-1; con 72 h y 30 min => N = 144).
#   - NO abre SSH al invitado (lo garantiza la fase `watch`: lee el latido del chivato).
#   - Si el host se durmio/bloqueo y un tick ya paso entero => lo registra como SALTADO
#     (no intenta ponerse al dia con rafagas) y sigue con el siguiente.
#   - Si un chequeo devuelve ALARMA (rc != 0) escribe `ALARMA_<ts>.txt` visible en
#     `evidencia\` ademas de la linea del `vigilancia_windows.log` del controlador.
#   - Impide la suspension del PC mientras corre (SetThreadExecutionState).
#   - Un solo proceso (mutex): un segundo bucle sale sin hacer nada.
#   - Al terminar escribe `watch_loop_resumen.json` con ejecutados/saltados/alarmas y el
#     veredicto: OK si ejecutados >= N-4 (>= 140 de 144); si no, INCIDENCIA declarada
#     (los DATOS pueden seguir siendo validos: los decide el latido `heartbeat.jsonl`).
#
# Uso (HOST, sesion que NO se cierra; la contrasena del manager solo vive en la sesion):
#     $env:TFG_MANAGER_PW = Read-Host            # (o como prefieras; NUNCA a fichero)
#     powershell -NoProfile -ExecutionPolicy Bypass -File watch_loop.ps1
#   Lee t0/t1 de `evidencia\ventana_actual.json` (lo escribe `arm`), o con -T0/-T1.
#   Antes de t0 espera; pasado t1 termina.
#
# Pruebas: -Control <script stub> -IntervaloSeg 2 -SinPw (los tests lo usan).
# ASCII puro (PowerShell 5.1 sin BOM). Sin secretos.
# ============================================================================
[CmdletBinding()]
param(
  [string]$T0 = '',
  [string]$T1 = '',
  [int]$IntervaloSeg = 1800,
  # Controlador a ejecutar con `-Phase watch` (por defecto el del repo).
  [string]$Control = '',
  # Donde dejar el log, el resumen y las ALARMA_*.txt (por defecto legit\evidencia).
  [string]$OutDir = '',
  # SOLO PRUEBAS: no exige TFG_MANAGER_PW.
  [switch]$SinPw,
  # Minimo de chequeos ejecutados para "OK" (plan: 140 de 144).
  [int]$MinOk = -1
)

$ErrorActionPreference = 'Continue'
$Aqui = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Control) { $Control = Join-Path (Split-Path -Parent $Aqui) 'windows_legit_host_control.ps1' }
if (-not $OutDir)  { $OutDir = Join-Path $Aqui 'evidencia' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Log     = Join-Path $OutDir 'watch_loop.log'
$Estado  = Join-Path $OutDir 'watch_loop_estado.json'
$Resumen = Join-Path $OutDir 'watch_loop_resumen.json'

function Ts { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
function WLog([string]$m) {
  $l = "[$(Ts)] $m"
  Add-Content -Path $Log -Value $l -Encoding utf8
  Write-Output $l
}

if ($IntervaloSeg -lt 1) { throw 'IntervaloSeg debe ser >= 1' }

# --- ventana ---------------------------------------------------------------
if (-not $T0 -or -not $T1) {
  $vf = Join-Path $OutDir 'ventana_actual.json'
  if (-not (Test-Path $vf)) { WLog "FALLO: sin -T0/-T1 y sin $vf (ejecuta `arm` antes)"; exit 2 }
  try {
    $v = Get-Content -Raw -LiteralPath $vf | ConvertFrom-Json
    if (-not $T0) { $T0 = [string]$v.t0 }
    if (-not $T1) { $T1 = [string]$v.t1 }
  } catch { WLog "FALLO: no se pudo leer $vf"; exit 2 }
}
try {
  $ini = ([datetime]::Parse($T0, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal))
  $fin = ([datetime]::Parse($T1, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal))
} catch { WLog "FALLO: t0/t1 no validos ($T0 / $T1)"; exit 2 }
if ($fin -le $ini) { WLog 'FALLO: t1 <= t0'; exit 2 }
if (-not (Test-Path $Control)) { WLog "FALLO: no existe el controlador $Control"; exit 2 }
if (-not $SinPw -and [string]::IsNullOrEmpty($env:TFG_MANAGER_PW)) {
  WLog 'FALLO: falta TFG_MANAGER_PW en la sesion (la fase watch consulta el manager con sudo). No se escribe a fichero.'
  exit 2
}

# --- un solo bucle ----------------------------------------------------------
$mutex = $null
try {
  $creado = $false
  $mutex = New-Object System.Threading.Mutex($false, 'Global\TFG-WinLegit-WatchLoop', [ref]$creado)
  if (-not $mutex.WaitOne(0)) { WLog 'segunda instancia: ya hay un watch_loop en marcha; salgo sin hacer nada'; exit 3 }
} catch [System.Threading.AbandonedMutexException] {
  # el bucle anterior murio sin liberar: lo recogemos
} catch { WLog "mutex_error $($_.Exception.Message)"; exit 3 }

# --- impedir la suspension mientras corre -----------------------------------
try {
  Add-Type -Namespace TfgWin -Name Pw -MemberDefinition '[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint esFlags);' -ErrorAction Stop
  # ES_CONTINUOUS (0x80000000) | ES_SYSTEM_REQUIRED (0x1)
  [void][TfgWin.Pw]::SetThreadExecutionState([uint32]2147483649)
  WLog 'suspension del PC bloqueada mientras corra el watch_loop (SetThreadExecutionState)'
} catch { WLog "AVISO: no se pudo bloquear la suspension ($($_.Exception.Message)); confiar en el plan de energia" }

$n = [int][math]::Floor(($fin - $ini).TotalSeconds / $IntervaloSeg)
if ($MinOk -lt 0) { $MinOk = [math]::Max(1, $n - 4) }
WLog ("watch_loop arranca: t0=" + $ini.ToString('yyyy-MM-ddTHH:mm:ssZ') + " t1=" + $fin.ToString('yyyy-MM-ddTHH:mm:ssZ') +
      " intervalo_s=$IntervaloSeg ticks=$n min_ok=$MinOk control=$Control")

$ejecutados = 0; $saltados = 0; $alarmas = 0
$primera = ''; $ultima = ''

for ($k = 0; $k -lt $n; $k++) {
  $prog = $ini.AddSeconds($k * $IntervaloSeg)
  # esperar al tick (en trozos cortos: detecta saltos de reloj / suspension del host)
  while ($true) {
    $ahora = (Get-Date).ToUniversalTime()
    if ($ahora -ge $prog) { break }
    $falta = ($prog - $ahora).TotalSeconds
    Start-Sleep -Seconds ([int][math]::Max(1, [math]::Min(10, [math]::Ceiling($falta))))
  }
  $ahora = (Get-Date).ToUniversalTime()
  if ($ahora -ge $fin) { WLog "tick ${k}/${n} - ya paso t1; fin"; break }
  $tarde = [math]::Round(($ahora - $prog).TotalSeconds, 1)
  if ($tarde -ge $IntervaloSeg) {
    $saltados++
    WLog "tick $k/$n SALTADO programado=$($prog.ToString('HH:mm:ss'))Z tarde_s=$tarde (el PC estuvo parado/dormido?)"
    continue
  }
  $salida = ''
  $rc = -1
  try {
    $salida = (& powershell -NoProfile -ExecutionPolicy Bypass -File $Control -Phase watch 2>&1 | Out-String)
    $rc = $LASTEXITCODE
  } catch { $salida = "EXCEPCION: $($_.Exception.Message)" }
  $ejecutados++
  if (-not $primera) { $primera = Ts }
  $ultima = Ts
  $res = (($salida -split "`r?`n" | Where-Object { $_ -match 'chequeo ok=|ALARMA' } | Select-Object -First 1) -replace '\s+', ' ').Trim()
  if (-not $res) { $res = (($salida -replace '\s+', ' ').Trim()); if ($res.Length -gt 200) { $res = $res.Substring(0, 200) } }
  WLog "tick $k/$n rc=$rc tarde_s=$tarde :: $res"
  if ($rc -ne 0) {
    $alarmas++
    $f = Join-Path $OutDir ("ALARMA_" + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHHmmssZ') + ".txt")
    Set-Content -Path $f -Value ("tick $k/$n rc=$rc`r`n" + $salida) -Encoding utf8
    WLog "ALARMA visible en $f"
  }
  try {
    (@{ ts_utc = (Ts); tick = $k; de = $n; ejecutados = $ejecutados; saltados = $saltados; alarmas = $alarmas } | ConvertTo-Json -Compress) |
      Set-Content -Path $Estado -Encoding utf8
  } catch { }
}

$veredicto = if ($ejecutados -ge $MinOk) { 'OK' } else { 'INCIDENCIA' }
$r = [ordered]@{
  t0 = $ini.ToString('yyyy-MM-ddTHH:mm:ssZ'); t1 = $fin.ToString('yyyy-MM-ddTHH:mm:ssZ')
  intervalo_s = $IntervaloSeg; esperados = $n; ejecutados = $ejecutados; saltados = $saltados
  alarmas = $alarmas; min_ok = $MinOk; primera = $primera; ultima = $ultima; veredicto = $veredicto
  nota = 'INCIDENCIA no invalida los datos por si sola: lo decide el latido heartbeat.jsonl (huecos) y W-V1..W-V9'
}
($r | ConvertTo-Json) | Set-Content -Path $Resumen -Encoding utf8
WLog ("watch_loop FIN: esperados=$n ejecutados=$ejecutados saltados=$saltados alarmas=$alarmas veredicto=$veredicto")
try { [void][TfgWin.Pw]::SetThreadExecutionState([uint32]2147483648) } catch { }
try { if ($mutex) { $mutex.ReleaseMutex(); $mutex.Dispose() } } catch { }
exit 0
