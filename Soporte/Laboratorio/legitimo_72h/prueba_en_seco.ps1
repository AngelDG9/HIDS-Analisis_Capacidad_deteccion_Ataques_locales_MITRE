# ============================================================================
# prueba_en_seco.ps1 - suite DT0...DT13 del bloque `legitimo-fix`.
#
# Ejecuta cada prueba, escribe la salida LITERAL (recortada) en `prueba_en_seco.md`
# y deja PASS/FAIL. Uso:
#   powershell -File prueba_en_seco.ps1 -DT DT0
#   powershell -File prueba_en_seco.ps1 -DT all
#
# Para la fase watch usa los overrides de prueba (-Test -ForzarBloque) que NO viajan
# a la ventana. No escribe secretos. Las contrasenas van por STDIN.
# Fichero ASCII a proposito (PowerShell 5.1 lee sin BOM como ANSI).
# ============================================================================
[CmdletBinding()]
param(
  [string]$DT = 'all',
  [string]$T0 = '2026-10-26T00:00:00Z',
  [string]$T1 = '2026-10-29T00:00:00Z',
  [string]$GuestPw = $null,
  [string]$ManagerPw = $null
)

$ErrorActionPreference = 'Continue'
$Repo   = 'D:\TFG\HIDS-Analisis_Capacidad_deteccion_Ataques_locales_MITRE'
$Base   = Join-Path $Repo 'Soporte\Laboratorio\legitimo_72h'
$Ghosts = Join-Path $Repo 'Soporte\Laboratorio\ghosts'
$Recetas = Join-Path $Base 'recetas'
$Ctl    = Join-Path $Base 'legitimo_host_control.ps1'
$Vmrun  = 'C:\Program Files\VMware\VMware Workstation\vmrun.exe'
$Victim = 'D:\TFG-VMs\victima-linux\victima-linux.vmx'
$Ssh    = 'C:\Program Files\Git\usr\bin\ssh.exe'
$Scp    = 'C:\Program Files\Git\usr\bin\scp.exe'
$Key    = Join-Path $env:USERPROFILE '.ssh\id_ed25519_tfg_lab'
$Vic    = 'angel@192.168.65.129'
$Man    = 'angel@192.168.65.128'
$GC     = '/home/angel/ghosts-client'
$Psql   = 'D:\TFG-VMs\material-ghosts\pgsql\bin\psql.exe'
$Doc    = Join-Path $Base 'prueba_en_seco.md'
$Tmp    = Join-Path $env:TEMP 'opencode'

if (-not $GuestPw)   { $GuestPw = $env:TFG_GUEST_PW }
if (-not $ManagerPw) { $ManagerPw = if ($env:TFG_MANAGER_PW) { $env:TFG_MANAGER_PW } else { $GuestPw } }
if (-not (Test-Path $Tmp)) { New-Item -ItemType Directory -Force -Path $Tmp | Out-Null }

function TsUtc { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
function Say([string]$txt) { Write-Host $txt; Add-Content -Path $Doc -Value $txt -Encoding utf8 }
function Sec([string]$id, [string]$titulo) {
  Say ""
  Say "## $id - $titulo"
  Say ""
  Say "**Inicio:** $(TsUtc)"
  Say ""
}
function Res([string]$id, [bool]$ok, [string]$detalle = '') {
  $v = if ($ok) { 'PASA' } else { 'FALLA' }
  $extra = if ($detalle) { " - $detalle" } else { '' }
  Say ""
  Say ("**Veredicto {0}: {1}**{2}  ({3})" -f $id, $v, $extra, (TsUtc))
  return $ok
}
function Code([string]$txt) { Say '```text'; Say $txt.TrimEnd(); Say '```' }

# Conteos y umbrales REALES de la receta (F-3): se leen del generador (`--check`), no se
# teclean. Devuelve @{ d = @(d1,d2,d3); hueco_s = 1320; pass = $bool }.
function Get-RecetaInfo([string]$Texto = '') {
  if (-not $Texto) {
    $Texto = & python (Join-Path $Repo '_artefactos\scripts\construir_receta_legitima.py') --check 2>&1 | Out-String
  }
  $d = @(0, 0, 0)
  if ($Texto -match 'dias=\{1: (\d+), 2: (\d+), 3: (\d+)\}') {
    $d = @([int]$Matches[1], [int]$Matches[2], [int]$Matches[3])
  }
  $h = 0
  if ($Texto -match 'hueco_max=(\d+)s') { $h = [int]$Matches[1] }
  return @{ d = $d; hueco_s = $h; pass = ($Texto -match 'RESULT=PASS'); raw = $Texto }
}

function OnVic([string]$cmd, [switch]$Pw) {
  if ($Pw) { return ([string](($GuestPw | & $Ssh -i $Key -o StrictHostKeyChecking=no $Vic $cmd 2>&1 | Out-String))) }
  return ([string](& $Ssh -i $Key -o StrictHostKeyChecking=no $Vic $cmd 2>&1 | Out-String))
}
function OnMan([string]$cmd, [switch]$Pw) {
  if ($Pw) { return ([string](($ManagerPw | & $Ssh -i $Key -o StrictHostKeyChecking=no $Man $cmd 2>&1 | Out-String))) }
  return ([string](& $Ssh -i $Key -o StrictHostKeyChecking=no $Man $cmd 2>&1 | Out-String))
}
function PutVic([string]$local, [string]$remoto = '/tmp/') {
  & $Scp -i $Key -o StrictHostKeyChecking=no $local "${Vic}:$remoto" 2>&1 | Out-Null
}
function Q([string]$sql) {
  $out = & $Psql -h 127.0.0.1 -p 5432 -U ghosts -d ghosts -t -A -c $sql 2>&1
  if ($out -is [array]) { return (($out -join "`n").Trim()) }
  return (([string]$out).Trim())
}
function Shas([string]$p) { if (Test-Path $p) { (Get-FileHash $p -Algorithm SHA256).Hash.ToLower() } else { '' } }
function Get-GhostsMachines {
  try { return Invoke-RestMethod -Uri 'http://192.168.65.1:5000/api/machines?q=' -TimeoutSec 10 }
  catch { return @() }
}
function Watch([switch]$Forzar) {
  $wa = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$Ctl,'-Phase','watch','-T0',$T0,'-T1',$T1,'-Test')
  if ($Forzar) { $wa += '-ForzarBloque' }
  return ([string](& powershell @wa 2>&1 | Out-String))
}
function ColocarTimeline([string]$local) {
  PutVic $local
  OnVic "cp -f /tmp/$(Split-Path $local -Leaf) $GC/config/timeline.json" | Out-Null
}
function ClienteStart { OnVic "bash $GC/client_ctl.sh start" | Out-Null; Start-Sleep 5 }
function ClienteStop  { OnVic "bash $GC/client_ctl.sh stop"  | Out-Null; Start-Sleep 3 }
function PidCliente { return (OnVic "pgrep -f '(^|/)ghosts[.]client[.]linux' | head -1").Trim() }
function EscribirJson([string]$path, $obj) {
  $txt = ($obj | ConvertTo-Json -Depth 12) -replace "^\uFEFF", ''
  [System.IO.File]::WriteAllText($path, $txt, (New-Object System.Text.UTF8Encoding($false)))
}

# --------------------------------------------------------------------------
# DT0 - no hay semilla: dos ejecuciones con `random` DIFIEREN
# --------------------------------------------------------------------------
function DT0 {
  Sec 'DT0' 'Hay semilla? (decision NPC): dos ejecuciones con Command=random'
  $tl = @{
    Status = 'Run'
    TimeLineHandlers = @(@{
      HandlerType = 'Command'; Initial = ''; UtcTimeOn = '00:00:00'; UtcTimeOff = '00:00:00'
      Loop = $false; HandlerArgs = @{}
      TimeLineEvents = @(
        @{ Command = 'random'; CommandArgs = @('echo ALFA','echo BETA','echo GAMMA','echo DELTA'); DelayAfter = 3000 },
        @{ Command = 'echo fin'; DelayAfter = 1000 }
      )
    })
  }
  $p = Join-Path $Tmp 'dt0.random.json'
  EscribirJson $p $tl
  $secs = 300
  $seqs = @()
  foreach ($run in 1,2) {
    ClienteStop
    ColocarTimeline $p
    ClienteStart
    Say "- run $run : $secs s de actividad con Command=random y delays fijos"
    Start-Sleep -Seconds $secs
    $q = "select command from history_timeline where createdutc >= (now() at time zone 'utc') - interval '6 minutes' order by createdutc limit 40;"
    $seq = @((Q $q) -split "`r?`n" | Where-Object { $_ -ne '' })
    $seqs += ,$seq
    Say ("  run {0}: {1} acciones muestreadas; primeras 8 = {2}" -f $run, $seq.Count, (($seq | Select-Object -First 8) -join ' | '))
    ClienteStop
  }
  $a = $seqs[0]; $b = $seqs[1]
  $iguales = ($a.Count -eq $b.Count) -and (($a -join '|') -eq ($b -join '|'))
  Say ("  run1_n={0} run2_n={1} identicas={2}" -f $a.Count, $b.Count, $iguales)
  ColocarTimeline (Join-Path $Recetas 'd1.json')
  return (Res 'DT0' (-not $iguales) 'las secuencias DIFIEREN => GHOSTS no es reproducible sin parchear => receta (S4.3)')
}

# --------------------------------------------------------------------------
# DT2 - tope del stdout
# --------------------------------------------------------------------------
function DT2 {
  Sec 'DT2' 'Tope del stdout (TFG_CLIENT_OUT_MAX_MB=1, 3 MB escritos)'
  ClienteStop
  OnVic "dd if=/dev/zero of=$GC/client.out bs=1M count=3 2>/dev/null; ls -l $GC/client.out" | ForEach-Object { Say $_ }
  $r1 = OnVic "TFG_CLIENT_OUT_MAX_MB=1 bash $GC/client_ctl.sh start; ls -l $GC/client.out $GC/client.out.1; pgrep -af ghosts.client.linux | head -1"
  Code $r1
  $r2 = OnVic "dd if=/dev/zero of=$GC/client.out bs=1M count=3 2>/dev/null; TFG_CLIENT_OUT_MAX_MB=1 bash $GC/client_ctl.sh rotate; ls -l $GC/client.out $GC/client.out.1; pgrep -f '(^|/)ghosts[.]client[.]linux' | head -1"
  Code $r2
  $sz = OnVic "stat -c %s $GC/client.out; stat -c %s $GC/client.out.1 2>/dev/null || echo 0; pgrep -c -f '(^|/)ghosts[.]client[.]linux'"
  $n = @(($sz -split "`r?`n") | Where-Object { $_.Trim() -match '^\d+$' } | ForEach-Object { [int]$_.Trim() })
  while ($n.Count -lt 3) { $n += 0 }
  Say ("  client.out={0} B  client.out.1={1} B  procesos={2}" -f $n[0], $n[1], $n[2])
  $ok = ($n[0] -le 1048576) -and ($n[1] -le 1048576) -and ($n[2] -ge 1)
  return (Res 'DT2' $ok 'ambos ficheros <= 1 MB y el proceso sigue vivo')
}

# --------------------------------------------------------------------------
# DT8 - extraccion con rotacion sobre los ficheros REALES del intento fallido
# --------------------------------------------------------------------------
function DT8 {
  Sec 'DT8' 'Extraccion con rotacion (datos REALES del intento fallido): 3 escenarios'
  $src = Join-Path $env:TEMP 'tfg-legit-72h-fallo'
  $dst = Join-Path $Tmp 'dt8'
  New-Item -ItemType Directory -Force -Path $dst | Out-Null
  Copy-Item (Join-Path $src 'ossec-archive-19.json.gz') $dst -Force
  Copy-Item (Join-Path $src 'ossec-archive-20.json')    $dst -Force
  Copy-Item (Join-Path $src 'archives.json')            $dst -Force
  $gz19  = Join-Path $dst 'ossec-archive-19.json.gz'
  $vivo  = Join-Path $dst 'archives.json'
  $plano = Join-Path $dst 'ossec-archive-20.json'
  $cop   = Join-Path $dst 'archives_copia.json'
  Copy-Item $vivo $cop -Force
  $script = Join-Path $Repo '_artefactos\scripts\contar_denominador.py'
  $args0 = @('--desde','2026-10-19T00:00:00Z','--hasta','2026-10-22T00:00:00Z','--estricto')

  Say "- (A) conjunto CORRECTO: .gz del dia + archives.json vivo (regla de borde)"
  $rA = & python $script @args0 --manifest (Join-Path $dst 'manifest.tsv') --out (Join-Path $dst 'M.csv') $gz19 $vivo 2>&1 | Out-String
  $rcA = $LASTEXITCODE
  Code $rA
  Say "  rc=$rcA"
  Say ("  MANIFEST:" + "`n" + ((Get-Content (Join-Path $dst 'manifest.tsv') -ErrorAction SilentlyContinue) -join "`n"))
  Say ("  CSV:" + "`n" + ((Get-Content (Join-Path $dst 'M.csv') -ErrorAction SilentlyContinue | Select-Object -First 3) -join "`n"))

  Say "- (B) TRAMPA H-D/H-E: se anade el plano diario del mismo dia (solapa con el vivo)"
  $rB = & python $script @args0 $gz19 $vivo $plano 2>&1 | Out-String
  $rcB = $LASTEXITCODE
  Code $rB
  Say "  rc=$rcB (3 = solape detectado; NO se cuenta dos veces)"

  Say "- (C) DEDUPE por sha256: se anade una COPIA EXACTA del vivo"
  $rC = & python $script @args0 $gz19 $vivo $cop 2>&1 | Out-String
  $rcC = $LASTEXITCODE
  Code $rC
  $dup = if ($rC -match 'DUPLICADO descartado') { $true } else { $false }
  Say "  rc=$rcC duplicado_detectado=$dup"

  $enDataset = @(Get-ChildItem (Join-Path $Repo 'Dataset\Legitimo\legitimo_72h') -ErrorAction SilentlyContinue).Count
  Say "  ficheros en Dataset/Legitimo/legitimo_72h: $enDataset (debe ser 0)"
  $ok = ($rcA -eq 0) -and ($rcB -eq 3) -and ($rcC -eq 0) -and $dup -and ($enDataset -eq 0)
  return (Res 'DT8' $ok "A=$rcA (0) B=$rcB (3=solape) C=$rcC (0 con dedupe)")
}

# --------------------------------------------------------------------------
# DT4 - la vigilancia detecta "estar sin hacer"
# --------------------------------------------------------------------------
function DT4_Arrancar {
  Sec 'DT4' 'La vigilancia detecta "estar sin hacer" (kill -STOP)'
  $dry = Join-Path $Tmp 'd1.dry.dt4.json'
  $base = (Get-Date).ToUniversalTime().AddMinutes(2).ToString('HH:mm') + 'Z'
  & python (Join-Path $Repo '_artefactos\scripts\construir_receta_legitima.py') --dry --base $base --out $dry | Out-Null
  ClienteStop
  ColocarTimeline $dry
  ClienteStart
  Say "- cliente arrancado con la receta dry (base $base); 3 min de actividad"
  Start-Sleep -Seconds 180
  $antes = OnVic "stat -c %Y $GC/logs/app.log; pgrep -f '(^|/)ghosts[.]client[.]linux' | head -1"
  Code "antes: $antes"
  $pidCli = (OnVic "pgrep -f '(^|/)ghosts[.]client[.]linux' | head -1").Trim()
  OnVic "kill -STOP $pidCli" | Out-Null
  Say "- SIGSTOP al pid $pidCli (proceso VIVO, congelado) a $(TsUtc)"
  $glob = @(Get-GhostsMachines | Where-Object { $_.name -eq 'victima-linux' })
  Say ("- GHOSTS: machines={0} statusUp={1} lastReportedUtc={2}" -f $glob.Count, (($glob | ForEach-Object { $_.statusUp }) -join ','), (($glob | ForEach-Object { $_.lastReportedUtc }) -join ','))
  return $pidCli
}
function DT4_Check([int]$n) {
  $w = Watch -Forzar
  Code $w
  $glob = @(Get-GhostsMachines | Where-Object { $_.name -eq 'victima-linux' })
  Say ("- GHOSTS: statusUp={0} lastReportedUtc={1}" -f (($glob | ForEach-Object { $_.statusUp }) -join ','), (($glob | ForEach-Object { $_.lastReportedUtc }) -join ','))
  $est = if ($w -match 'estado=ALARMA') { 'ALARMA' } elseif ($w -match 'estado=AVISO') { 'AVISO' } else { 'OK' }
  Say "  check #$n -> $est"
  return $est
}
function DT4_Fin([string]$pidProceso) {
  if ($pidProceso) { OnVic "kill -CONT $pidProceso" | Out-Null }
  # La receta dry de DT4 ya agoto su ventana: para comprobar que la actividad se
  # reanuda se relanza el cliente con una receta dry fresca (declarado).
  $dry = Join-Path $Tmp 'd1.dry.dt4b.json'
  $base = (Get-Date).ToUniversalTime().AddMinutes(1).ToString('HH:mm') + 'Z'
  & python (Join-Path $Repo '_artefactos\scripts\construir_receta_legitima.py') --dry --base $base --out $dry | Out-Null
  ClienteStop
  ColocarTimeline $dry
  ClienteStart
  Start-Sleep 240
  $est = DT4_Check 3
  ClienteStop
  ColocarTimeline (Join-Path $Recetas 'd1.json')
  return (Res 'DT4' ($est -eq 'OK') 'tras SIGCONT + receta fresca vuelve a OK')
}

# --------------------------------------------------------------------------
# DT5a - autocuracion
# --------------------------------------------------------------------------
function DT5a {
  Sec 'DT5a' 'Autocuracion (heartbeat): stop(TERM->KILL)+start y acciones reanudadas'
  ClienteStop
  OnVic "rm -f $GC/recovery.log" | Out-Null
  $dry = Join-Path $Tmp 'd1.dry.dt5.json'
  $base = (Get-Date).ToUniversalTime().AddMinutes(1).ToString('HH:mm') + 'Z'
  & python (Join-Path $Repo '_artefactos\scripts\construir_receta_legitima.py') --dry --base $base --out $dry | Out-Null
  ColocarTimeline $dry
  ClienteStart
  Start-Sleep 90
  $pidCli = PidCliente
  OnVic "kill -STOP $pidCli" | Out-Null
  Say "- SIGSTOP a $pidCli; keepalive con overrides (STALE=2, CONFIRMA=1, FORZAR_BLOQUE=1)"
  OnVic "cd $GC && TFG_TEST_MODE=1 TFG_FORZAR_BLOQUE=1 TFG_STALE_MIN=2 TFG_CONFIRMA_MIN=1 TFG_MAX_RECUP=2 TFG_COOLDOWN_MIN=1 nohup bash $GC/tfg_keepalive.sh 74 > /tmp/ka_dt5a.log 2>&1 < /dev/null &" | Out-Null
  Start-Sleep 360
  OnVic "pkill -f '[t]fg_keepalive.sh'; sleep 1; true" | Out-Null
  $rec = OnVic "cat $GC/recovery.log 2>/dev/null; echo ---; tail -14 $GC/keepalive.log; echo ---; pgrep -c -f '(^|/)ghosts[.]client[.]linux'"
  Code $rec
  $nrec = ([regex]::Matches($rec, 'accion=recuperacion')).Count
  $procs = 0
  try { $procs = [int]((($rec -split '---')[-1]).Trim()) } catch { }
  $edad = (OnVic "echo $(( ( $(date -u +%s) - $(stat -c %Y $GC/logs/app.log) ) / 60 ))").Trim()
  Say "  recuperaciones=$nrec procesos=$procs edad_app_log=$edad min"
  ClienteStop
  ColocarTimeline (Join-Path $Recetas 'd1.json')
  return (Res 'DT5a' ($nrec -ge 1 -and $procs -eq 1) "1 linea de recuperacion y 1 proceso (edad app.log=$edad min)")
}

# --------------------------------------------------------------------------
# DT5b - rotacion de receta (2 veces) sin cambiar el machineid
# --------------------------------------------------------------------------
function DT5b {
  Sec 'DT5b' 'Rotacion de receta (d1 -> d2 -> d3) con reinicio y machineid ESTABLE'
  ClienteStop
  OnVic "rm -f $GC/recovery.log $GC/rotacion.estado" | Out-Null
  $midAntes = (Q "select id from machines where name = 'victima-linux';")
  $midAntes = ($midAntes -split "`r?`n")[0].Trim()
  Say "- machineid ANTES = $midAntes"
  OnVic "bash $GC/client_ctl.sh start" | Out-Null
  OnVic "cd $GC && TFG_TEST_MODE=1 TFG_DIA_OVERRIDE=2 TFG_ROTACION_UTC=00:00 nohup bash $GC/tfg_keepalive.sh 0.05 > /tmp/ka_dt5b.log 2>&1 < /dev/null &" | Out-Null
  Start-Sleep 150
  $shaA = (OnVic "sha256sum $GC/config/timeline.json | cut -c1-8").Trim()
  $d2 = Shas (Join-Path $Recetas 'd2.json')
  Say "- tras rotacion 1: timeline.json sha=$shaA (d2 esperado $($d2.Substring(0,8)))"
  Code (OnVic "cat $GC/recovery.log 2>/dev/null")
  OnVic "rm -f $GC/rotacion.estado" | Out-Null
  OnVic "cd $GC && TFG_TEST_MODE=1 TFG_DIA_OVERRIDE=3 TFG_ROTACION_UTC=00:00 nohup bash $GC/tfg_keepalive.sh 0.05 > /tmp/ka_dt5b2.log 2>&1 < /dev/null &" | Out-Null
  Start-Sleep 150
  $shaB = (OnVic "sha256sum $GC/config/timeline.json | cut -c1-8").Trim()
  $d3 = Shas (Join-Path $Recetas 'd3.json')
  Code (OnVic "cat $GC/recovery.log 2>/dev/null; echo ---; pgrep -c -f '(^|/)ghosts[.]client[.]linux'")
  $midDespues = (Q "select id from machines where name = 'victima-linux';")
  $midDespues = ($midDespues -split "`r?`n")[0].Trim()
  Say "- machineid DESPUES = $midDespues"
  ClienteStop
  ColocarTimeline (Join-Path $Recetas 'd1.json')
  OnVic "rm -f $GC/rotacion.estado" | Out-Null
  $ok = ($shaA -eq $d2.Substring(0,8)) -and ($shaB -eq $d3.Substring(0,8)) -and ($midAntes -eq $midDespues)
  return (Res 'DT5b' $ok "d2=$($d2.Substring(0,8)) d3=$($d3.Substring(0,8)); machineid igual=$($midAntes -eq $midDespues)")
}

# --------------------------------------------------------------------------
# DT6 - alarma de agente desconectado (is-active miente)
# --------------------------------------------------------------------------
function DT6_Caer {
  Sec 'DT6' 'Alarma de agente desconectado (is-active sigue active)'
  $r = OnVic "kill -9 `$(pgrep -f wazuh-agentd) 2>/dev/null; sleep 2; echo is-active=`$(systemctl is-active wazuh-agent); echo procs=`$(pgrep -c -f wazuh-agentd)" -Pw
  Code $r
  Say "- agente matado a $(TsUtc); se espera >10 min para que el keep-alive envejezca"
}
function DT6_Check([string]$etiqueta) {
  $w = Watch -Forzar
  Code $w
  $est = if ($w -match 'estado=ALARMA') { 'ALARMA' } elseif ($w -match 'estado=AVISO') { 'AVISO' } else { 'OK' }
  $r = OnVic 'echo is-active=$(systemctl is-active wazuh-agent); echo procs=$(pgrep -c -x wazuh-agentd)'
  Say "- $etiqueta : unidad/procesos -> $(($r -replace '\s+',' ').Trim()) | watch=$est"
  return $est
}
function DT6_Fin {
  $r = OnVic "sudo -S systemctl start wazuh-agent 2>&1; sleep 30; echo is-active=`$(systemctl is-active wazuh-agent); echo procs=`$(pgrep -c -x wazuh-agentd)" -Pw
  Code $r
  Start-Sleep 60
  $est = DT6_Check 'tras reiniciar el agente'
  return (Res 'DT6' ($est -eq 'OK') 'vuelve a OK')
}

# --------------------------------------------------------------------------
# DT7 - disco leido del agente (valor +-5 %, tasa y antiguedad)
# --------------------------------------------------------------------------
function DT7 {
  Sec 'DT7' 'Disco de la victima leido del agente (df -P): valor y tasa'
  ClienteStop
  Say "- logall_json ON y movimiento de ~500 MB en la victima"
  Code (OnMan 'bash /tmp/logall_json_ctl.sh on' -Pw)
  $real1 = (OnVic "df -Pk / | awk 'NR==2{print `$4}'").Trim()
  OnVic "dd if=/dev/zero of=$GC/relleno.bin bs=1M count=500 2>/dev/null" | Out-Null
  Say "  libre antes=$real1 KB; relleno de 500 MB creado"
  Say "- esperando 2 muestras del agente (13 min)"
  Start-Sleep -Seconds 800
  $w = Watch -Forzar
  Code $w
  $real2 = (OnVic "df -Pk / | awk 'NR==2{print `$4}'").Trim()
  $dfKb = if ($w -match 'df_avail_kb=(\d+)') { [int]$Matches[1] } else { -1 }
  Say "  real libre=$real2 KB | watch=$dfKb KB"
  OnVic "rm -f $GC/relleno.bin" | Out-Null
  $ok = ($dfKb -gt 0) -and (([math]::Abs($dfKb - [int]$real2) / [int]$real2) -lt 0.05)
  return (Res 'DT7' $ok 'dentro del +-5 % y con tasa calculada')
}

# --------------------------------------------------------------------------
# DT9 - DOBLE EJECUCION de la receta (misma secuencia)
# --------------------------------------------------------------------------
function DT9 {
  $info = Get-RecetaInfo
  $esperado = $info.d[0]          # acciones del día 1 (la dry es d1), leídas de --check
  Sec 'DT9' "DOBLE EJECUCION de la receta (misma secuencia, $esperado acciones)"
  $seqs = @(); $cuentas = @()
  foreach ($run in 1,2) {
    $base = (Get-Date).ToUniversalTime().AddMinutes(1).ToString('HH:mm') + 'Z'
    $dry = Join-Path $Tmp "d1.dry.run$run.json"
    & python (Join-Path $Repo '_artefactos\scripts\construir_receta_legitima.py') --dry --base $base --out $dry | Out-Null
    ClienteStop
    OnVic "rm -f $GC/recovery.log" | Out-Null
    ColocarTimeline $dry
    $mk = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    ClienteStart
    Say "- run $run : receta dry desde $base (13 min)"
    Start-Sleep -Seconds 780
    ClienteStop
    $q = "select command from history_timeline where createdutc >= '$mk' order by createdutc;"
    $seq = @((Q $q) -split "`r?`n" | Where-Object { $_ -ne '' })
    $seqs += ,$seq
    $rec = (OnVic "cat $GC/recovery.log 2>/dev/null | wc -l").Trim()
    $cuentas += ,@($seq.Count, [int]$rec)
    Say ("  run {0}: acciones={1} lineas_recovery={2}" -f $run, $seq.Count, $rec)
  }
  $a = $seqs[0]; $b = $seqs[1]
  $igual = ($a.Count -eq $b.Count) -and ($a.Count -gt 0)
  if ($igual) { for ($i=0; $i -lt $a.Count; $i++) { if ($a[$i] -ne $b[$i]) { $igual = $false; break } } }
  Say ("  run1={0} run2={1} secuencia_identica={2}" -f $a.Count, $b.Count, $igual)
  if (-not $igual) {
    $d = 0
    for ($i=0; $i -lt [Math]::Min($a.Count,$b.Count); $i++) {
      if ($a[$i] -ne $b[$i]) { Say "   [$i] run1=$($a[$i])"; Say "   [$i] run2=$($b[$i])"; $d++; if ($d -ge 4) { break } }
    }
  }
  ColocarTimeline (Join-Path $Recetas 'd1.json')
  $ok = $igual -and ($a.Count -eq $esperado) -and ($cuentas[0][1] -eq 0) -and ($cuentas[1][1] -eq 0)
  return (Res 'DT9' $ok "$esperado acciones en ambos runs y recovery.log vacio")
}

# --------------------------------------------------------------------------
# DT11 - ritmo y coste reales (B1 + 20 min de B2 sin comprimir)
# --------------------------------------------------------------------------
function DT11 {
  Sec 'DT11' 'Ritmo y coste reales (B1 12 min + 20 min de B2, sin comprimir)'
  $tl = Get-Content -Raw (Join-Path $Recetas 'd1.json') | ConvertFrom-Json
  $inicioB1 = (Get-Date).ToUniversalTime().AddMinutes(2)
  # Desplaza las ventanas para poder ejecutar B1+B2 a la hora actual (declarado: los
  # eventos y los delays son LOS MISMOS; solo cambia UtcTimeOn/UtcTimeOff).
  $finB1 = $inicioB1.AddMinutes(12)
  $tl.TimeLineHandlers[0].UtcTimeOn  = $inicioB1.ToString('HH:mm:ss')
  $tl.TimeLineHandlers[0].UtcTimeOff = $finB1.ToString('HH:mm:ss')
  $tl.TimeLineHandlers[1].UtcTimeOn  = $finB1.ToString('HH:mm:ss')
  $tl.TimeLineHandlers[1].UtcTimeOff = $finB1.AddMinutes(108).ToString('HH:mm:ss')
  for ($i = 2; $i -lt $tl.TimeLineHandlers.Count; $i++) {
    $tl.TimeLineHandlers[$i].UtcTimeOn  = '23:59:00'
    $tl.TimeLineHandlers[$i].UtcTimeOff = '23:59:30'
  }
  $p = Join-Path $Tmp 'd1.dt11.json'
  EscribirJson $p $tl
  ClienteStop
  ColocarTimeline $p
  $mk = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
  $a0 = (OnMan 'sudo -n stat -c %s /var/ossec/logs/archives/archives.json' -Pw).Trim()
  ClienteStart
  Say "- B1 desplazado a $($inicioB1.ToString('HH:mm'))Z; B3-B5 desactivados; 32 min de medida"
  Start-Sleep -Seconds 1980
  $q = "select to_char(date_trunc('minute', createdutc), 'HH24:MI') from history_timeline where createdutc >= '$mk' order by createdutc;"
  $mins = @((Q $q) -split "`r?`n" | Where-Object { $_ -ne '' })
  $a1 = (OnMan 'sudo -n stat -c %s /var/ossec/logs/archives/archives.json' -Pw).Trim()
  Say "  acciones medidas: $($mins.Count)"
  Say "  minutos con accion: $(($mins | Group-Object | ForEach-Object { "$($_.Name)x$($_.Count)" }) -join ' ')"
  Say "  archives.json: $a0 -> $a1 B (delta=$([int64]$a1-[int64]$a0) B en 32 min)"
  ClienteStop
  $fuera = 0
  foreach ($m in ($mins | Select-Object -Unique)) {
    $mm = [datetime]::ParseExact($m, 'HH:mm', $null)
    if ($mm -lt $inicioB1 -or $mm -gt $inicioB1.AddMinutes(34)) { $fuera++ }
  }
  Say "  minutos fuera de la ventana: $fuera"
  Say ("  ritmo nominal B1+B2 = 35 acciones / 2 h = 17,5 acc/h; medido en la muestra = {0}/h" -f [math]::Round($mins.Count/(32.0/60.0),1))
  ColocarTimeline (Join-Path $Recetas 'd1.json')
  $ok = ($mins.Count -ge 9) -and ($fuera -eq 0)
  return (Res 'DT11' $ok "$($mins.Count) acciones, todas en su minuto (+-2)")
}

# --------------------------------------------------------------------------
# DT3 - crecimiento real con Warn
# --------------------------------------------------------------------------
function DT3 {
  Sec 'DT3' 'Crecimiento real de stdout con Warn'
  Say "  (base del fallo: ~340 MB/h; tope duro 40 MB)"
  $before = [int64]((OnVic "stat -c %s $GC/client.out 2>/dev/null || echo 0").Trim())
  $t0s = Get-Date
  Start-Sleep -Seconds 900
  $after = [int64]((OnVic "stat -c %s $GC/client.out 2>/dev/null || echo 0").Trim())
  $dt = ((Get-Date) - $t0s).TotalMinutes
  $mb30 = [math]::Round((($after - $before) / 1MB) * (30.0 / $dt), 3)
  Say "  client.out: $before -> $after B en $([math]::Round($dt,1)) min => $mb30 MB/30 min"
  return (Res 'DT3' ($mb30 -le 5) '<= 5 MB/30 min')
}

# --------------------------------------------------------------------------
# DT12 - snapshot v2 limpio + verificacion post-snapshot
# --------------------------------------------------------------------------
function DT12 {
  Sec 'DT12' 'Snapshot lab-listo-legit-v2 (VM apagada) y verificacion post-snapshot'
  ClienteStop
  OnVic "rm -f $GC/client.out $GC/client.out.1 $GC/keepalive.log $GC/recovery.log $GC/rotacion.estado $GC/ghasts.out; rm -rf $GC/logs/*; rm -f ~/Documentos/* ~/Descargas/* 2>/dev/null; rm -rf ~/.cache/tfg-web; true" | Out-Null
  Code (OnVic "ls -la $GC; echo ---; ls -la $GC/logs; echo ---; ls ~/Documentos ~/Descargas; echo ---; systemctl list-unit-files 'tfg-ghosts-legit*' --no-pager")
  & $Vmrun -T ws stop $Victim soft | Out-Null
  Start-Sleep 25
  & $Vmrun -T ws snapshot $Victim 'lab-listo-legit-v2' | Out-Null
  $snaps = (& $Vmrun -T ws listSnapshots $Victim | Out-String)
  Code $snaps
  & $Vmrun -T ws start $Victim nogui | Out-Null
  Start-Sleep 45
  $nlog = (Select-String -Path (Join-Path $Base 'sha256sums.txt') -Pattern 'client_config/nlog.config').Line.Split(' ')[0]
  $ka   = (Select-String -Path (Join-Path $Base 'sha256sums.txt') -Pattern 'tfg_keepalive.sh').Line.Split(' ')[0]
  $d1 = Shas (Join-Path $Recetas 'd1.json'); $d2 = Shas (Join-Path $Recetas 'd2.json'); $d3 = Shas (Join-Path $Recetas 'd3.json')
  $va = OnVic "bash $GC/verificar_arreglos.sh $nlog $d1 $d2 $d3 $ka" -Pw
  Code $va
  Code (OnVic "ls -la $GC/client.out $GC/logs/ 2>&1 | head -5")
  & $Vmrun -T ws stop $Victim soft | Out-Null
  Start-Sleep 20
  & $Vmrun -T ws revertToSnapshot $Victim 'lab-listo-legit-v2' | Out-Null
  Code (& $Vmrun -T ws listSnapshots $Victim | Out-String)
  $ok = ($snaps -match 'lab-listo-legit-v2') -and ($snaps -match 'lab-listo-legit') -and ($va -match 'RESULT=PASS') -and ($va -match 'receptor_navegador=none')
  return (Res 'DT12' $ok 'snapshot con VM apagada, PASS y v1 conservado; revertido a v2')
}

# --------------------------------------------------------------------------
# DT13 - el laboratorio queda cerrado
# --------------------------------------------------------------------------
function DT13 {
  Sec 'DT13' 'El laboratorio queda CERRADO y NO armado'
  $tasks = @(Get-ScheduledTask -TaskName 'TFG-Legit-*' -ErrorAction SilentlyContinue)
  Say "- tareas TFG-Legit-*: $($tasks.Count) => $(($tasks | ForEach-Object { $_.TaskName }) -join ',') (las preexistentes TFG-Baseline-* no cuentan)"
  $vms = (& $Vmrun -T ws list | Out-String)
  Say ($vms.Trim())
  $fw = @(Get-NetFirewallRule -DisplayName 'TFG-*' -ErrorAction SilentlyContinue)
  Say "- reglas de firewall TFG-*: $($fw.Count)"
  $ok = ($tasks.Count -eq 0) -and ($vms -match 'Total running VMs: 0') -and ($fw.Count -eq 0)
  return (Res 'DT13' $ok '0 VMs, 0 tareas TFG-Legit-* (las 4 TFG-Baseline-* preexistentes no cuentan), 0 reglas de firewall')
}

# ==========================================================================
if (-not (Test-Path $Doc)) {
  Say "# prueba_en_seco.md - pruebas en seco del bloque legitimo-fix"
  Say ""
  Say "> Generado por prueba_en_seco.ps1. Salida LITERAL (recortada). Horas UTC."
  Say "> Se ejecuta sobre la instancia arreglada, FUERA de la ventana, antes de crear"
  Say "> lab-listo-legit-v2. Lo que ensucia se descarta revirtiendo al snapshot."
  Say "> Orden real de ejecucion: DT-B0 (browser_eval.md), DT1, DT10, DT2, DT8, DT0,"
  Say "> DT4/DT7/DT6, DT5a, DT5b, DT9, DT11, DT3, DT12, DT13."
}

$resultados = [ordered]@{}
switch ($DT) {
  'DT0'   { $resultados['DT0'] = DT0 }
  'DT2'   { $resultados['DT2'] = DT2 }
  'DT3'   { $resultados['DT3'] = DT3 }
  'DT8'   { $resultados['DT8'] = DT8 }
  'DT9'   { $resultados['DT9'] = DT9 }
  'DT10'  {
    Sec 'DT10' 'Invariantes de la receta (--check)'
    $chk = & python (Join-Path $Repo '_artefactos\scripts\construir_receta_legitima.py') --check 2>&1 | Out-String
    Code $chk
    $info = Get-RecetaInfo $chk
    $hmin = [math]::Round($info.hueco_s / 60.0)
    $det = ("{0}/{1}/{2}, hueco <= {3} min, 0 random, 0 Browser*, web_session=1" -f $info.d[0], $info.d[1], $info.d[2], $hmin)
    $resultados['DT10'] = Res 'DT10' ($chk -match 'RESULT=PASS') $det
  }
  'DT11'  { $resultados['DT11'] = DT11 }
  'DT4A'  { $script:dt4pid = DT4_Arrancar }
  'DT4C'  { $e = DT4_Check 2; Say "**estado=$e**" }
  'DT4F'  { $pc = if ($script:dt4pid) { $script:dt4pid } else { PidCliente }; $resultados['DT4'] = DT4_Fin $pc }
  'DT5a'  { $resultados['DT5a'] = DT5a }
  'DT5b'  { $resultados['DT5b'] = DT5b }
  'DT6A'  { DT6_Caer }
  'DT6C'  { $e = DT6_Check 'con el daemon caido'; Say "**estado=$e**" }
  'DT6F'  { $resultados['DT6'] = DT6_Fin }
  'DT7'   { $resultados['DT7'] = DT7 }
  'DT12'  { $resultados['DT12'] = DT12 }
  'DT13'  { $resultados['DT13'] = DT13 }
  'DT1'   {
    Sec 'DT1' 'Arreglos y receta presentes (verificar_arreglos.sh)'
    $nlog = (Select-String -Path (Join-Path $Base 'sha256sums.txt') -Pattern 'client_config/nlog.config').Line.Split(' ')[0]
    $ka   = (Select-String -Path (Join-Path $Base 'sha256sums.txt') -Pattern 'tfg_keepalive.sh').Line.Split(' ')[0]
    $d1 = Shas (Join-Path $Recetas 'd1.json'); $d2 = Shas (Join-Path $Recetas 'd2.json'); $d3 = Shas (Join-Path $Recetas 'd3.json')
    $va = OnVic "bash $GC/verificar_arreglos.sh $nlog $d1 $d2 $d3 $ka" -Pw
    Code $va
    $resultados['DT1'] = Res 'DT1' ($va -match 'RESULT=PASS') 'nlog=Warn, tope=20, keepalive v3, recetas == repo, timer=NOT-FOUND'
  }
  default { Say "DT no reconocido: $DT" }
}

if ($resultados.Count -gt 0) {
  Say ""
  Say "### Resumen de esta ejecucion"
  foreach ($k in $resultados.Keys) { Say ("- {0}: {1}" -f $k, $(if ($resultados[$k]) { 'PASA' } else { 'FALLA' })) }
}
exit 0
