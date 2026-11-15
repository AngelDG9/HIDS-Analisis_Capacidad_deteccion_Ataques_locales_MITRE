# ============================================================================
# deploy_windows.ps1 - despliegue IDEMPOTENTE y REVERSIBLE del bloque W3
# Bloque `windows-legit-prep`. Se ejecuta en el HOST (no en el invitado).
# ----------------------------------------------------------------------------
# Que despliega (todo bajo C:\Users\angel\ghosts-client salvo lo indicado):
#   - cliente GHOSTS Windows (`ghosts.exe` + libs; se excluye `app.publish`, que es la
#     copia de publicacion ClickOnce y no la usa el ejecutable)
#   - `config\application.json` (API en http://192.168.65.1:5000/api)
#   - `nlog.config` (consola WARN, app.log 1 MB x 20)
#   - `config\timeline.d{1,2,3}.json` (recetas W1) y `config\timeline.json` = d1
#   - `recetas\{bloques_windows.env,calendario_windows.json}` (misma fuente que el keepalive)
#   - `tfg_keepalive_windows.ps1`, `instalar_tareas_windows.ps1`, `verificar_windows.ps1`,
#     `preparar_invitado_windows.ps1`
#   - `C:\lab-legit\campana\{casos_windows.md,campana_windows.csv}`
#   - `C:\Users\angel\Documentos\errores.log` (vacio; nunca se trunca)
#   - alias `intranet.local` en hosts (idempotente)
#   - tareas `TFG-WinLegit-Actividad` (angel, Medium) y `TFG-WinLegit-Keepalive` (SYSTEM)
#
# IDEMPOTENCIA: dos `-Phase apply` seguidos dejan el MISMO `MANIFEST_SHA256`
# (la huella excluye logs, instance y client.out*). R-W16 / CA-W11.
#
# REVERSIBLE: `-Phase revert` desregistra las tareas y borra todo lo anterior; deja
# `RESIDUOS=0`. NO toca `C:\lab-legit\tools` (historico) ni la linea de hosts (existia antes).
#
# SIN SECRETOS: el despliegue NO usa ninguna contrasena (la tarea de actividad va en
# modo Interactive; el snapshot tiene autologon de `angel` desde B1.0-SSH `-gui`).
#
# Uso (HOST):
#   powershell -NoProfile -ExecutionPolicy Bypass -File Soporte\Laboratorio\windows\deploy_windows.ps1 -Phase apply
#   ... -Phase hash | status | verify | revert
# ============================================================================
[CmdletBinding()]
param(
  [ValidateSet('apply', 'revert', 'status', 'verify', 'hash')]
  [string]$Phase = 'status',
  # Deja el staging (ZIP) en el host para inspeccion.
  [switch]$MantenerStaging,
  # Directorio del cliente Windows en el HOST. T2b-2 fija como DEFECTO el build 8.3.1
  # (el cliente final de la ventana); el ZIP publicado 8.0.0 sigue disponible pasando
  # `-ClienteDir` de forma explícita.
  [string]$ClienteDir = 'D:\TFG-VMs\material-ghosts\client-windows\build-v8.3.1\client'
)

$ErrorActionPreference = 'Stop'

$Repo    = 'D:\TFG\HIDS-Analisis_Capacidad_deteccion_Ataques_locales_MITRE'
$Win     = Join-Path $Repo 'Soporte\Laboratorio\windows'
$Cfg     = Join-Path $Win 'client_config'
$Recetas = Join-Path $Win 'recetas'
$Campana = Join-Path $Win 'campana'
$Guest   = Join-Path $Win 'guest'
$ClienteHost = $ClienteDir

$Ssh = 'C:\Program Files\Git\usr\bin\ssh.exe'
$Scp = 'C:\Program Files\Git\usr\bin\scp.exe'
$Key = Join-Path $env:USERPROFILE '.ssh\id_ed25519_tfg_win'
$Target = 'angel@192.168.65.130'

$RDir    = 'C:\Users\angel\ghosts-client'
$RCamp   = 'C:\lab-legit\campana'
# OJO (hallazgo W3): el cliente GHOSTS VACIA `C:\Users\angel\AppData\Local\Temp` mientras
# corre. Los ficheros transitorios del deploy van a `C:\Windows\Temp` (no los toca).
$RTmp    = 'C:/Windows/Temp'
$RPrep   = "$RTmp/preparar_invitado_windows.ps1"
$RZip    = "$RTmp/tfg-win-legit.zip"
$RTareas = 'C:/Users/angel/ghosts-client/instalar_tareas_windows.ps1'
$RVerif  = 'C:/Users/angel/ghosts-client/verificar_windows.ps1'
$RKa     = 'C:/Users/angel/ghosts-client/tfg_keepalive_windows.ps1'

$TareaAct = 'TFG-WinLegit-Actividad'
$TareaKa  = 'TFG-WinLegit-Keepalive'

$Stage   = Join-Path $env:TEMP 'opencode\tfg-win-legit'
$Payload = Join-Path $Stage 'payload'
$Zip     = Join-Path $Stage 'payload.zip'
# G-8: registro del ultimo despliegue aplicado (huella del payload + manifiesto +
# huella de tareas). Un 2.o `apply` con el MISMO payload y el MISMO manifiesto NO
# re-sube ni re-registra nada (solo aplica lo que falte).
$DeployState = Join-Path $Win 'legit\evidencia\despliegue_actual.json'

function Ts { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
function Log([string]$m) { Write-Output "[$(Ts)] $m" }

function Invoke-Remote([string]$Cmd, [switch]$PermitirFallo) {
  $eap = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  $out = & $Ssh -i $Key -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR $Target $Cmd 2>&1
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $eap
  $txt = (($out | Out-String).Trim())
  if (-not $PermitirFallo -and $rc -ne 0) { throw "ssh rc=$rc :: $Cmd`n$txt" }
  return $txt
}

function Invoke-RemoteStdin([string]$Cmd, [string]$Texto) {
  $eap = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  $out = $Texto | & $Ssh -i $Key -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR $Target $Cmd 2>&1
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $eap
  $txt = (($out | Out-String).Trim())
  if ($rc -ne 0) { throw "ssh(stdin) rc=$rc :: $Cmd`n$txt" }
  return $txt
}

function Copy-ToGuest([string]$Local, [string]$Remoto) {
  $eap = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  $out = & $Scp -i $Key -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR $Local "${Target}:$Remoto" 2>&1
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $eap
  if ($rc -ne 0) { throw "scp rc=$rc :: $Local -> $Remoto`n$(($out | Out-String).Trim())" }
}

function Assert-Ssh {
  $w = Invoke-Remote 'whoami' -PermitirFallo
  if ($w -notmatch 'angel') { throw "el invitado no responde como angel (whoami='$w')" }
  Log "SSH OK ($w)"
}

function Detener-Actividad {
  Invoke-Remote "schtasks /end /tn $TareaAct" -PermitirFallo | Out-Null
  Invoke-Remote 'taskkill /f /im ghosts.exe' -PermitirFallo | Out-Null
  Start-Sleep -Seconds 2
}

function Build-Payload {
  if (-not (Test-Path (Join-Path $ClienteHost 'ghosts.exe'))) { throw "falta el cliente Windows en $ClienteHost" }
  $exeI = Get-Item (Join-Path $ClienteHost 'ghosts.exe')
  $domI = Get-Item (Join-Path $ClienteHost 'ghosts.domain.dll') -ErrorAction SilentlyContinue
  $verExe = [string]$exeI.VersionInfo.FileVersion
  $verDom = if ($domI) { [string]$domI.VersionInfo.FileVersion } else { 'AUSENTE' }
  $shaExe = (Get-FileHash -LiteralPath $exeI.FullName -Algorithm SHA256).Hash.ToLower()
  $shaDom = if ($domI) { (Get-FileHash -LiteralPath $domI.FullName -Algorithm SHA256).Hash.ToLower() } else { 'AUSENTE' }
  Log "cliente_origen=$ClienteHost"
  Log "CLIENTE_HOST ghosts_exe=$verExe sha256=$shaExe"
  Log "CLIENTE_HOST ghosts_domain=$verDom sha256=$shaDom"
  foreach ($f in @('application.json', 'nlog.config')) {
    if (-not (Test-Path (Join-Path $Cfg $f))) { throw "falta client_config\$f" }
  }
  foreach ($f in @('w1.json', 'w2.json', 'w3.json', 'bloques_windows.env', 'calendario_windows.json')) {
    if (-not (Test-Path (Join-Path $Recetas $f))) { throw "falta recetas\$f (W1)" }
  }
  foreach ($f in @('casos_windows.md', 'campana_windows.csv')) {
    if (-not (Test-Path (Join-Path $Campana $f))) { throw "falta campana\$f (W2)" }
  }
  foreach ($f in @('tfg_keepalive_windows.ps1', 'instalar_tareas_windows.ps1', 'verificar_windows.ps1', 'preparar_invitado_windows.ps1')) {
    if (-not (Test-Path (Join-Path $Guest $f))) { throw "falta guest\$f" }
  }

  # Auditoria 2026-11-15: el prep real dejo `payload\campana` como un FICHERO (el CSV) en lugar de
  # una carpeta con los 2 ficheros, y `robocopy campana` fallo en el invitado (rc=16). En
  # aislado el mismo codigo funciona: lo mas probable es que `Remove-Item -Recurse` sobre el
  # stage viejo (15 MB de DLL, con el antivirus del host escaneando) devuelva antes de que
  # NTFS termine de borrar y las carpetas recien creadas queden en estado raro. Ahora: (1) se
  # ESPERA a que el stage desaparezca, (2) las carpetas se crean con la API de .NET, (3) cada
  # fichero se copia a una ruta de FICHERO explicita (nunca a una carpeta que quiza no exista)
  # y (4) se VERIFICA la estructura antes de comprimir. Falla pronto y claro.
  if (Test-Path $Stage) {
    for ($i = 0; ($i -lt 40) -and (Test-Path $Stage); $i++) {
      Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue
      if (Test-Path $Stage) { Start-Sleep -Milliseconds 750 }
    }
    if (Test-Path $Stage) { throw "no se pudo limpiar el stage $Stage (algo lo tiene bloqueado)" }
  }
  [void][System.IO.Directory]::CreateDirectory((Join-Path $Payload 'client'))
  [void][System.IO.Directory]::CreateDirectory((Join-Path $Payload 'campana'))

  # Cliente (sin app.publish: es la copia de publicacion, no la usa ghosts.exe)
  $excluir = @('app.publish', 'logs', 'instance', 'client.out', 'client.out.1')
  foreach ($it in Get-ChildItem $ClienteHost -Force) {
    if ($excluir -contains $it.Name) { continue }
    if ($it.PSIsContainer) {
      Copy-Item -LiteralPath $it.FullName -Destination (Join-Path $Payload 'client') -Recurse -Force
    } else {
      Copy-Item -LiteralPath $it.FullName -Destination (Join-Path $Payload 'client') -Force
    }
  }
  $dst = Join-Path $Payload 'client'

  # Configuracion (repo = fuente de verdad)
  New-Item -ItemType Directory -Force -Path (Join-Path $dst 'config') | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $dst 'recetas') | Out-Null
  Copy-Item (Join-Path $Cfg 'application.json') (Join-Path $dst 'config\application.json') -Force
  Copy-Item (Join-Path $Cfg 'nlog.config')      (Join-Path $dst 'nlog.config') -Force
  foreach ($d in 1..3) {
    Copy-Item (Join-Path $Recetas "w$d.json") (Join-Path $dst "config\timeline.d$d.json") -Force
  }
  Copy-Item (Join-Path $Recetas 'w1.json') (Join-Path $dst 'config\timeline.json') -Force
  Copy-Item (Join-Path $Recetas 'bloques_windows.env')    (Join-Path $dst 'recetas\bloques_windows.env') -Force
  Copy-Item (Join-Path $Recetas 'calendario_windows.json') (Join-Path $dst 'recetas\calendario_windows.json') -Force

  # Scripts del invitado (quedan desplegados y entran en la huella)
  foreach ($f in @('tfg_keepalive_windows.ps1', 'instalar_tareas_windows.ps1', 'verificar_windows.ps1', 'preparar_invitado_windows.ps1')) {
    Copy-Item (Join-Path $Guest $f) (Join-Path $dst $f) -Force
  }

  # Documentos de la campana (pre-registro; los casos W-XX los crea la receta)
  foreach ($f in @('casos_windows.md', 'campana_windows.csv')) {
    Copy-Item -LiteralPath (Join-Path $Campana $f) -Destination (Join-Path (Join-Path $Payload 'campana') $f) -Force
  }
  # Verificacion estructural del payload ANTES de comprimir (falla pronto y claro).
  if (-not (Test-Path -LiteralPath (Join-Path $Payload 'campana') -PathType Container)) {
    throw "payload mal formado: '$Payload\campana' no es una carpeta"
  }
  foreach ($f in @('casos_windows.md', 'campana_windows.csv')) {
    if (-not (Test-Path -LiteralPath (Join-Path (Join-Path $Payload 'campana') $f) -PathType Leaf)) {
      throw "payload mal formado: falta campana\$f"
    }
  }
  if (-not (Test-Path -LiteralPath (Join-Path $Payload 'client\ghosts.exe') -PathType Leaf)) {
    throw "payload mal formado: falta client\ghosts.exe"
  }

  if (Test-Path $Zip) { Remove-Item -LiteralPath $Zip -Force }
  # T2b-1b: `Compress-Archive` falló una vez con "no se pudo encontrar el archivo"
  # (fichero bloqueado un instante por el escaneo del host) y abortó `prep`. Se usa
  # `ZipFile::CreateFromDirectory`, que recorre el árbol de forma secuencial y no
  # depende del pipeline de cmdlets. Mismo layout (items en la raiz del zip).
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [System.IO.Compression.ZipFile]::CreateFromDirectory($Payload, $Zip,
    [System.IO.Compression.CompressionLevel]::Optimal, $false)
  if (-not (Test-Path $Zip)) { throw "no se genero $Zip" }
  $mb = [math]::Round((Get-Item $Zip).Length / 1MB, 1)
  Log "payload construido: $Zip ($mb MB)"
}

function Get-Manifiesto {
  return (Invoke-Remote "powershell -NoProfile -ExecutionPolicy Bypass -File `"$RVerif`" -Manifiesto")
}

function Get-PayloadFingerprint {
  # Huella del payload LOCAL (rutas relativas + sha256 de cada fichero). Sirve para
  # decidir si un 2.o `apply` tiene algo nuevo que subir (G-8).
  $items = @(Get-ChildItem -LiteralPath $Payload -Recurse -File -Force | Sort-Object FullName)
  $lineas = @($items | ForEach-Object {
      $rel = $_.FullName.Substring($Payload.Length).TrimStart('\', '/').ToLower()
      $h = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower()
      "$rel`t$h"
    })
  $txt = ($lineas -join "`n")
  return [System.BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::Create().ComputeHash(
      [System.Text.Encoding]::UTF8.GetBytes($txt))).Replace('-', '').ToLower()
}

function Clear-ResiduosGuest {
  # G-2: el snapshot/prep debe quedar sin residuos de campana. Solo se borran
  # ficheros VOLATILES (fuera del manifiesto): client.out*, armado/stop.flag,
  # instance\ y logs\ (los recrea el cliente/keepalive). `heartbeat.seq` NO se borra
  # aqui: si el deploy ocurre en `arm`, el bucle debe continuar su `seq` (si no, el
  # sink veria una bajada legitima como `ROTA_SEQ`). `prep` lo archiva antes.
  # T2b-1b: se manda por STDIN (no como linea de comandos del host), que es lo que
  # exige la regla del incidente de Defender. OJO: `powershell -Command -` ejecuta
  # sentencia a sentencia; NO admite bloques `foreach { ... }` multilinea (se quedaba
  # en silencio sin hacer nada). Por eso son tres sentencias completas.
  $script = @'
$b = 'C:\Users\angel\ghosts-client'
Remove-Item -LiteralPath @((Join-Path $b 'client.out'), (Join-Path $b 'client.out.1'), (Join-Path $b 'armado.flag'), (Join-Path $b 'stop.flag')) -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath @((Join-Path $b 'instance'), (Join-Path $b 'logs')) -Recurse -Force -ErrorAction SilentlyContinue
Write-Output 'LIMPIEZA_OK'
'@
  $out = ''
  try { $out = Invoke-RemoteStdin 'powershell -NoProfile -ExecutionPolicy Bypass -Command -' $script }
  catch { $out = "ERROR $($_.Exception.Message)" }
  Log ("residuos invitado: " + (($out -replace '\s+', ' ').Trim()))
}

# --- fases -----------------------------------------------------------------
Assert-Ssh

switch ($Phase) {

  'apply' {
    # G-8: primero se construye el payload (sin tocar el invitado) para calcular su
    # huella. Si coincide con la del ultimo despliegue Y el manifiesto del invitado
    # es el mismo, no hay nada que hacer: NO se sube el payload ni se re-registran
    # tareas (un 2.o `arm` es inocuo).
    Log 'apply: construyendo payload (huella)'
    Build-Payload
    $fp = Get-PayloadFingerprint
    $skip = $false
    if (Test-Path $DeployState) {
      try {
        $st = Get-Content -Raw $DeployState | ConvertFrom-Json
        if ($st.payload_sha256 -eq $fp -and $st.manifest_sha256) {
          $manAct = Get-Manifiesto
          $act = if ($manAct -match 'MANIFEST_SHA256=([0-9a-f]+)') { $Matches[1] } else { '' }
          if ($act -and $act -eq $st.manifest_sha256) {
            $skip = $true
            Write-Output "DEPLOY_SKIP=1 payload_sha256=$fp manifest_sha256=$act"
            Log 'apply: SKIP (payload y manifiesto ya desplegados; no se sube ni se re-registran tareas)'
          }
        }
      } catch {
        Log "apply: estado de despliegue ilegible ($($_.Exception.Message)); se despliega completo"
      }
    }

    if (-not $skip) {
      Log 'apply: parando actividad/keepalive previos'
      Invoke-Remote "schtasks /end /tn $TareaKa" -PermitirFallo | Out-Null
      Detener-Actividad
      Clear-ResiduosGuest

      Log 'apply: subiendo payload'
      Copy-ToGuest (Join-Path $Guest 'preparar_invitado_windows.ps1') $RPrep
      Copy-ToGuest $Zip $RZip

      Log 'apply: preparando el invitado (carpetas, campana, errores.log, hosts, payload)'
      $prep = Invoke-Remote "powershell -NoProfile -ExecutionPolicy Bypass -File `"$RPrep`" -PayloadZip `"$RZip`" -LimpiarCampana"
      Write-Output $prep
      if ($prep -notmatch 'RESULT=PASS') { throw 'preparar_invitado_windows.ps1 no devolvio RESULT=PASS' }

      Log 'apply: registrando tareas (actividad=angel/Interactive/Medium; keepalive=SYSTEM)'
      $tareas = Invoke-Remote "powershell -NoProfile -ExecutionPolicy Bypass -File `"$RTareas`""
      Write-Output $tareas
      if ($tareas -notmatch 'TAREAS_FINGERPRINT=') { throw 'instalar_tareas_windows.ps1 no devolvio huella' }

      # F-1: el UNICO emisor del latido es el bucle `-Loop`. `-Once` ya no emite
      # (era el segundo escritor que rompia `seq`). Aqui se arranca la tarea del bucle.
      # T2b-1b: puede quedar una instancia `-Once` de la tarea VIEJA (disparador de 5 min)
      # que, con `MultipleInstances=IgnoreNew`, impide arrancar el `-Loop` ("currently
      # running"). Se mata la instancia y se arranca el bucle; se verifica `Running`.
      Log 'apply: arrancando el bucle keepalive (unico emisor del latido)'
      Invoke-Remote "schtasks /end /tn $TareaKa" -PermitirFallo | Out-Null
      Start-Sleep -Seconds 2
      $ka = Invoke-Remote "schtasks /run /tn $TareaKa" -PermitirFallo
      Start-Sleep -Seconds 6
      $kaEstado = Invoke-Remote "schtasks /query /tn $TareaKa /fo LIST" -PermitirFallo
      if ($kaEstado -notmatch '(?i)Status:\s*Running') {
        Log 'apply: keepalive NO Running tras run; segundo intento'
        Invoke-Remote "schtasks /end /tn $TareaKa" -PermitirFallo | Out-Null
        Start-Sleep -Seconds 2
        $ka = Invoke-Remote "schtasks /run /tn $TareaKa" -PermitirFallo
        Start-Sleep -Seconds 6
        $kaEstado = Invoke-Remote "schtasks /query /tn $TareaKa /fo LIST" -PermitirFallo
      }
      Write-Output $ka
      Write-Output ("KEEPALIVE_ESTADO=" + (($kaEstado -replace '\s+', ' ').Trim()))

      Log 'apply: verificando el invitado'
      $ver = Invoke-Remote "powershell -NoProfile -ExecutionPolicy Bypass -File `"$RVerif`" -SinCampana" -PermitirFallo
      Write-Output $ver

      $man = Get-Manifiesto
      Write-Output $man
      Invoke-Remote 'del /f /q C:\Windows\Temp\preparar_invitado_windows.ps1' -PermitirFallo | Out-Null

      $shaMan = if ($man -match 'MANIFEST_SHA256=([0-9a-f]+)') { $Matches[1] } else { '' }
      $fpTar = if ($tareas -match 'TAREAS_FINGERPRINT=([0-9a-f]+)') { $Matches[1] } else { '' }
      if ($shaMan) {
        [ordered]@{
          payload_sha256      = $fp
          manifest_sha256     = $shaMan
          tareas_fingerprint  = $fpTar
          aplicado_utc        = (Ts)
        } | ConvertTo-Json | Set-Content -Path $DeployState -Encoding utf8
        Log "apply: estado de despliegue guardado (payload=$fp manifest=$shaMan)"
      } else {
        Log 'apply AVISO: el invitado no devolvio MANIFEST_SHA256; no se guarda el estado (2.o apply no podra saltar)'
      }
    }

    if (-not $MantenerStaging) { Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue }
    Log 'apply: FIN'
  }

  'revert' {
    Log 'revert: subiendo el script de limpieza (C:\Windows\Temp)'
    Copy-ToGuest (Join-Path $Guest 'preparar_invitado_windows.ps1') $RPrep
    Log 'revert: desregistrando tareas'
    foreach ($n in @($TareaAct, $TareaKa)) {
      Invoke-Remote "schtasks /end /tn $n" -PermitirFallo | Out-Null
      Invoke-Remote "schtasks /delete /tn $n /f" -PermitirFallo | Out-Null
    }
    Log 'revert: borrando arboles y residuos'
    $rev = Invoke-Remote "powershell -NoProfile -ExecutionPolicy Bypass -File `"$RPrep`" -Revertir" -PermitirFallo
    Write-Output $rev
    Invoke-Remote 'del /f /q C:\Windows\Temp\preparar_invitado_windows.ps1' -PermitirFallo | Out-Null

    Log 'revert: comprobando cero residuos'
    $t1 = Invoke-Remote "schtasks /query /tn $TareaAct" -PermitirFallo
    $t2 = Invoke-Remote "schtasks /query /tn $TareaKa" -PermitirFallo
    $d1 = Invoke-Remote 'if exist C:\Users\angel\ghosts-client (echo SI) else (echo NO)'
    $d2 = Invoke-Remote 'if exist C:\lab-legit\campana (echo SI) else (echo NO)'
    $p  = Invoke-Remote 'tasklist /nh | findstr /i ghosts.exe' -PermitirFallo
    $tareasOk = ($t1 -match 'no se encuentra|cannot find|ERROR') -and ($t2 -match 'no se encuentra|cannot find|ERROR')
    $residuos = @()
    if (-not $tareasOk) { $residuos += 'tareas' }
    if ($d1 -match 'SI') { $residuos += 'ghosts-client' }
    if ($d2 -match 'SI') { $residuos += 'campana' }
    if ($p -match 'ghosts\.exe') { $residuos += 'proceso' }
    if ($residuos.Count -eq 0) {
      Write-Output 'REVERT_LIMPIO=1'
      Log 'revert: FIN (0 residuos)'
    } else {
      Write-Output ("REVERT_LIMPIO=0 residuos=" + ($residuos -join ','))
      Log 'revert: FIN CON RESIDUOS'
    }
  }

  'status' {
    Write-Output (Invoke-Remote "schtasks /query /tn $TareaAct /fo LIST" -PermitirFallo)
    Write-Output (Invoke-Remote "schtasks /query /tn $TareaKa /fo LIST" -PermitirFallo)
    Write-Output (Invoke-Remote 'tasklist /nh | findstr /i ghosts.exe' -PermitirFallo)
    Write-Output (Get-Manifiesto)
  }

  'verify' {
    Write-Output (Invoke-Remote "powershell -NoProfile -ExecutionPolicy Bypass -File `"$RVerif`"" -PermitirFallo)
  }

  'hash' {
    Write-Output (Get-Manifiesto)
  }
}
