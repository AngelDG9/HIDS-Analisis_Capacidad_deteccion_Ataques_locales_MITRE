# ============================================================================
# prueba_once.ps1 - PRUEBA de F-1 (T2b-1b): `-Once` NO emite latido, NO toca
# `heartbeat.seq` y NO recrea `estado.json`. Se ejecuta EN EL INVITADO por ruta
# (no en la linea de comandos del host). Solo lectura + un ciclo `-Once`.
# ============================================================================
$ErrorActionPreference = 'Continue'
$d = 'C:\Users\angel\ghosts-client'

function Estado([string]$etiqueta) {
  Write-Output "--- $etiqueta ---"
  foreach ($f in @('heartbeat.seq', 'estado.json', 'keepalive.log')) {
    $p = Join-Path $d $f
    if (Test-Path $p) {
      $i = Get-Item $p
      $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower().Substring(0, 16)
      Write-Output ("{0} size={1} mtime={2} sha16={3}" -f $f, $i.Length, $i.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'), $h)
    } else {
      Write-Output "$f AUSENTE"
    }
  }
  $s = Join-Path $d 'heartbeat.seq'
  if (Test-Path $s) { Write-Output ("heartbeat.seq valor=" + (Get-Content -Raw -LiteralPath $s).Trim()) }
  # Instancias del bucle -Loop vivas (no debe cambiar).
  $n = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -and $_.CommandLine -match 'tfg_keepalive_windows\.ps1' -and $_.CommandLine -match '(?i)-Loop\b' }).Count
  Write-Output "ka_loop_instancias=$n"
}

Estado 'ANTES'
$lineasAntes = if (Test-Path (Join-Path $d 'keepalive.log')) { (Get-Content -LiteralPath (Join-Path $d 'keepalive.log')).Count } else { 0 }
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $d 'tfg_keepalive_windows.ps1') -Once
Write-Output "once_rc=$LASTEXITCODE"
Start-Sleep -Seconds 2
Estado 'DESPUES'
$lineasDespues = if (Test-Path (Join-Path $d 'keepalive.log')) { (Get-Content -LiteralPath (Join-Path $d 'keepalive.log')).Count } else { 0 }
Write-Output ("keepalive_log_lineas antes=$lineasAntes despues=$lineasDespues")
Write-Output '--- ULTIMA LINEA DEL LOG (debe decir modo=Once sin_latido sin_seq sin_estado) ---'
if (Test-Path (Join-Path $d 'keepalive.log')) { Get-Content -LiteralPath (Join-Path $d 'keepalive.log') -Tail 3 }
