# ============================================================================
# TFG · HIDS — Actividad legítima de baseline Windows (fase-02b-baseline · §1.5)
# ============================================================================
# Espejo Windows de Soporte/Wazuh/Scripts/baseline_actividad.sh (Linux).
# Genera actividad BENIGNA y variada en C:\lab-legit\ durante N minutos y deja
# trazas en C:\lab-legit\baseline_log.txt con timestamps UTC.
#
# Uso:
#   powershell -NoProfile -ExecutionPolicy Bypass -File baseline_actividad_windows.ps1 -DurationMin 248
#
# Propiedades:
#   - Determinista (sin aleatoriedad), sin secretos, re-ejecutable.
#   - Sin utilidades de ataque: SOLO cmdlets nativos (FileSystem, Compress-Archive,
#     Get-FileHash, Get-WinEvent, Get-ItemProperty, Select-String). No usa
#     vssadmin/bcdedit/wbadmin/cipher/reg save ni nada de fase-03b.
#   - Ciclo cada ~300 s (5 min), igual que Linux.
#   - Formato del log (una línea por evento, UTC ISO8601):
#       # duracion_min=<N>
#       START <UTC ISO8601>
#       CYCLE <n> <UTC ISO8601>
#       ...
#       END <UTC ISO8601>
#   - El log vive en la RAÍZ de la carpeta base y NO se incluye en los backups.
# ============================================================================
[CmdletBinding()]
param(
  [int]$DurationMin = 248,
  [string]$Base = 'C:\lab-legit'
)

$ErrorActionPreference = 'Continue'
$IntervalSec = 300  # segundos entre ciclos (~5 min)

if ($DurationMin -le 0) { Write-Error 'DurationMin debe ser > 0'; exit 2 }

$Log    = Join-Path $Base 'baseline_log.txt'
$Work   = Join-Path $Base 'work'
$Backup = Join-Path $Base 'backup'
$Tools  = Join-Path $Base 'tools'

New-Item -ItemType Directory -Force -Path $Base, $Work, $Backup, $Tools | Out-Null

function TsUtc { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }

function Write-LogLine([string]$line) {
  for ($i = 0; $i -lt 5; $i++) {
    try { Add-Content -Path $Log -Value $line -Encoding ascii -ErrorAction Stop; return }
    catch { Start-Sleep -Milliseconds 200 }
  }
}

$Start = Get-Date
$End   = $Start.AddMinutes($DurationMin)

Write-LogLine "# duracion_min=$DurationMin"
Write-LogLine "START $(TsUtc)"

$n = 0
while ((Get-Date) -lt $End) {
  $n++

  try {
    New-Item -ItemType Directory -Force -Path $Work, $Backup, $Tools | Out-Null

    # 1) crear varios ficheros de texto
    foreach ($i in 1..5) {
      Set-Content -Path (Join-Path $Work ("doc_{0}.txt" -f $i)) `
                  -Value ("legit baseline cycle {0} file {1}" -f $n, $i) -Encoding ascii
    }

    # 2) leer los ficheros
    Get-Content (Join-Path $Work 'doc_*.txt') -ErrorAction SilentlyContinue | Out-Null

    # 3) escribir/append en uno de ellos
    Add-Content -Path (Join-Path $Work 'doc_1.txt') -Value ("append cycle {0}" -f $n) -Encoding ascii

    # 4) compresión/backup legítimo de work\ (equivalente de `tar`)
    $zip = Join-Path $Backup ("backup_ciclo_{0}.zip" -f $n)
    Compress-Archive -Path (Join-Path $Work '*') -DestinationPath $zip -Force -ErrorAction SilentlyContinue

    # 5) copiar / mover / borrar un temporal
    Copy-Item (Join-Path $Work 'doc_2.txt') (Join-Path $Work 'tmp_copy.txt')  -Force -ErrorAction SilentlyContinue
    Move-Item (Join-Path $Work 'tmp_copy.txt') (Join-Path $Work 'tmp_moved.txt') -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $Work 'tmp_moved.txt') -Force -ErrorAction SilentlyContinue

    # 6) búsqueda / filtrado / listado + hash (equivalente de find/grep/sha256sum)
    Get-ChildItem -Path $Work -Recurse -File -Filter '*.txt' -ErrorAction SilentlyContinue |
      Select-Object -ExpandProperty FullName | Sort-Object |
      Set-Content -Path (Join-Path $Work 'lista.txt') -Encoding ascii
    Select-String -Path (Join-Path $Work '*.txt') -Pattern 'cycle' -ErrorAction SilentlyContinue | Out-Null
    (Get-FileHash (Join-Path $Work 'doc_1.txt') -Algorithm SHA256).Hash |
      Set-Content -Path (Join-Path $Work 'doc_1.sha256') -Encoding ascii

    # 7) lectura del registro de eventos del sistema (equivalente de journalctl)
    Get-WinEvent -LogName System -MaxEvents 20 -ErrorAction SilentlyContinue | Out-Null

    # 8) inventario de programas instalados (equivalente de apt list --installed)
    Get-ItemProperty `
      -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', `
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `
      -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion | Out-Null

    # 9) limpieza legítima: conservar solo los 5 backups más recientes
    Get-ChildItem -Path (Join-Path $Backup 'backup_ciclo_*.zip') -ErrorAction SilentlyContinue |
      Sort-Object LastWriteTime -Descending | Select-Object -Skip 5 |
      Remove-Item -Force -ErrorAction SilentlyContinue
  }
  catch {
    Write-LogLine "# WARN ciclo ${n}: $($_.Exception.Message)"
  }

  Write-LogLine "CYCLE $n $(TsUtc)"

  $remaining = ($End - (Get-Date)).TotalSeconds
  if ($remaining -le 0) { break }
  $sleep = [Math]::Min([double]$IntervalSec, $remaining)
  Start-Sleep -Seconds ([int][Math]::Ceiling($sleep))
}

Write-LogLine "END $(TsUtc)"
$cycles = (Select-String -Path $Log -Pattern '^CYCLE ' -ErrorAction SilentlyContinue | Measure-Object).Count
Write-Output ("Baseline finalizado: {0} ciclos. Log: {1}" -f $cycles, $Log)
exit 0
