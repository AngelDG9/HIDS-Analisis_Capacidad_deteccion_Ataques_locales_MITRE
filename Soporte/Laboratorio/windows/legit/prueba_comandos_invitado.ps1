# ============================================================================
# prueba_comandos_invitado.ps1 - ejecuta UNA A UNA las acciones de una receta, EN EL INVITADO
# ----------------------------------------------------------------------------
# Para que no vuelva a pasar lo del `curl --compressed`: el curl.exe de Windows se negaba a
# ejecutarse (rc=2) SIN enviar la peticion, el cliente GHOSTS lo registraba como una accion
# mas y nadie lo vio en 3 pruebas. Aqui se lanza cada `Command` de la receta tal y como lo
# lanza GHOSTS (`cmd.exe /c <texto exacto>`, cwd C:\Users\angel) y se anota su CODIGO DE
# SALIDA, el tiempo y el primer mensaje de error.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File prueba_comandos_invitado.ps1 `
#        -Timeline C:/Users/angel/ghosts-client/config/timeline.d1.json -Out C:/Users/angel/prueba_d1.csv
#
# Salida CSV: n, rc, timeout, segundos, comando(90), stderr(140).
# Lectura: las acciones con control de error (`& if errorlevel 1 (...)`) devuelven rc 0 aunque el
# comando interno falle (el rc es el del `echo` final): las que NO llevan control y salen con
# rc != 0 son FALLOS REALES. Un rc 0 con "is not recognized" en stderr tambien lo es.
#
# SOLO PRUEBAS en un invitado desechable (se revierte al snapshot): crea ficheros en
# C:\Users\angel. ASCII puro (PowerShell 5.1 sin BOM). Sin secretos.
# ============================================================================
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Timeline,
  [Parameter(Mandatory = $true)][string]$Out,
  [int]$TimeoutSeg = 40,
  [int]$Desde = 1,
  [int]$Hasta = 100000
)

$ErrorActionPreference = 'Continue'
$j = Get-Content -Raw -LiteralPath $Timeline | ConvertFrom-Json
$filas = New-Object System.Collections.Generic.List[string]
$filas.Add('n,rc,timeout,segundos,comando,stderr')

function Limpiar([string]$t, [int]$max) {
  if ($null -eq $t) { return '' }
  $x = ($t -replace '[\r\n\t]+', ' ' -replace '"', "'" -replace ',', ';').Trim()
  if ($x.Length -gt $max) { $x = $x.Substring(0, $max) }
  return $x
}

$n = 0
foreach ($h in $j.TimeLineHandlers) {
  foreach ($e in $h.TimeLineEvents) {
    $n++
    if ($n -lt $Desde -or $n -gt $Hasta) { continue }
    $cmd = [string]$e.Command
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'cmd.exe'
    $psi.Arguments = '/c ' + $cmd
    $psi.WorkingDirectory = 'C:\Users\angel'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardOutput = $true
    $psi.CreateNoWindow = $true
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $rc = -1; $to = 0; $err = ''
    try {
      $p = [System.Diagnostics.Process]::Start($psi)
      $tErr = $p.StandardError.ReadToEndAsync()
      $tOut = $p.StandardOutput.ReadToEndAsync()
      if (-not $p.WaitForExit($TimeoutSeg * 1000)) { try { $p.Kill() } catch { }; $to = 1 }
      else { $p.WaitForExit() }
      try { $rc = $p.ExitCode } catch { $rc = -2 }
      try { $err = $tErr.Result } catch { $err = '' }
    } catch { $err = 'EXCEPCION ' + $_.Exception.Message }
    $sw.Stop()
    $filas.Add(('{0},{1},{2},{3},"{4}","{5}"' -f $n, $rc, $to, [math]::Round($sw.Elapsed.TotalSeconds, 1), (Limpiar $cmd 90), (Limpiar $err 140)))
  }
}
$filas | Set-Content -LiteralPath $Out -Encoding ASCII
Write-Output ("ACCIONES_EJECUTADAS=" + ($filas.Count - 1))
Write-Output ("SALIDA=" + $Out)
