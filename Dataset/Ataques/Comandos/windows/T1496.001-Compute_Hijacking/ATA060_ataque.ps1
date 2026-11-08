# ATA060 - T1496.001 Compute Hijacking (Windows)
# Manual (no hay atomic Windows aprovechable en el clon de ART para T1496.001).
# 4 trabajadores de computo (runspaces en el mismo proceso) durante 30 s.
# Guardarrail: 30 s y 4 trabajadores (cota del plan: <=120 s).
$ErrorActionPreference = 'Continue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null

function CpuNow { (Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 1).CounterSamples.CookedValue }
function MemNow { [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1024, 1) }

$cpuBefore = CpuNow
$memBefore = MemNow
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

$pool = [runspacefactory]::CreateRunspacePool(1, 4)
$pool.Open()
$end = (Get-Date).AddSeconds(30)
$workers = @()
1..4 | ForEach-Object {
    $p = [powershell]::Create()
    $p.RunspacePool = $pool
    [void]$p.AddScript({ param($e) $x = 0; while ((Get-Date) -lt $e) { $x = $x + 1 }; $x }).AddArgument($end)
    $h = $p.BeginInvoke()
    $workers += [pscustomobject]@{ PS = $p; H = $h }
}
Start-Sleep -Seconds 5
$during = @()
1..3 | ForEach-Object { $during += (CpuNow); Start-Sleep -Seconds 1 }
$memDuring = MemNow
$workers | ForEach-Object {
    try { [void]$_.PS.EndInvoke($_.H) } catch { }
    $_.PS.Dispose()
}
$pool.Close()

$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$cpuAvg = [math]::Round((($during | Measure-Object -Average).Average), 2)
@(
    "ata=ATA060",
    "tecnica=T1496.001",
    "fuente=propio",
    "t0=$t0",
    "t1=$t1",
    "workers=4",
    "duracion_objetivo_s=30",
    "cpu_before_pct=$([math]::Round($cpuBefore,2))",
    "cpu_during_samples=$($during -join ',')",
    "cpu_during_avg_pct=$cpuAvg",
    "mem_before_available_mb=$memBefore",
    "mem_during_available_mb=$memDuring",
    "delta_cpu_pct=$([math]::Round($cpuAvg - $cpuBefore,2))"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
@("t0=$t0", "t1=$t1") | Out-File -FilePath (Join-Path $ev 'times.log') -Encoding ascii
exit 0
