# ATA097 - T1565.003 Runtime Data Manipulation (Windows)
# Manual: WriteProcessMemory sobre un proceso PowerShell de juguete; cadena alterada y leida.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA097*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$toy = Join-Path $dir 'ATA097_toy.ps1'
if (-not (Test-Path $toy)) {
    'GUARDARRAIL: toy.ps1 no encontrado' | Out-File (Join-Path $ev 'efecto_local.txt') -Encoding ascii
    exit 2
}
$toyProc = Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$toy -PassThru
$addrFile = Join-Path $ev 'toy_addr.txt'
$outFile = Join-Path $ev 'toy_out.txt'
for ($i = 0; $i -lt 30; $i++) { if (Test-Path $addrFile) { break }; Start-Sleep -Milliseconds 500 }
if (-not (Test-Path $addrFile)) {
    'GUARDARRAIL: toy no arranco' | Out-File (Join-Path $ev 'efecto_local.txt') -Encoding ascii
    Stop-Process -Id $toyProc.Id -Force -ErrorAction SilentlyContinue
    exit 2
}
$addr = [IntPtr]([int64](Get-Content $addrFile -Raw).Trim())
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class Mem {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out IntPtr written);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
}
'@
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$man = [Text.Encoding]::ASCII.GetBytes('TFG-MANIPULATED-STRING')
$h = [Mem]::OpenProcess(0x1F0FFF, $false, $toyProc.Id)
$written = [IntPtr]::Zero
$okWrite = $false
if ($h -ne [IntPtr]::Zero) {
    $okWrite = [Mem]::WriteProcessMemory($h, $addr, $man, $man.Length, [ref]$written)
    [Mem]::CloseHandle($h) | Out-Null
}
Start-Sleep -Seconds 2
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
Stop-Process -Id $toyProc.Id -Force -ErrorAction SilentlyContinue
$lines = @()
if (Test-Path $outFile) { $lines = Get-Content $outFile -ErrorAction SilentlyContinue }
$last = ''
if ($lines.Count -gt 0) { $last = $lines[-1] }
$alterado = ($last -eq 'TFG-MANIPULATED-STRING')
@(
    "ata=ATA097", "tecnica=T1565.003", "fuente=manual",
    "t0=$t0", "t1=$t1", "pid=$($toyProc.Id)",
    "write_ok=$okWrite", "original=TFG-ORIGINAL-STRING",
    "manipulated=TFG-MANIPULATED-STRING", "ultima_lectura=$last",
    "alterado=$alterado"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
