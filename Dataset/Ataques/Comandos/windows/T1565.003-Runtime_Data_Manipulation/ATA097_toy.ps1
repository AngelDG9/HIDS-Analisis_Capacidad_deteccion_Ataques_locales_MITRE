$ErrorActionPreference = "Continue"
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class ToyMem {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint allocType, uint protect);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool VirtualFree(IntPtr addr, UIntPtr size, uint freeType);
}
'@
$addr = [ToyMem]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]256, 0x3000, 0x04)
$orig = [Text.Encoding]::ASCII.GetBytes("TFG-ORIGINAL-STRING")
[Runtime.InteropServices.Marshal]::Copy($orig, 0, $addr, $orig.Length)
Set-Content -Path "C:\lab-attack\ATA097\evidencias\toy_addr.txt" -Value $addr.ToInt64() -Encoding ascii
$end = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $end) {
    $bytes = New-Object byte[] 64
    [Runtime.InteropServices.Marshal]::Copy($addr, $bytes, 0, 64)
    $s = [Text.Encoding]::ASCII.GetString($bytes).Trim([char]0)
    Add-Content -Path "C:\lab-attack\ATA097\evidencias\toy_out.txt" -Value $s -Encoding ascii
    Start-Sleep -Milliseconds 500
}
[ToyMem]::VirtualFree($addr, [UIntPtr]0, 0x8000)
