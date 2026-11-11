$ErrorActionPreference = 'Continue'
$dll = 'C:\Users\angel\ghosts-client\ghosts.domain.dll'
$exe = 'C:\Users\angel\ghosts-client\ghosts.exe'
try { "DOMAIN_ASSEMBLY=" + [Reflection.AssemblyName]::GetAssemblyName($dll).Version.ToString() } catch { "DOMAIN_ASSEMBLY=ERROR $($_.Exception.Message)" }
try { "EXE_ASSEMBLY=" + [Reflection.AssemblyName]::GetAssemblyName($exe).Version.ToString() } catch { "EXE_ASSEMBLY=ERROR $($_.Exception.Message)" }
$out = 'C:\Windows\Temp\tfg-ver.out'
$err = 'C:\Windows\Temp\tfg-ver.err'
$p = Start-Process -FilePath $exe -ArgumentList '--version' -PassThru -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err
$salio = $p.WaitForExit(15000)
if (-not $salio) { try { $p.Kill() } catch { } }
"VERSION_SALIO=$salio RC=$($p.ExitCode)"
"VERSION_STDOUT=" + (((Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue) -replace "`r?`n", ' | ').Trim())
"VERSION_STDERR=" + (((Get-Content -LiteralPath $err -Raw -ErrorAction SilentlyContinue) -replace "`r?`n", ' | ').Trim())
Get-Process ghosts -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2
"PROCESOS_GHOSTS=" + @(Get-Process ghosts -ErrorAction SilentlyContinue).Count
Remove-Item -LiteralPath $out, $err -Force -ErrorAction SilentlyContinue
