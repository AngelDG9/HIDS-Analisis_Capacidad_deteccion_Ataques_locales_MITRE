# ATA078 - T1567.001 Exfiltration to Code Repository (Windows)
# Manual: el clon ART 388942ad no trae T1567.001 (solo .002/.003/.004). Se implementa
# git push a un repositorio bare local. PortableGit pre-staged fuera del repo.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA078*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$git = 'C:\tfg-tools\PortableGit\bin\git.exe'
if (-not (Test-Path $git)) { 'GUARDARRAIL: git.exe no pre-staged' | Out-File (Join-Path $ev 'efecto_local.txt') -Encoding ascii; exit 2 }
$repo = Join-Path $dir 'repo.git'
$work = Join-Path $dir 'work'
if (-not (Test-Path $repo)) { & $git init --bare $repo | Out-Null }
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
New-Item -ItemType Directory -Force -Path (Join-Path $work 'datos') | Out-Null
1..20 | ForEach-Object { Set-Content -Path (Join-Path $work "datos\exfil_$_.txt") -Value ("TFG repo $_ " + ('E' * 64)) -Encoding ascii }
Push-Location $work
& $git init | Out-Null
& $git config user.email 'tfg@local'
& $git config user.name 'TFG'
& $git add .
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$commitOut = (& $git commit -m 'TFG exfil ATA078' 2>&1 | Out-String).Trim()
& $git remote add origin $repo 2>$null
& $git branch -M main
$pushOut = (& $git push -u origin main 2>&1 | Out-String).Trim()
Pop-Location
$log = (& $git -C $repo log --oneline -1 main 2>&1 | Out-String).Trim()
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@(
    "ata=ATA078", "tecnica=T1567.001", "fuente=manual",
    "t0=$t0", "t1=$t1", "repo=$repo", "work=$work",
    "commit=$log", "push=$pushOut", "commit_out=$commitOut"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
