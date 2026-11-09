# ATA103 - T1039 Data from Network Shared Drive (Windows)
# ART_adaptado: crear un share loopback \\127.0.0.1\labshare con 20 ficheros y copiarlos por UNC; guardarrail C:\lab-attack\ATA103\; sin red externa.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA103*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'
New-Item -ItemType Directory -Force -Path $ev | Out-Null

$shareDir = Join-Path $dir 'share'
$copiados = Join-Path $dir 'copiados'
New-Item -ItemType Directory -Force -Path $shareDir, $copiados | Out-Null
1..20 | ForEach-Object { Set-Content -Path (Join-Path $shareDir ("doc_{0:D2}.txt" -f $_)) -Value ("TFG share $_ " + ('F' * 64)) -Encoding ascii }
$smb = 'labshare'
Remove-SmbShare -Name $smb -Force -ErrorAction SilentlyContinue | Out-Null
New-SmbShare -Name $smb -Path $shareDir -FullAccess "$env:COMPUTERNAME\angel" -ErrorAction Stop | Out-Null
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$n = 0
$ok = $false
try {
    Copy-Item -Path "\\127.0.0.1\$smb\*" -Destination $copiados -Force -ErrorAction Stop
    $n = (Get-ChildItem $copiados -File).Count
    $ok = $true
    foreach ($f in Get-ChildItem $shareDir -File) {
        $a = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower()
        $b = (Get-FileHash (Join-Path $copiados $f.Name) -Algorithm SHA256).Hash.ToLower()
        if ($a -ne $b) { $ok = $false }
    }
    $ok = $ok -and ($n -eq 20)
} catch {
    'ERROR: ' + $_.Exception.Message | Out-File (Join-Path $ev 'efecto_error.txt') -Encoding ascii
} finally {
    Remove-SmbShare -Name $smb -Force -ErrorAction SilentlyContinue | Out-Null
}
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@(
    "ata=ATA103", "tecnica=T1039", "fuente=ART_adaptado",
    "t0=$t0", "t1=$t1", "share=\\127.0.0.1\$smb", "copiados=$copiados",
    "ficheros_copiados=$n", "sha256_coinciden=$ok", "copia_ok=$ok"
) | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
