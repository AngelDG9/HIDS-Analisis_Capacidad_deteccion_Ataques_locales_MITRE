$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($dir -notlike 'C:\lab-attack\ATA064*') { Write-Error 'GUARDARRAIL: carpeta no permitida'; exit 2 }
$ev = Join-Path $dir 'evidencias'; New-Item -ItemType Directory -Force -Path $ev | Out-Null
$svc = 'TFG-Svc-1489'
$exe = Join-Path $dir 'ToyService.exe'
$code = @'
using System;
using System.ServiceProcess;
using System.Threading;
public class ToyService : ServiceBase {
    public ToyService() { ServiceName = "TFG-Svc-1489"; }
    protected override void OnStart(string[] args) {
        Thread t = new Thread(() => { Thread.Sleep(60000); });
        t.IsBackground = true;
        t.Start();
    }
    protected override void OnStop() { }
    public static void Main() { ServiceBase.Run(new ToyService()); }
}
'@
$t0 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$err = ''
$creado = $false
try {
    if (Test-Path $exe) { Remove-Item $exe -Force -ErrorAction SilentlyContinue }
    Add-Type -TypeDefinition $code -OutputAssembly $exe -OutputType ConsoleApplication -ReferencedAssemblies System.ServiceProcess -ErrorAction Stop
    New-Service -Name $svc -BinaryPathName ('"' + $exe + '"') -StartupType Manual -ErrorAction Stop
    $creado = $true
} catch { $err = $_.Exception.Message }
try { Start-Service $svc -ErrorAction Stop } catch { $err = $_.Exception.Message }
Start-Sleep -Seconds 1
$q0 = Get-Service $svc -ErrorAction SilentlyContinue
$estado0 = if ($q0) { $q0.Status } else { 'NO_EXISTE' }
try { Stop-Service $svc -Force -ErrorAction Stop } catch { $err = $_.Exception.Message }
Start-Sleep -Seconds 1
$q1 = Get-Service $svc -ErrorAction SilentlyContinue
$estado1 = if ($q1) { $q1.Status } else { 'NO_EXISTE' }
try { Get-CimInstance Win32_Service -Filter "Name='$svc'" | Remove-CimInstance -ErrorAction Stop } catch { $err = $_.Exception.Message }
Start-Sleep -Seconds 1
$q2 = Get-Service $svc -ErrorAction SilentlyContinue
$borrado = -not [bool]$q2
$t1 = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$salida = @(
    "ata=ATA064", "tecnica=T1489", "fuente=ART_adaptado",
    "guid=21dfb440-830d-4c86-a3e5-2a491d5a8d04",
    "t0=$t0", "t1=$t1", "servicio=$svc", "binario=$exe",
    "creado=$creado", "estado_antes=$estado0", "estado_despues=$estado1",
    "borrado=$borrado", "error=$err"
)
$salida | Out-File -FilePath (Join-Path $ev 'efecto_local.txt') -Encoding ascii
exit 0
