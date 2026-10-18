# start_internet_local.ps1 — arranca la "internet local" del laboratorio (HOST, bloque L0)
#
# Levanta, enlazados a 192.168.65.1 (host en VMnet1), tres servicios:
#   - 8080  servidor web estatico (sitio creible + descargas)   [NUEVO]
#   - 9090  sink HTTP (paste / C2 / health)                     [REUSO sink_http.py]
#   - 9092  sink WebDAV (nube)                                  [REUSO sink_webdav.py]
#
# Abre reglas de firewall acotadas a 192.168.65.0/24 (una por puerto).
# NO toca los puertos del manager (443/1514/1515/55000). Sin secretos.
#
# Uso (HOST):
#   powershell -ExecutionPolicy Bypass -File Soporte\Laboratorio\internet_local\start_internet_local.ps1

$ErrorActionPreference = "Stop"

$Repo   = "D:\TFG\HIDS-Analisis_Capacidad_deteccion_Ataques_locales_MITRE"
$Bind   = "192.168.65.1"
$LogDir = "D:\TFG-VMs\lab-logs"
$Site   = Join-Path $Repo "Soporte\Laboratorio\internet_local\site"
$SinkH  = Join-Path $Repo "Soporte\Ataques\receiver\sink_http.py"
$SinkD  = Join-Path $Repo "Soporte\Ataques\receiver\sink_webdav.py"
$Serve  = Join-Path $Repo "Soporte\Laboratorio\internet_local\serve_site.py"
$Bucket = "D:\TFG-VMs\lab-logs\cloud_bucket"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
New-Item -ItemType Directory -Force -Path $Bucket | Out-Null

function Start-Svc($name, $arglist) {
    Write-Host "Arrancando $name ..."
    Start-Process -FilePath "python" -ArgumentList $arglist -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $LogDir "$name.out.log") `
        -RedirectStandardError  (Join-Path $LogDir "$name.err.log")
}

Start-Svc "web8080"    @("`"$Serve`"",  "--bind", $Bind, "--port", "8080", "--root", "`"$Site`"",  "--log", "`"$LogDir\web_access.log`"")
Start-Svc "sink9090"   @("`"$SinkH`"",  "--bind", $Bind, "--port", "9090", "--log", "`"$LogDir\sink_http.log`"")
Start-Svc "webdav9092" @("`"$SinkD`"",  "--bind", $Bind, "--port", "9092", "--root", "`"$Bucket`"", "--log", "`"$LogDir\sink_webdav.log`"")

$ruleSet = @(
    @{ Name = "TFG-web-8080";    Port = 8080 },
    @{ Name = "TFG-sink-9090";   Port = 9090 },
    @{ Name = "TFG-webdav-9092"; Port = 9092 }
)
foreach ($r in $ruleSet) {
    if (-not (Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $r.Name -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort $r.Port -RemoteAddress 192.168.65.0/24 | Out-Null
        Write-Host "Regla creada: $($r.Name) (TCP $($r.Port) desde 192.168.65.0/24)"
    } else {
        Write-Host "Regla ya existente: $($r.Name)"
    }
}

Start-Sleep -Seconds 3
Write-Host "Comprobacion local:"
foreach ($p in 8080, 9090, 9092) {
    try {
        $r = Invoke-WebRequest -Uri "http://$Bind`:$p/" -UseBasicParsing -TimeoutSec 5
        Write-Host "  $p -> HTTP $($r.StatusCode)"
    } catch {
        Write-Host "  $p -> sin respuesta ($($_.Exception.Message))"
    }
}
