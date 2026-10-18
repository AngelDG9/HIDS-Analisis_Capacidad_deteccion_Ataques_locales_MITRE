# stop_internet_local.ps1 — detiene la "internet local" (HOST, bloque L0)
#
# Para los procesos Python de los tres servicios y retira las reglas de firewall.
# Uso (HOST):
#   powershell -ExecutionPolicy Bypass -File Soporte\Laboratorio\internet_local\stop_internet_local.ps1

$ErrorActionPreference = "Continue"

$scripts = @("serve_site.py", "sink_http.py", "sink_webdav.py")
$procs = Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
         Where-Object { $cl = $_.CommandLine; $cl -and ($scripts | Where-Object { $cl -like "*$_*" }) }
foreach ($p in $procs) {
    Write-Host "Deteniendo PID $($p.ProcessId): $($p.CommandLine)"
    Stop-Process -Id $p.ProcessId -Force
}

foreach ($name in "TFG-web-8080", "TFG-sink-9090", "TFG-webdav-9092") {
    $rule = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
    if ($rule) {
        Remove-NetFirewallRule -DisplayName $name
        Write-Host "Regla retirada: $name"
    }
}
Write-Host "Fin."
